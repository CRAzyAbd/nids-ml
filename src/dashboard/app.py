import os, sys, time, threading, queue
from datetime import datetime
from collections import deque, defaultdict
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from src.detection.detector import RealTimeDetector
from src.utils.logger import setup_logger
from config.settings import LOG_FILE, LOG_LEVEL

logger = setup_logger(__name__, LOG_FILE, LOG_LEVEL)
app = Flask(__name__)
app.config["SECRET_KEY"] = "nids-2024"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                    logger=False, engineio_logger=False)
event_queue = queue.Queue(maxsize=500)


class DashboardState:
    def __init__(self):
        self._lock              = threading.RLock()
        self.total_packets      = 0
        self.total_flows        = 0
        self.total_alerts       = 0
        self.session_start      = time.time()
        self.protocol_counts    = defaultdict(int)
        self.label_counts       = defaultdict(int)
        self.alert_level_counts = defaultdict(int)
        self.recent_alerts      = deque(maxlen=100)
        self.recent_flows       = deque(maxlen=50)
        self._pkt_ts            = deque(maxlen=1000)

    def add_packet(self, protocol):
        with self._lock:
            self.total_packets += 1
            self.protocol_counts[protocol] += 1
            self._pkt_ts.append(time.time())

    def add_flow(self, r):
        with self._lock:
            self.total_flows += 1
            label = r["rf_label"]
            self.label_counts[label] += 1
            if r["is_alert"]:
                self.total_alerts += 1
                self.alert_level_counts[r["alert_level"]] += 1
                self.recent_alerts.appendleft({
                    "timestamp":   datetime.now().strftime("%H:%M:%S"),
                    "alert_level": r["alert_level"],
                    "rf_label":    r["rf_label"],
                    "confidence":  round(r["rf_confidence"] * 100, 1),
                    "iso_label":   r["iso_label"],
                    "iso_score":   round(r["iso_score"], 4),
                    "flow":        r["flow_summary"],
                })
            self.recent_flows.appendleft({
                "timestamp":   datetime.now().strftime("%H:%M:%S"),
                "label":       label,
                "confidence":  round(r["rf_confidence"] * 100, 1),
                "alert_level": r["alert_level"],
                "is_alert":    r["is_alert"],
                "flow":        r["flow_summary"],
            })

    def pps(self):
        now = time.time()
        with self._lock:
            return round(len([t for t in self._pkt_ts if now - t <= 5]) / 5, 1)

    def snapshot(self):
        # Copy data under lock, compute outside to avoid deadlock
        with self._lock:
            now     = time.time()
            elapsed = max(now - self.session_start, 1)
            benign  = self.label_counts.get("BENIGN", 0)
            pps     = round(len([t for t in self._pkt_ts if now - t <= 5]) / 5, 1)
            return {
                "total_packets":      self.total_packets,
                "total_flows":        self.total_flows,
                "total_alerts":       self.total_alerts,
                "packets_per_sec":    pps,
                "flows_per_min":      round(self.total_flows / elapsed * 60, 1),
                "alert_rate":         round(self.total_alerts / max(self.total_flows,1) * 100, 1),
                "benign_pct":         round(benign / max(self.total_flows,1) * 100, 1),
                "uptime":             round(elapsed),
                "protocol_counts":    dict(self.protocol_counts),
                "label_counts":       dict(self.label_counts),
                "alert_level_counts": dict(self.alert_level_counts),
                "recent_alerts":      list(self.recent_alerts)[:20],
                "recent_flows":       list(self.recent_flows)[:20],
            }


state = DashboardState()


class DashboardAlertEngine:
    def process(self, r):
        state.add_flow(r)
        try:
            event_queue.put_nowait({"type": "flow", "data": {
                "timestamp":   datetime.now().strftime("%H:%M:%S"),
                "label":       r["rf_label"],
                "confidence":  round(r["rf_confidence"] * 100, 1),
                "alert_level": r["alert_level"],
                "is_alert":    r["is_alert"],
                "flow":        r["flow_summary"],
                "iso_score":   round(r["iso_score"], 4),
            }})
        except queue.Full:
            pass
        if r["is_alert"]:
            try:
                event_queue.put_nowait({"type": "alert", "data": {
                    "timestamp":   datetime.now().strftime("%H:%M:%S"),
                    "alert_level": r["alert_level"],
                    "rf_label":    r["rf_label"],
                    "confidence":  round(r["rf_confidence"] * 100, 1),
                    "iso_label":   r["iso_label"],
                    "iso_score":   round(r["iso_score"], 4),
                    "flow":        r["flow_summary"],
                }})
            except queue.Full:
                pass

    def print_final_summary(self):
        pass


def capture_worker(interface, packet_filter):
    try:
        from src.sniffer.packet_capture import PacketCapture
        orig = PacketCapture._process_packet

        def patched(self_cap, packet):
            from scapy.all import IP, TCP, UDP, ICMP
            if packet.haslayer(IP):
                if packet.haslayer(TCP):    p = "TCP"
                elif packet.haslayer(UDP):  p = "UDP"
                elif packet.haslayer(ICMP): p = "ICMP"
                else:                       p = "OTHER"
                state.add_packet(p)
            orig(self_cap, packet)

        PacketCapture._process_packet = patched
        detector = RealTimeDetector()
        ae = DashboardAlertEngine()
        if not detector.load_models():
            logger.error("Models missing")
            return
        PacketCapture(interface=interface, packet_filter=packet_filter,
                      mode="detect", detector=detector, alert_engine=ae).start()
    except Exception as e:
        logger.error(f"Capture error: {e}")
        import traceback; traceback.print_exc()


def emit_worker():
    last_stats = time.time()
    while True:
        try:
            while True:
                evt = event_queue.get_nowait()
                socketio.emit(evt["type"], evt["data"])
        except queue.Empty:
            pass
        now = time.time()
        if now - last_stats >= 1.0:
            socketio.emit("stats_update", state.snapshot())
            last_stats = now
        time.sleep(0.05)


@app.route("/")
def index():
    return render_template("index.html")



@app.route("/ping")
def ping():
    return "pong"

@app.route("/api/stats")
def api_stats():
    return jsonify(state.snapshot())


@socketio.on("connect")
def on_connect(auth=None):
    logger.info("Browser connected")
    emit("stats_update", state.snapshot())


def run_dashboard(interface="wlo1", packet_filter="", port=5000, debug=False):
    logger.info(f"Dashboard starting on http://localhost:{port}")
    logger.info(f"Interface : {interface}")

    t = threading.Thread(target=capture_worker,
                         args=(interface, packet_filter), daemon=True)
    t.start()
    logger.info("Capture thread started")

    socketio.start_background_task(emit_worker)
    logger.info("Emit worker started")

    socketio.run(app, host="0.0.0.0", port=port,
                 debug=debug, allow_unsafe_werkzeug=True)
