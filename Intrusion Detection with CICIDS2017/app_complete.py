# app.py
# Flask Web Interface for Intrusion Detection System with CORS support
# + Live capture using Scapy (Npcap, no Wireshark needed)

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import pickle
import numpy as np
from datetime import datetime

from scapy.all import sniff, IP, TCP  # Scapy

app = Flask(__name__)
CORS(app)

detection_history = []
max_history = 100


class IDSModel:
    def __init__(self, model_path='ids_model.pkl'):
        self.model_loaded = False
        self.model = None
        self.scaler = None
        self.feature_names = None

        try:
            self.load_model(model_path)
        except Exception as e:
            print(f"Warning: Could not load model - {str(e)}")
            print("Please train the model first by running: python quick_start_complete.py")

    def load_model(self, model_path):
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.model_loaded = True
            print("✓ IDS Model loaded successfully")
            print(f"✓ Model features: {len(self.feature_names)}")

    def predict(self, features):
        if not self.model_loaded:
            raise Exception("Model not loaded")

        features_array = np.array(features).reshape(1, -1)
        features_scaled = self.scaler.transform(features_array)
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        return prediction, probability


print("Initializing Intrusion Detection System...")
ids_model = IDSModel()


# -------------------------------------------------------------------
# Feature extraction from Scapy packets
# -------------------------------------------------------------------
def extract_features_from_scapy_packets(packets):
    """
    Convert live-captured Scapy packets to the 20 CICIDS-style features.

    0  Flow Duration (µs)
    1  Total Fwd Packets
    2  Total Backward Packets
    3  Fwd Packet Length Max
    4  Fwd Packet Length Min
    5  Fwd Packet Length Mean
    6  Bwd Packet Length Max
    7  Bwd Packet Length Min
    8  Flow Bytes/s
    9  Flow Packets/s
    10 Fwd IAT Mean
    11 Fwd IAT Max
    12 Bwd IAT Mean
    13 Bwd IAT Max
    14 PSH Flag Count
    15 ACK Flag Count
    16 Down_Up Ratio
    17 Avg Packet Size
    18 Fwd Segment Size Avg
    19 Subflow Fwd Bytes
    """
    if len(packets) < 2:
        raise ValueError("Not enough packets captured to build features")

    # pick first IP packet to define forward direction
    first_ip_pkt = None
    for p in packets:
        if IP in p:
            first_ip_pkt = p
            break
    if first_ip_pkt is None:
        first_ip_pkt = packets[0]

    fwd_src = first_ip_pkt[IP].src if IP in first_ip_pkt else None
    fwd_dst = first_ip_pkt[IP].dst if IP in first_ip_pkt else None

    total_bytes = 0
    total_packets = 0

    fwd_lens = []
    bwd_lens = []

    fwd_times = []
    bwd_times = []

    psh_count = 0
    ack_count = 0

    first_time = packets[0].time
    last_time = packets[-1].time

    for p in packets:
        total_packets += 1
        plen = len(p)
        total_bytes += plen

        direction = 'fwd'
        if IP in p and fwd_src and fwd_dst:
            src = p[IP].src
            dst = p[IP].dst
            if src == fwd_src and dst == fwd_dst:
                direction = 'fwd'
            elif src == fwd_dst and dst == fwd_src:
                direction = 'bwd'
            else:
                continue

        t = p.time

        if direction == 'fwd':
            fwd_lens.append(plen)
            fwd_times.append(t)
        else:
            bwd_lens.append(plen)
            bwd_times.append(t)

        if TCP in p:
            flags = p[TCP].flags
            if flags & 0x08:
                psh_count += 1
            if flags & 0x10:
                ack_count += 1

    flow_duration_s = max(float(last_time - first_time), 1e-6)
    flow_duration_us = flow_duration_s * 1e6

    total_fwd = len(fwd_lens)
    total_bwd = len(bwd_lens)

    def get_stats(arr):
        if not arr:
            return (0, 0, 0.0)
        return (max(arr), min(arr), float(sum(arr) / len(arr)))

    fwd_max, fwd_min, fwd_mean = get_stats(fwd_lens)
    bwd_max, bwd_min, bwd_mean = get_stats(bwd_lens)

    def compute_iat_stats(time_list):
        if len(time_list) < 2:
            return (0.0, 0.0)
        time_list_sorted = sorted(time_list)
        diffs = [
            (t2 - t1) * 1e6
            for t1, t2 in zip(time_list_sorted[:-1], time_list_sorted[1:])
        ]
        mean_iat = float(sum(diffs) / len(diffs))
        max_iat = float(max(diffs))
        return mean_iat, max_iat

    fwd_iat_mean, fwd_iat_max = compute_iat_stats(fwd_times)
    bwd_iat_mean, bwd_iat_max = compute_iat_stats(bwd_times)

    flow_bytes_per_s = total_bytes / flow_duration_s
    flow_pkts_per_s = total_packets / flow_duration_s

    down_up_ratio = float(total_bwd) / float(total_fwd) if total_fwd > 0 else 0.0
    avg_pkt_size = float(total_bytes) / float(total_packets) if total_packets > 0 else 0.0
    fwd_seg_size_avg = fwd_mean
    subflow_fwd_bytes = float(sum(fwd_lens))

    features = [
        flow_duration_us,
        total_fwd,
        total_bwd,
        fwd_max,
        fwd_min,
        fwd_mean,
        bwd_max,
        bwd_min,
        flow_bytes_per_s,
        flow_pkts_per_s,
        fwd_iat_mean,
        fwd_iat_max,
        bwd_iat_mean,
        bwd_iat_max,
        psh_count,
        ack_count,
        down_up_ratio,
        avg_pkt_size,
        fwd_seg_size_avg,
        subflow_fwd_bytes,
    ]

    cleaned = []
    for v in features:
        if v is None:
            v = 0.0
        try:
            if np.isnan(v) or np.isinf(v):
                v = 0.0
        except Exception:
            pass
        cleaned.append(float(v))

    return cleaned


def run_prediction_and_record(features, source="manual"):
    prediction, probability = ids_model.predict(features)

    if prediction == 0:
        result = "BENIGN"
        threat_level = "Low"
        color = "success"
        icon = "check-circle"
    else:
        result = "ATTACK DETECTED"
        threat_level = "High"
        color = "danger"
        icon = "exclamation-triangle"

    confidence = max(probability) * 100

    detection_record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "result": result,
        "confidence": f"{confidence:.2f}%",
        "threat_level": threat_level,
        "color": color,
        "source": source,
    }

    detection_history.append(detection_record)
    if len(detection_history) > max_history:
        detection_history.pop(0)

    response = {
        "success": True,
        "prediction": result,
        "confidence": float(confidence),
        "threat_level": threat_level,
        "color": color,
        "icon": icon,
        "timestamp": detection_record["timestamp"],
        "source": source,
        "probabilities": {
            "benign": float(probability[0] * 100),
            "attack": float(probability[1] * 100),
        },
    }
    return response


# -------------------------------------------------------------------
# ROUTES
# -------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/detect", methods=["POST"])
def detect():
    try:
        if not ids_model.model_loaded:
            return jsonify(
                {"success": False, "error": "Model not loaded. Please train the model first."}
            ), 503

        data = request.json
        features = data.get("features", [])

        if not features:
            return jsonify({"success": False, "error": "No features provided"}), 400

        response = run_prediction_and_record(features, source="manual")
        return jsonify(response)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/detect_live", methods=["POST"])
def detect_live():
    """
    Capture real network packets with Scapy (requires Npcap / admin rights),
    extract features, and run IDS prediction.
    """
    try:
        if not ids_model.model_loaded:
            return jsonify(
                {"success": False, "error": "Model not loaded. Please train the model first."}
            ), 503

        data = request.json or {}
        capture_seconds = int(data.get("capture_seconds", 5))
        max_packets = int(data.get("max_packets", 200))
        interface = data.get("interface")  # e.g. "Wi-Fi", "Ethernet" or None

        print(
            f"[LIVE] Starting capture (Scapy): {capture_seconds}s, "
            f"{max_packets} packets, iface={interface or 'default'}"
        )

        packets = sniff(
            iface=interface,
            timeout=capture_seconds,
            count=max_packets,
            store=True,
        )

        print(f"[LIVE] Captured {len(packets)} packets")

        if len(packets) < 2:
            return jsonify(
                {
                    "success": False,
                    "error": f"Not enough packets captured ({len(packets)}). "
                             f"Please generate some traffic and try again.",
                }
            ), 400

        features = extract_features_from_scapy_packets(packets)
        response = run_prediction_and_record(features, source="live")
        return jsonify(response)

    except Exception as e:
        return jsonify({"success": False, "error": f"Live capture failed: {str(e)}"}), 500


@app.route("/history")
def get_history():
    return jsonify(detection_history[-50:])


@app.route("/stats")
def get_stats():
    if len(detection_history) == 0:
        return jsonify(
            {
                "total_scans": 0,
                "attacks_detected": 0,
                "benign_traffic": 0,
                "detection_rate": 0,
                "avg_confidence": 0,
            }
        )

    attacks = sum(1 for d in detection_history if d["result"] == "ATTACK DETECTED")
    benign = len(detection_history) - attacks
    confidences = [
        float(d["confidence"].replace("%", "")) for d in detection_history
    ]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0

    return jsonify(
        {
            "total_scans": len(detection_history),
            "attacks_detected": attacks,
            "benign_traffic": benign,
            "detection_rate": (attacks / len(detection_history) * 100)
            if len(detection_history) > 0
            else 0,
            "avg_confidence": avg_confidence,
        }
    )


@app.route("/clear_history", methods=["POST"])
def clear_history():
    global detection_history
    detection_history = []
    return jsonify({"success": True, "message": "History cleared"})


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "healthy",
            "model_loaded": ids_model.model_loaded,
            "detections_count": len(detection_history),
        }
    )


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("INTRUSION DETECTION SYSTEM - WEB INTERFACE (SCAPY LIVE CAPTURE)")
    print("=" * 60)
    print("\nStarting Flask server...")
    print("Dashboard URL: http://localhost:5000")
    print("\nPress CTRL+C to stop the server")
    print("=" * 60 + "\n")

    app.run(debug=True, host="0.0.0.0", port=5000)
