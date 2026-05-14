import shutil
import os
import time
import json
from datetime import datetime
from collections import deque, defaultdict, Counter

import numpy as np
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
from ai_edge_litert.interpreter import Interpreter

# --------------------------------------------------
# PATHS
# --------------------------------------------------
BASE_DIR = "/home/pi/Desktop/iomt_ids"
DEPLOY_DIR = os.path.join(BASE_DIR, "DEPLOY_READY")
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

MODEL_PATH = os.path.join(DEPLOY_DIR, "edge18_student.tflite")
SCALER_JSON_PATH = os.path.join(DEPLOY_DIR, "scaler_params_edge18.json")  # NEW
THRESHOLD_PATH = os.path.join(DEPLOY_DIR, "threshold.json")

EVENTS_JSONL = os.path.join(LOG_DIR, "events.jsonl")

# --------------------------------------------------
# LOG RESET (fresh log every run)
# --------------------------------------------------
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
ARCHIVE_LOG = os.path.join(LOG_DIR, f"events_{RUN_ID}.jsonl")

# If an old events.jsonl exists and is not empty, archive it
if os.path.exists(EVENTS_JSONL) and os.path.getsize(EVENTS_JSONL) > 0:
    shutil.move(EVENTS_JSONL, ARCHIVE_LOG)

# Create a fresh empty log file for this run
open(EVENTS_JSONL, "w").close()
os.chmod(EVENTS_JSONL, 0o664)

print("RUN_ID             :", RUN_ID)
print("Fresh log file     :", EVENTS_JSONL)
print("Archived old log   :", ARCHIVE_LOG if os.path.exists(ARCHIVE_LOG) else "None")

# --------------------------------------------------
# CAPTURE SETTINGS
# --------------------------------------------------
INTERFACE = "wlan0"
WINDOW_SECONDS = 5

# --------------------------------------------------
# DECISION SETTINGS
# --------------------------------------------------
BASE_THRESHOLD = 0.5
THRESH_LOW = 0.40
THRESH_HIGH = 0.75

PERSIST_WINDOW_SEC = 10
K_MIN = 4

# ICMP policy
ICMP_DOMINANT_RATIO = 0.70

# --------------------------------------------------
# HYBRID UDP RATE RULE (demo reliability)
# --------------------------------------------------
UDP_DOMINANT_RATIO = 0.70      # UDP must dominate the window
UDP_PPS_SUSP = 800             # packets/sec => SUSPICIOUS
UDP_PPS_ATTACK = 2000          # packets/sec => ATTACK

# Anti-sticky: require 2 consecutive high windows for "udp_rate_rule_high"
UDP_HIGH_STREAK_REQUIRED = 2
udp_high_streak = 0

# --------------------------------------------------
# LOAD THRESHOLD.JSON IF PRESENT
# --------------------------------------------------
if os.path.exists(THRESHOLD_PATH):
    try:
        with open(THRESHOLD_PATH, "r") as f:
            data = json.load(f)
        BASE_THRESHOLD = float(data.get("threshold", BASE_THRESHOLD))
    except Exception:
        pass

# --------------------------------------------------
# LOAD SCALER PARAMS (JSON)  <-- NEW
# --------------------------------------------------
with open(SCALER_JSON_PATH, "r") as f:
    sp = json.load(f)

SCALER_MEAN = np.array(sp["mean"], dtype=np.float32)
SCALER_SCALE = np.array(sp["scale"], dtype=np.float32)

# --------------------------------------------------
# LOAD MODEL
# --------------------------------------------------
interpreter = Interpreter(model_path=MODEL_PATH)
interpreter.allocate_tensors()
input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()

IN_IDX = input_details[0]["index"]
OUT_IDX = output_details[0]["index"]

print("=" * 72)
print("LIVE IDS")
print("=" * 72)
print("Interface           :", INTERFACE)
print("Window (seconds)    :", WINDOW_SECONDS)
print("Events log          :", EVENTS_JSONL)
print("=" * 72)
print()

# --------------------------------------------------
# STATE
# --------------------------------------------------
pkts = []
ts = []

suspicious_times = deque()
src_windows = defaultdict(deque)

count_attack = 0
count_suspicious = 0
count_benign = 0
count_windows = 0
count_packets = 0
alerts_by_src = defaultdict(int)

# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def now_iso():
    return datetime.now().isoformat(timespec="seconds")

def write_event(event: dict):
    with open(EVENTS_JSONL, "a") as f:
        f.write(json.dumps(event) + "\n")

# --------------------------------------------------
# PACKET HANDLER
# --------------------------------------------------
def packet_handler(pkt):
    global pkts, ts
    if IP not in pkt:
        return
    pkts.append(pkt)
    ts.append(time.time())

# --------------------------------------------------
# FEATURE EXTRACTION (dominant proto + dominant ports)
# --------------------------------------------------
def extract_edge18_features():
    if len(pkts) < 1:
        return None, None

    first = pkts[0]
    last = pkts[-1]

    proto_counts = Counter()
    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    src_ports = []
    dst_ports = []

    pairs = Counter()

    sizes = []
    syn = ack = fin = rst = 0

    for p in pkts:
        sizes.append(len(p))

        if IP in p:
            sip = p[IP].src
            dip = p[IP].dst
            pairs[(sip, dip)] += 1
            proto_counts[int(p[IP].proto)] += 1

        if TCP in p:
            tcp_count += 1
            src_ports.append(int(p[TCP].sport))
            dst_ports.append(int(p[TCP].dport))
            flags = int(p[TCP].flags)
            if flags & 0x02: syn += 1
            if flags & 0x10: ack += 1
            if flags & 0x01: fin += 1
            if flags & 0x04: rst += 1
        elif UDP in p:
            udp_count += 1
            src_ports.append(int(p[UDP].sport))
            dst_ports.append(int(p[UDP].dport))
        elif ICMP in p:
            icmp_count += 1

    if pairs:
        (src_ip, dst_ip), _ = pairs.most_common(1)[0]
    else:
        src_ip = first[IP].src if IP in first else "0.0.0.0"
        dst_ip = first[IP].dst if IP in first else "0.0.0.0"

    proto = proto_counts.most_common(1)[0][0] if proto_counts else (int(first[IP].proto) if IP in first else 0)

    src_port = Counter(src_ports).most_common(1)[0][0] if src_ports else 0
    dst_port = Counter(dst_ports).most_common(1)[0][0] if dst_ports else 0

    duration = float(last.time - first.time) if len(pkts) > 1 else 0.0
    if duration <= 0:
        duration = 0.0001

    number = len(pkts)
    tot_size = float(sum(sizes))

    min_size = float(min(sizes))
    max_size = float(max(sizes))
    avg_size = float(np.mean(sizes))
    std_size = float(np.std(sizes)) if len(sizes) > 1 else 0.0

    # model features keep instantaneous estimate (your current behaviour)
    rate_pps_model = float(number / duration)
    srate_bps = float(tot_size / duration)

    # stable rate for rules (prevents sticky udp_rate_rule_high after stopping)
    rate_pps_rule = float(number / WINDOW_SECONDS)

    iat = float(np.mean(np.diff(ts))) if len(ts) >= 2 else 0.0

    tcp_present = 1.0 if tcp_count > 0 else 0.0
    udp_present = 1.0 if udp_count > 0 else 0.0
    icmp_present = 1.0 if icmp_count > 0 else 0.0

    protocol_type = float(proto)

    features = np.array([
        protocol_type,
        duration,
        rate_pps_model,
        srate_bps,
        float(syn),
        float(ack),
        float(fin),
        float(rst),
        tcp_present,
        udp_present,
        icmp_present,
        min_size,
        max_size,
        avg_size,
        std_size,
        tot_size,
        iat,
        float(number)
    ], dtype=np.float32)

    meta = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "proto": int(proto),
        "packets": int(number),
        "duration": float(duration),
        "tot_size": float(tot_size),
        "tcp_count": int(tcp_count),
        "udp_count": int(udp_count),
        "icmp_count": int(icmp_count),
        "rate_pps_model": float(rate_pps_model),
        "rate_pps_rule": float(rate_pps_rule),
    }

    return features, meta

# --------------------------------------------------
# MODEL INFERENCE  <-- UPDATED: NumPy scaling
# --------------------------------------------------
def predict_prob(feature_vector):
    x = (np.array(feature_vector, dtype=np.float32) - SCALER_MEAN) / SCALER_SCALE
    x = x.reshape(1, -1).astype(np.float32)
    interpreter.set_tensor(IN_IDX, x)
    interpreter.invoke()
    prob = interpreter.get_tensor(OUT_IDX)[0][0]
    return float(prob)

# --------------------------------------------------
# HYBRID RULE (UDP flood) - uses stable rate_pps_rule
# --------------------------------------------------
def udp_rate_rule(meta: dict):
    global udp_high_streak

    total = max(meta["packets"], 1)
    udp_ratio = meta["udp_count"] / total
    rate_pps = meta["rate_pps_rule"]

    # reset streak if condition not met
    if not (udp_ratio >= UDP_DOMINANT_RATIO and rate_pps >= UDP_PPS_SUSP):
        udp_high_streak = 0
        return None, None

    # High condition
    if udp_ratio >= UDP_DOMINANT_RATIO and rate_pps >= UDP_PPS_ATTACK:
        udp_high_streak += 1
        if udp_high_streak >= UDP_HIGH_STREAK_REQUIRED:
            return "ATTACK", "udp_rate_rule_high"
        return "SUSPICIOUS", "udp_rate_rule_pre_high"

    # Suspicious condition
    udp_high_streak = 0
    return "SUSPICIOUS", "udp_rate_rule"

# --------------------------------------------------
# DECISION LOGIC
# --------------------------------------------------
def decide_label(src_ip: str, meta: dict, prob: float):
    now = time.time()

    if prob >= THRESH_HIGH:
        return "ATTACK", "high_conf"

    rule_label, rule_reason = udp_rate_rule(meta)
    if rule_label is not None:
        return rule_label, rule_reason

    total = max(meta["packets"], 1)
    icmp_ratio = meta["icmp_count"] / total
    if meta["proto"] == 1 and icmp_ratio >= ICMP_DOMINANT_RATIO:
        if prob >= BASE_THRESHOLD:
            return "SUSPICIOUS", "icmp_suspicious"
        return "BENIGN", "icmp_allowed"

    if prob >= THRESH_LOW:
        suspicious_times.append(now)
        src_windows[src_ip].append(now)

    while suspicious_times and (now - suspicious_times[0]) > PERSIST_WINDOW_SEC:
        suspicious_times.popleft()

    dq = src_windows[src_ip]
    while dq and (now - dq[0]) > PERSIST_WINDOW_SEC:
        dq.popleft()

    if len(dq) >= K_MIN:
        return "ATTACK", f"src_window_{len(dq)}/{PERSIST_WINDOW_SEC}s"

    if len(suspicious_times) >= K_MIN:
        return "ATTACK", f"global_window_{len(suspicious_times)}/{PERSIST_WINDOW_SEC}s"

    if prob >= THRESH_LOW:
        return "SUSPICIOUS", f"watch_{len(dq)}/{PERSIST_WINDOW_SEC}s"

    if prob >= BASE_THRESHOLD:
        return "SUSPICIOUS", "single_flow_watch"

    return "BENIGN", "normal"

# --------------------------------------------------
# MAIN WINDOW EVALUATION
# --------------------------------------------------
def evaluate_window():
    global pkts, ts
    global count_attack, count_suspicious, count_benign, count_windows, count_packets

    count_windows += 1

    if len(pkts) == 0:
        print(f"[{now_iso()}]\nWINDOW {count_windows}\nNo packets captured in this window.\n")
        return

    features, meta = extract_edge18_features()
    if features is None:
        return

    prob = predict_prob(features)
    label, reason = decide_label(meta["src_ip"], meta, prob)

    count_packets += meta["packets"]

    print(f"[{now_iso()}]")
    print(f"WINDOW      : {count_windows}")
    print(f"SRC         : {meta['src_ip']}:{meta['src_port']}")
    print(f"DST         : {meta['dst_ip']}:{meta['dst_port']}")
    print(f"PACKETS     : {meta['packets']}")
    print(f"DURATION    : {meta['duration']:.3f}s")
    print(f"RATE        : {meta['rate_pps_rule']:.1f} pkts/sec")
    print(f"PROBABILITY : {prob:.3f}")
    print(f"RESULT      : {label}")
    print("-" * 50)

    if label == "ATTACK":
        count_attack += 1
        alerts_by_src[meta["src_ip"]] += 1
        event = {
            "timestamp": now_iso(),
            "label": "ATTACK",
            "reason": reason,
            "action": "block",
            "score": float(prob),
            "src_ip": str(meta["src_ip"]),
            "dst_ip": str(meta["dst_ip"]),
            "src_port": int(meta["src_port"]),
            "dst_port": int(meta["dst_port"]),
            "proto": int(meta["proto"]),
            "packets": int(meta["packets"]),
            "duration": float(meta["duration"]),
            "rate_pps": float(meta["rate_pps_rule"]),
        }
        write_event(event)

    elif label == "SUSPICIOUS":
        count_suspicious += 1
        event = {
            "timestamp": now_iso(),
            "label": "SUSPICIOUS",
            "reason": reason,
            "action": "monitor",
            "score": float(prob),
            "src_ip": str(meta["src_ip"]),
            "dst_ip": str(meta["dst_ip"]),
            "src_port": int(meta["src_port"]),
            "dst_port": int(meta["dst_port"]),
            "proto": int(meta["proto"]),
            "packets": int(meta["packets"]),
            "duration": float(meta["duration"]),
            "rate_pps": float(meta["rate_pps_rule"]),
        }
        write_event(event)

    else:
        count_benign += 1

    pkts.clear()
    ts.clear()

# --------------------------------------------------
# SUMMARY
# --------------------------------------------------
def print_summary():
    print("\n" + "=" * 72)
    print("FINAL SUMMARY")
    print("=" * 72)
    print("Windows processed :", count_windows)
    print("Packets processed :", count_packets)
    print("BENIGN            :", count_benign)
    print("SUSPICIOUS        :", count_suspicious)
    print("ATTACKS           :", count_attack)

    if alerts_by_src:
        print("\nTop alerting source IPs:")
        for ip, c in sorted(alerts_by_src.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip} : {c}")

    print("\nLog file:", EVENTS_JSONL)
    print("=" * 72 + "\n")

# --------------------------------------------------
# START SNIFFER
# --------------------------------------------------
sniffer = AsyncSniffer(iface=INTERFACE, prn=packet_handler, store=False, filter="ip")
sniffer.start()

try:
    while True:
        time.sleep(WINDOW_SECONDS)
        evaluate_window()

except KeyboardInterrupt:
    pass

finally:
    sniffer.stop()
    print_summary()