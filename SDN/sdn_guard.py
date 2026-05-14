from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
import time
import json
import os
import threading

LOG_FILE = "incidents.log"
ML_LOG_PATH = "/home/pi/Desktop/iomt_ids/logs/events.jsonl"
HONEYPOT_DIR = "/home/pi/Desktop/cowrie_logs/dashboard"

BLOCK_IPV4_SRC = {"10.0.0.2"}
BLOCK_MAC_SRC = set()

def log_event(event_type, details):
    entry = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "details": details
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
    except Exception as e:
        print(f"Log error: {e}")

class SDNGuard(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNGuard, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.blocked_ips = set(BLOCK_IPV4_SRC)
        self.processed_ml_ips = set()
        self.processed_honeypot_ips = set()

        # Start both monitors
        threading.Thread(target=self.monitor_ml_log, daemon=True).start()
        threading.Thread(target=self.monitor_honeypot_dir, daemon=True).start()

    def monitor_ml_log(self):
        last_size = os.path.getsize(ML_LOG_PATH) if os.path.exists(ML_LOG_PATH) else 0
        print(f"[ML] Monitor STARTED - watching: {ML_LOG_PATH}")

        while True:
            print(f"[ML] Checking at {time.strftime('%H:%M:%S')}")
            try:
                if os.path.exists(ML_LOG_PATH):
                    current_size = os.path.getsize(ML_LOG_PATH)
                    if current_size > last_size:
                        print(f"[ML] New data - size: {last_size} → {current_size}")
                        with open(ML_LOG_PATH, 'r') as f:
                            f.seek(last_size)
                            new_content = f.read()
                            last_size = current_size
                            lines = new_content.splitlines()
                            for line in lines:
                                line = line.strip()
                                if line:
                                    try:
                                        entry = json.loads(line)
                                        if entry.get("label") == "ATTACK" and entry.get("action") == "block":
                                            src_ip = entry.get("src_ip")
                                            if src_ip and src_ip not in self.processed_ml_ips:
                                                self.processed_ml_ips.add(src_ip)
                                                self.blocked_ips.add(src_ip)
                                                print(f"[ML] Permanently blocking src_ip: {src_ip}")
                                                log_event("ML_BLOCK_IP", {
                                                    "src_ip": src_ip,
                                                    "reason": entry.get("reason", "unknown"),
                                                    "score": entry.get("score"),
                                                    "timestamp": entry.get("timestamp")
                                                })
                                    except json.JSONDecodeError:
                                        pass
                    else:
                        print(f"[ML] No new data (size still {current_size})")
                else:
                    print("[ML] File not found")
            except Exception as e:
                print(f"[ML] Monitor error: {e}")

            time.sleep(5)

    def monitor_honeypot_dir(self):
        seen_files = set(os.listdir(HONEYPOT_DIR)) if os.path.exists(HONEYPOT_DIR) else set()
        print(f"[HONEYPOT] Monitor STARTED - watching: {HONEYPOT_DIR}")

        while True:
            try:
                if os.path.exists(HONEYPOT_DIR):
                    current_files = set(os.listdir(HONEYPOT_DIR))
                    new_files = current_files - seen_files
                    seen_files = current_files

                    for file in new_files:
                        if file.startswith("attack_") and file.endswith(".json"):
                            full_path = os.path.join(HONEYPOT_DIR, file)
                            print(f"[HONEYPOT] New file: {file}")
                            try:
                                with open(full_path, 'r') as f:
                                    entry = json.load(f)
                                    src_ip = entry.get("src_ip")
                                    if src_ip and src_ip not in self.processed_honeypot_ips:
                                        self.processed_honeypot_ips.add(src_ip)
                                        self.blocked_ips.add(src_ip)
                                        print(f"[HONEYPOT] Permanently blocking src_ip: {src_ip}")
                                        log_event("HONEYPOT_BLOCK_IP", entry)
                            except Exception as e:
                                print(f"[HONEYPOT] Error reading {file}: {e}")
                else:
                    print("[HONEYPOT] Directory not found")
            except Exception as e:
                print(f"[HONEYPOT] Monitor error: {e}")

            time.sleep(5)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        log_event("SWITCH_CONNECTED", {"dpid": datapath.id})

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        src = eth.src
        dst = eth.dst

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt and ip_pkt.src in self.blocked_ips:
            print(f"[BLOCK DROP] src_ip: {ip_pkt.src} - ATTACK BLOCKED")
            log_event("ATTACK_BLOCKED", {
                "dpid": dpid,
                "src_ip": ip_pkt.src,
                "dst_ip": ip_pkt.dst,
                "src_mac": src,
                "dst_mac": dst,
                "trigger": "ML_or_HONEYPOT",
                "status": "BLOCKED"
            })
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_pkt.src)
            self.add_flow(datapath, 200, match, [], idle_timeout=0, hard_timeout=0)
            return

        if src in BLOCK_MAC_SRC:
            log_event("BLOCK_MAC", {"dpid": dpid, "src_mac": src})
            match = parser.OFPMatch(eth_src=src)
            self.add_flow(datapath, 100, match, [], idle_timeout=60)
            return

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_src=src,
                                    eth_dst=dst)
            self.add_flow(datapath, 10, match, actions,
                          idle_timeout=60)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)

if __name__ == '__main__':
    from ryu.cmd import manager
    manager.main()
