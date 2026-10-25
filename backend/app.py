from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from scapy.all import ARP, Ether, ICMP, IP, IPv6, TCP, UDP, get_if_list, get_if_addr, sniff
from collections import Counter
import csv
import io
import threading
import time

app = Flask(__name__)
CORS(app)

MAX_PACKETS = 5000

state = {
    "capturing": False,
    "started_at": None,
    "packets": [],
    "total_bytes": 0,
    "packet_counter": 0,
    "capture_error": None,
    "max_packets": 500,
    "analysis_sample": 100,
    # Proposed mechanism: incremental counters
    "protocol_counts": Counter(),
    "source_counts": Counter(),
    "destination_counts": Counter(),
}
state_lock = threading.Lock()
capture_thread = None


def protocol_name(packet):
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(IP):
        return "IPv4"
    if packet.haslayer(IPv6):
        return "IPv6"
    if packet.haslayer(Ether):
        return "Ethernet"
    return "Other"


def endpoint_info(packet):
    src_ip = dst_ip = "-"
    src_port = dst_port = None

    if packet.haslayer(IP):
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
    elif packet.haslayer(ARP):
        src_ip, dst_ip = packet[ARP].psrc or "-", packet[ARP].pdst or "-"

    if packet.haslayer(TCP):
        src_port, dst_port = int(packet[TCP].sport), int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        src_port, dst_port = int(packet[UDP].sport), int(packet[UDP].dport)

    return src_ip, dst_ip, src_port, dst_port


def packet_to_record(packet):
    src_ip, dst_ip, src_port, dst_port = endpoint_info(packet)
    proto = protocol_name(packet)

    src_mac = dst_mac = "-"
    if packet.haslayer(Ether):
        src_mac, dst_mac = packet[Ether].src, packet[Ether].dst

    flags = str(packet[TCP].flags) if packet.haslayer(TCP) else ""

    record = {
        "id": None,
        "timestamp": float(getattr(packet, "time", time.time())),
        "source": src_ip,
        "destination": dst_ip,
        "protocol": proto,
        "sourcePort": src_port,
        "destinationPort": dst_port,
        "length": len(packet),
        "tcpFlags": flags,
        "sourceMac": src_mac,
        "destinationMac": dst_mac,
        "summary": packet.summary(),
    }

    if packet.haslayer(IP):
        record["ipVersion"] = 4
        record["ttl"] = int(packet[IP].ttl)
    elif packet.haslayer(IPv6):
        record["ipVersion"] = 6
        record["hopLimit"] = int(packet[IPv6].hlim)
    else:
        record["ipVersion"] = None

    return record


def capture_callback(packet):
    with state_lock:
        if not state["capturing"]:
            return

        record = packet_to_record(packet)
        state["packet_counter"] += 1
        record["id"] = state["packet_counter"]

        state["packets"].append(record)
        state["total_bytes"] += record["length"]

        # Proposed incremental analysis: update once, never rescan packet history.
        state["protocol_counts"][record["protocol"]] += 1
        if record["source"] != "-":
            state["source_counts"][record["source"]] += 1
        if record["destination"] != "-":
            state["destination_counts"][record["destination"]] += 1

        max_packets = min(MAX_PACKETS, max(1, int(state["max_packets"])))
        if len(state["packets"]) > max_packets:
            state["packets"] = state["packets"][-max_packets:]


def matches_capture_filter(packet, capture_filter):
    """Cross-platform protocol filtering for the live capture.

    We intentionally do the final protocol check in Python instead of relying
    only on a BPF expression. This makes the ICMP/TCP/UDP/ARP filters behave
    consistently with Windows + Npcap while still using Scapy for capture.
    """
    capture_filter = (capture_filter or "").lower().strip()

    if not capture_filter:
        return True
    if capture_filter == "tcp":
        return packet.haslayer(TCP)
    if capture_filter == "udp":
        return packet.haslayer(UDP)
    if capture_filter == "icmp":
        return packet.haslayer(ICMP)
    if capture_filter == "arp":
        return packet.haslayer(ARP)
    if capture_filter == "ip":
        return packet.haslayer(IP)
    if capture_filter == "ip6":
        return packet.haslayer(IPv6)
    return True


def sniff_worker(interface, capture_filter):
    try:
        # Capture from the selected adapter and perform the protocol check in
        # Python. This avoids platform-specific BPF behaviour while preserving
        # the same user-visible filters. Scapy/Npcap remains responsible for
        # the actual packet capture.
        sniff(
            iface=interface or None,
            prn=capture_callback,
            lfilter=lambda packet: matches_capture_filter(packet, capture_filter),
            store=False,
            stop_filter=lambda _: not state["capturing"],
        )
    except Exception as exc:
        with state_lock:
            state["capturing"] = False
            state["capture_error"] = str(exc)


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "NetScope"})


@app.get("/api/interfaces")
def interfaces():
    result = []
    for iface in get_if_list():
        try:
            address = get_if_addr(iface)
        except Exception:
            address = "N/A"
        result.append({"name": iface, "address": address})
    return jsonify(result)


@app.post("/api/capture/start")
def start_capture():
    global capture_thread

    payload = request.get_json(silent=True) or {}
    interface = payload.get("interface") or None
    bpf_filter = payload.get("bpfFilter") or ""
    max_packets = int(payload.get("maxPackets", 500))
    analysis_sample = int(payload.get("analysisSample", 100))

    if max_packets < 50 or max_packets > MAX_PACKETS:
        return jsonify({"message": f"maxPackets must be between 50 and {MAX_PACKETS}."}), 400
    if analysis_sample < 1 or analysis_sample > 100:
        return jsonify({"message": "analysisSample must be between 1 and 100."}), 400

    # Keep BPF input deliberately constrained to common safe filters.
    allowed = {"", "tcp", "udp", "icmp", "arp", "ip", "ip6"}
    if bpf_filter.lower() not in allowed:
        return jsonify({"message": "Allowed capture filters: tcp, udp, icmp, arp, ip, ip6, or none."}), 400

    with state_lock:
        if state["capturing"]:
            return jsonify({"message": "Capture is already running."}), 409

        state["capturing"] = True
        state["started_at"] = time.time()
        state["capture_error"] = None
        state["max_packets"] = max_packets
        state["analysis_sample"] = analysis_sample

    capture_thread = threading.Thread(
        target=sniff_worker,
        args=(interface, bpf_filter.lower()),
        daemon=True,
    )
    capture_thread.start()

    return jsonify({
        "message": "Capture started.",
        "interface": interface or "default interface",
        "maxPackets": max_packets,
        "bpfFilter": bpf_filter.lower(),
        "analysisSample": analysis_sample,
    })


@app.post("/api/capture/stop")
def stop_capture():
    with state_lock:
        state["capturing"] = False
    return jsonify({"message": "Capture stopped."})


@app.post("/api/capture/clear")
def clear_capture():
    with state_lock:
        state["packets"].clear()
        state["total_bytes"] = 0
        state["packet_counter"] = 0
        state["protocol_counts"].clear()
        state["source_counts"].clear()
        state["destination_counts"].clear()
        state["capture_error"] = None
    return jsonify({"message": "Capture cleared."})


@app.get("/api/capture/status")
def capture_status():
    with state_lock:
        return jsonify({
            "capturing": state["capturing"],
            "startedAt": state["started_at"],
            "packetCount": len(state["packets"]),
            "totalBytes": state["total_bytes"],
            "maxPackets": state["max_packets"],
            "analysisSample": state["analysis_sample"],
            "error": state["capture_error"],
        })


@app.get("/api/packets")
def packets():
    try:
        limit = min(int(request.args.get("limit", 500)), MAX_PACKETS)
    except ValueError:
        limit = 500

    search = request.args.get("search", "").strip().lower()
    protocol = request.args.get("protocol", "").strip().upper()

    with state_lock:
        data = list(state["packets"])

    if protocol and protocol != "ALL":
        data = [p for p in data if p["protocol"] == protocol]

    if search:
        data = [
            p for p in data
            if search in " ".join([
                str(p["source"]),
                str(p["destination"]),
                str(p["protocol"]),
                str(p["sourcePort"] or ""),
                str(p["destinationPort"] or ""),
                str(p["summary"]),
            ]).lower()
        ]

    return jsonify(data[-limit:])


@app.get("/api/stats")
def stats():
    # Proposed method: O(k) serialization of already-maintained counters.
    with state_lock:
        protocol_counts = dict(state["protocol_counts"])
        top_sources = state["source_counts"].most_common(8)
        top_destinations = state["destination_counts"].most_common(8)
        total_packets = len(state["packets"])
        total_bytes = state["total_bytes"]
        packets_copy = list(state["packets"])

    now = time.time()
    recent = sum(1 for p in packets_copy if now - p["timestamp"] <= 10)

    return jsonify({
        "totalPackets": total_packets,
        "totalBytes": total_bytes,
        "protocols": protocol_counts,
        "topSources": top_sources,
        "topDestinations": top_destinations,
        "recentPackets": recent,
        "analysisMethod": "incremental",
        "analysisSample": state["analysis_sample"],
        "captureError": state.get("capture_error"),
    })


@app.get("/api/packets/<int:packet_id>")
def packet_detail(packet_id):
    with state_lock:
        for packet in state["packets"]:
            if packet["id"] == packet_id:
                return jsonify(packet)
    return jsonify({"error": "Packet not found"}), 404


@app.get("/api/export")
def export_csv():
    with state_lock:
        packets_copy = list(state["packets"])

    output = io.StringIO()
    fields = [
        "id", "timestamp", "source", "destination", "protocol",
        "sourcePort", "destinationPort", "length", "tcpFlags",
        "sourceMac", "destinationMac", "summary"
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for packet in packets_copy:
        writer.writerow({key: packet.get(key) for key in fields})

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=network_capture.csv"},
    )


if __name__ == "__main__":
    print("NetScope backend running on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
