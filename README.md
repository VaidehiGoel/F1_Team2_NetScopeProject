# NetScope — Rubric-Ready Packet Sniffer & Network Analyser

## Project goal

NetScope is a full-stack Computer Networks lab project that captures packets from an authorised local network interface, extracts protocol/header metadata, and analyses traffic in real time.



## Proposed mechanism / novelty

The project compares two traffic-analysis approaches:

### Baseline
Every time statistics are requested, the analyser scans the complete captured packet list and recomputes:

- protocol frequencies
- source frequencies
- destination frequencies
- total bytes

This is simple but repeatedly costs O(n) per analysis request.

### Proposed incremental analyser
While packets are captured, the analyser updates counters once:

```text
packet arrives
    |
    +--> total packets += 1
    +--> total bytes += packet length
    +--> protocol_count[protocol] += 1
    +--> source_count[source] += 1
    +--> destination_count[destination] += 1
```

Statistics can then be returned without rescanning all packets.

For n packets, the baseline repeatedly performs O(n) aggregation work, while the proposed analyser performs O(1) average counter updates per packet and O(k) work for the number of distinct categories when producing aggregate summaries.

The project also supports an **analysis sampling parameter** so the demo can compare full analysis with reduced analysis workload while still capturing packets.

## Folder structure

```text
NetScope_Rubric_Ready/
│
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── .gitignore
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── styles.css
│   ├── package.json
│   ├── vite.config.js
│   └── index.html
│
├── performance/
│   ├── benchmark.py
│   ├── plot_results.py
│   ├── requirements.txt
│   └── results/
│
├── PROJECT_REPORT.md
├── VIVA_GUIDE.md
└── DEMO_SCRIPT.md
```

## Requirements

- Python 3.10+
- Node.js 18+
- Windows: Npcap
- Administrator privileges may be needed for live capture

## Backend setup
run as administrator
```bash
cd backend
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
py app.py
```

Backend:

```text
http://127.0.0.1:5000
```

## Frontend setup

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend:

```text
http://localhost:5173
```

## Performance experiment

Open another terminal:

```bash
cd performance
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
py benchmark.py --runs 10
py plot_results.py
```

This produces:

```text
performance/results/benchmark_results.csv
performance/results/performance_graph.png
```

The benchmark uses reproducible synthetic packet metadata so performance can be evaluated without depending on Internet traffic.

## Recommended live demo

1. Start backend.
2. Start frontend.
3. Select active Wi-Fi/Ethernet interface.
4. Set packet limit to 500.
5. Start capture.
6. Run `ping 8.8.8.8`.-ICMP
7. Run `nslookup google.com`.-UDP
8. Open a website.-TCP
9. Change protocol filter to TCP, UDP and ICMP.
10. Select a packet and explain its fields.
11. Change packet limit to 1000 and repeat.
12. Export CSV.
13. Show the performance benchmark and explain why incremental analysis is faster for repeated statistics requests.

## Ethical/safety scope

Only capture traffic from interfaces/networks you are authorised to monitor. The project focuses on packet metadata and does not attempt to defeat encryption or decrypt private application traffic.
