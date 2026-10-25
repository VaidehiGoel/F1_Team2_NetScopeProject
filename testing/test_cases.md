# NetScope Test Cases

| Test ID | Feature Tested | Test Procedure | Expected Result |
|---|---|---|---|
| TC01 | Backend startup | Run `python app.py` | Flask backend starts successfully |
| TC02 | Frontend startup | Run `npm run dev` | Dashboard loads successfully |
| TC03 | Interface detection | Open interface selection | Available network interfaces are displayed |
| TC04 | ICMP capture | Run `ping 8.8.8.8 -n 5` | ICMP packets are captured and displayed |
| TC05 | DNS/UDP capture | Run `nslookup google.com` | UDP/DNS traffic is captured |
| TC06 | TCP traffic | Generate TCP traffic through a web connection | TCP packets are captured |
| TC07 | Packet information | Inspect captured packets | Source, destination, protocol and packet details are displayed |
| TC08 | Traffic statistics | Capture multiple packets | Protocol and traffic statistics update correctly |
| TC09 | Incremental analysis | Compare baseline and proposed approaches | Proposed approach performs faster |
| TC10 | Performance benchmark | Run `benchmark.py` | Benchmark results are generated successfully |