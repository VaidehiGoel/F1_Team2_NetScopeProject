# NetScope Testing Results

## Functional Testing

### TC01 — Backend Startup
**Result:** PASS

The Flask backend started successfully using `python app.py`.

### TC02 — Frontend Startup
**Result:** PASS

The React/Vite frontend loaded successfully and displayed the NetScope dashboard.

### TC03 — ICMP Packet Capture
**Command:**
```cmd
ping 8.8.8.8 -n 5