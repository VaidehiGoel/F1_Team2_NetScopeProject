import React, { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, BarChart3, CheckCircle2, Clock3, Download,
  Filter, Gauge, Globe2, HardDriveDownload, Network, Pause, Play,
  RefreshCw, Search, Server, Shield, Trash2, X
} from "lucide-react";

const API = "http://127.0.0.1:5000/api";

const protocolColors = {
  TCP: "tcp", UDP: "udp", ICMP: "icmp", ARP: "arp",
  IPv4: "ipv4", IPv6: "ipv6", Ethernet: "ethernet", Other: "other"
};

function formatBytes(bytes = 0) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}
function formatTime(ts) { return ts ? new Date(ts * 1000).toLocaleTimeString() : "-"; }

export default function App() {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState("");
  const [capturing, setCapturing] = useState(false);
  const [packets, setPackets] = useState([]);
  const [stats, setStats] = useState({ totalPackets: 0, totalBytes: 0, protocols: {}, topSources: [], recentPackets: 0 });
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [search, setSearch] = useState("");
  const [protocol, setProtocol] = useState("ALL");
  const [maxPackets, setMaxPackets] = useState(1000);
  const [captureFilter, setCaptureFilter] = useState("");
  const [analysisSample, setAnalysisSample] = useState(100);
  const [error, setError] = useState("");

  async function loadInterfaces() {
    try {
      const res = await fetch(`${API}/interfaces`);
      const data = await res.json();
      setInterfaces(data);
      if (!selectedInterface && data.length) {
        const preferred = data.find(x => x.address && x.address !== "0.0.0.0" && x.address !== "127.0.0.1") || data[0];
        setSelectedInterface(preferred.name);
      }
    } catch { setError("Backend is not reachable. Start Flask first."); }
  }

  async function loadData() {
    try {
      const [p, s, st] = await Promise.all([
        fetch(`${API}/packets?limit=500&search=${encodeURIComponent(search)}&protocol=${protocol}`),
        fetch(`${API}/stats`),
        fetch(`${API}/capture/status`)
      ]);
      const pd = await p.json(), sd = await s.json(), std = await st.json();
      setPackets(pd); setStats(sd); setCapturing(std.capturing);
      if (std.error) setError(std.error);
    } catch { setError("Unable to communicate with backend."); }
  }

  useEffect(() => { loadInterfaces(); }, []);
  useEffect(() => {
    loadData();
    const id = setInterval(loadData, 1000);
    return () => clearInterval(id);
  }, [search, protocol]);

  async function startCapture() {
    try {
      const res = await fetch(`${API}/capture/start`, {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({
          interface: selectedInterface,
          maxPackets: Number(maxPackets),
          bpfFilter: captureFilter,
          analysisSample: Number(analysisSample)
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message);
      setCapturing(true); setError("");
    } catch (e) { setError(e.message); }
  }

  async function stopCapture() {
    await fetch(`${API}/capture/stop`, {method:"POST"});
    setCapturing(false);
  }

  async function clearCapture() {
    await fetch(`${API}/capture/clear`, {method:"POST"});
    setSelectedPacket(null); loadData();
  }

  const protocolEntries = useMemo(
    () => Object.entries(stats.protocols || {}).sort((a,b) => b[1]-a[1]), [stats.protocols]
  );
  const maxProtocol = Math.max(1, ...protocolEntries.map(([,n]) => n));

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark"><Network size={21}/></div>
          <div><b>NetScope</b><small>Packet Sniffer & Network Analyser</small></div>
        </div>
        <div className="status"><span className={capturing ? "dot live":"dot"}/>{capturing ? "LIVE CAPTURE":"CAPTURE STOPPED"}</div>
      </header>

      <main className="page">
        {error && <div className="error"><AlertTriangle size={17}/><span>{error}</span><button onClick={()=>setError("")}><X size={15}/></button></div>}

        <section className="hero">
          <div>
            <div className="eyebrow">COMPUTER NETWORKS LAB • RUBRIC READY</div>
            <h1>Observe. Analyse.<br/>Compare performance.</h1>
            <p>Live packet capture with incremental traffic analysis and configurable experiment parameters.</p>
          </div>

          <div className="controls">
            <div className="control-row">
              <label>INTERFACE<select value={selectedInterface} disabled={capturing} onChange={e=>setSelectedInterface(e.target.value)}>
                {interfaces.map(i=><option key={i.name} value={i.name}>{i.label || i.name} — {i.address}</option>)}
              </select></label>
              <label>PACKET LIMIT<input type="number" min="50" max="5000" value={maxPackets} disabled={capturing} onChange={e=>setMaxPackets(e.target.value)}/></label>
              <label>CAPTURE FILTER<select value={captureFilter} disabled={capturing} onChange={e=>setCaptureFilter(e.target.value)}>
                <option value="">All</option><option value="tcp">TCP</option><option value="udp">UDP</option>
                <option value="icmp">ICMP</option><option value="arp">ARP</option><option value="ip">IPv4</option><option value="ip6">IPv6</option>
              </select></label>
              <label>ANALYSIS %<input type="number" min="1" max="100" value={analysisSample} disabled={capturing} onChange={e=>setAnalysisSample(e.target.value)}/></label>
              <button className={capturing ? "btn stop":"btn start"} onClick={capturing ? stopCapture:startCapture}>
                {capturing ? <Pause size={16}/> : <Play size={16}/>} {capturing ? "Stop":"Start"}
              </button>
              <button className="icon" onClick={loadInterfaces}><RefreshCw size={16}/></button>
            </div>
            <div className="parameter-note">Capture Filter controls what Scapy stores; the table filter only changes what is displayed.</div>
          </div>
        </section>

        <section className="stats">
          <Card icon={<Activity/>} label="PACKETS" value={stats.totalPackets.toLocaleString()} detail={`${stats.recentPackets} in last 10s`}/>
          <Card icon={<HardDriveDownload/>} label="TRAFFIC" value={formatBytes(stats.totalBytes)} detail="Captured bytes"/>
          <Card icon={<Gauge/>} label="PROTOCOLS" value={Object.keys(stats.protocols || {}).length} detail="Detected types"/>
          <Card icon={<Clock3/>} label="ANALYSIS" value="Incremental" detail="Proposed mechanism"/>
        </section>

        <section className="grid">
          <div className="panel">
            <div className="panel-head">
              <div><h2>Packet Capture</h2><p>{packets.length} packets shown</p></div>
              <div className="actions">
                <div className="search"><Search size={15}/><input placeholder="Search IP, port..." value={search} onChange={e=>setSearch(e.target.value)}/></div>
                <div className="filter"><Filter size={14}/><select value={protocol} onChange={e=>setProtocol(e.target.value)}><option>ALL</option>{Object.keys(stats.protocols||{}).map(p=><option key={p}>{p}</option>)}</select></div>
                <button className="secondary" onClick={clearCapture}><Trash2 size={14}/> Clear</button>
                <a className="secondary" href={`${API}/export`}><Download size={14}/> CSV</a>
              </div>
            </div>
            <div className="table-wrap">
              <table><thead><tr><th>#</th><th>TIME</th><th>SOURCE</th><th>DESTINATION</th><th>PROTOCOL</th><th>PORTS</th><th>LEN</th></tr></thead>
              <tbody>
                {!packets.length ? <tr><td colSpan="7"><div className="empty"><Shield size={28}/><b>No packets captured yet</b><span>Start a capture and generate local traffic.</span></div></td></tr> :
                packets.slice().reverse().map(p=><tr key={p.id} className={selectedPacket?.id===p.id ? "selected":""} onClick={()=>setSelectedPacket(p)}>
                  <td className="muted">{p.id}</td><td className="mono">{formatTime(p.timestamp)}</td>
                  <td className="mono">{p.source}</td><td className="mono">{p.destination}</td>
                  <td><span className={`badge ${protocolColors[p.protocol]||"other"}`}>{p.protocol}</span></td>
                  <td className="mono">{p.sourcePort || p.destinationPort ? `${p.sourcePort||"-"} → ${p.destinationPort||"-"}`:"-"}</td>
                  <td className="mono">{p.length} B</td>
                </tr>)}
              </tbody></table>
            </div>
          </div>

          <aside>
            <div className="panel details">
              <div className="panel-head"><div><h2>Packet Details</h2><p>{selectedPacket ? `Packet #${selectedPacket.id}`:"Select a packet"}</p></div></div>
              {selectedPacket ? <div className="detail-body">
                <Row a="Time" b={formatTime(selectedPacket.timestamp)}/><Row a="Protocol" b={selectedPacket.protocol}/>
                <Row a="Source IP" b={selectedPacket.source} mono/><Row a="Destination IP" b={selectedPacket.destination} mono/>
                <Row a="Source MAC" b={selectedPacket.sourceMac} mono/><Row a="Destination MAC" b={selectedPacket.destinationMac} mono/>
                <Row a="Source Port" b={selectedPacket.sourcePort||"-"}/><Row a="Destination Port" b={selectedPacket.destinationPort||"-"}/>
                <Row a="Length" b={`${selectedPacket.length} bytes`}/><Row a="TCP Flags" b={selectedPacket.tcpFlags||"-"}/>
                <Row a="IP Version" b={selectedPacket.ipVersion ? `IPv${selectedPacket.ipVersion}`:"-"}/><Row a="TTL" b={selectedPacket.ttl||"-"}/>
                <div className="summary"><small>SCAPY SUMMARY</small><code>{selectedPacket.summary}</code></div>
              </div> : <div className="empty small"><Shield size={23}/>Click a packet row to inspect it.</div>}
            </div>

            <div className="panel">
              <div className="panel-head"><div><h2>Protocol Analysis</h2><p>Incremental counters</p></div><BarChart3 size={18}/></div>
              <div className="bars">{protocolEntries.length ? protocolEntries.map(([n,c])=><div className="barrow" key={n}><div><span>{n}</span><b>{c}</b></div><i><em className={protocolColors[n]||"other"} style={{width:`${c/maxProtocol*100}%`}}/></i></div>) : <div className="mini">No data yet.</div>}</div>
            </div>

            <div className="panel">
              <div className="panel-head"><div><h2>Top Talkers</h2><p>Most frequent sources</p></div><Globe2 size={18}/></div>
              <div className="talkers">{stats.topSources?.length ? stats.topSources.map(([ip,c])=><div className="talker" key={ip}><Server size={14}/><span className="mono">{ip}</span><b>{c}</b></div>) : <div className="mini">No source data yet.</div>}</div>
            </div>
          </aside>
        </section>

        <footer><span><CheckCircle2 size={13}/> Authorised local packet analysis</span><span>NetScope • Rubric-Ready CN Lab Project</span></footer>
      </main>
    </div>
  );
}

function Card({icon,label,value,detail}) { return <div className="card"><div className="cardicon">{React.cloneElement(icon,{size:18})}</div><div><small>{label}</small><strong>{value}</strong><span>{detail}</span></div></div>; }
function Row({a,b,mono}) { return <div className="row"><span>{a}</span><b className={mono?"mono":""}>{b}</b></div>; }
