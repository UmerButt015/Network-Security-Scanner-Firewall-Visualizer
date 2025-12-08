
# backend.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uvicorn
import socket
import time
import json
import threading
import queue
from datetime import datetime
import uuid
import asyncio
from contextlib import asynccontextmanager
import logging
import re

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Optional imports
try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False
    logger.warning("nmap not available")

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import networkx as nx
    import io
    import base64
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    logger.warning("matplotlib not available")

# ==================== Global State ====================
active_scans: Dict[str, Dict] = {}
firewall_sim = None  # Will be initialized

# ==================== Common Services ====================
COMMON_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 137: "NetBIOS", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    3389: "RDP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 3306: "MySQL",
    5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"
}

# ==================== Scanner Class ====================
class Scanner:
    def __init__(self, result_queue=None, timeout=1.0):
        self.result_queue = result_queue or queue.Queue()
        self.timeout = timeout
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()

    def tcp_connect_scan(self, target, ports):
        logger.info(f"Starting TCP connect scan on {target} ports {ports}")
        
        # Show scanning progress
        total_ports = len(ports)
        for i, port in enumerate(ports):
            if self.is_stopped(): 
                break
                
            # Progress update every 10 ports or for small scans
            if total_ports > 10 and i % 10 == 0:
                logger.info(f"Scan progress: {i}/{total_ports} ports ({i/total_ports*100:.1f}%)")
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            start = time.time()
            status = "closed"
            rtt = None
            try:
                res = s.connect_ex((target, port))
                rtt = (time.time() - start) * 1000
                status = "open" if res == 0 else "closed"
                
                if status == "open":
                    logger.info(f"Found open port: {port} ({COMMON_SERVICES.get(port, 'Unknown')})")
            except Exception as e:
                logger.error(f"Error scanning port {port}: {e}")
                status = "error"
            finally:
                try: 
                    s.close()
                except: 
                    pass

            self.result_queue.put({
                "ip": target,
                "port": port,
                "service": COMMON_SERVICES.get(port, ""),
                "status": status,
                "rtt_ms": round(rtt, 2) if rtt else None
            })
        self.result_queue.put({"done": True})
        logger.info(f"TCP scan completed for {target}")

    def udp_probe(self, target, ports):
        logger.info(f"Starting UDP probe on {target} ports {ports}")
        
        total_ports = len(ports)
        for i, port in enumerate(ports):
            if self.is_stopped(): 
                break
                
            if total_ports > 10 and i % 10 == 0:
                logger.info(f"UDP scan progress: {i}/{total_ports} ports")
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            status = "closed"
            rtt = None
            try:
                start = time.time()
                s.sendto(b'\x00', (target, port))
                s.recvfrom(1024)
                rtt = (time.time() - start) * 1000
                status = "open|responded"
                logger.info(f"UDP port {port} responded")
            except socket.timeout:
                status = "open|filtered"
            except Exception as e:
                logger.error(f"Error UDP probing port {port}: {e}")
                status = "error"
            finally:
                try: 
                    s.close()
                except: 
                    pass

            self.result_queue.put({
                "ip": target,
                "port": port,
                "service": COMMON_SERVICES.get(port, ""),
                "status": status,
                "rtt_ms": round(rtt, 2) if rtt else None
            })
        self.result_queue.put({"done": True})
        logger.info(f"UDP scan completed for {target}")

    def nmap_scan(self, target, ports_str, scan_type="syn"):
        if not HAS_NMAP:
            self.result_queue.put({"error": "nmap not available"})
            self.result_queue.put({"done": True})
            return
        
        logger.info(f"Starting Nmap scan on {target} ports {ports_str}")
        nm = nmap.PortScanner()
        args = "-sS -Pn -T4" if scan_type == "syn" else "-sT -Pn -T4"
        if "udp" in scan_type:
            args = "-sU -Pn -T4"
        try:
            nm.scan(target, ports_str, arguments=args)
            for host in nm.all_hosts():
                logger.info(f"Scanned host: {host}")
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    logger.info(f"Found {len(ports)} {proto} ports")
                    for p in sorted(ports):
                        st = nm[host][proto][p]["state"]
                        svc = nm[host][proto][p].get("name","")
                        self.result_queue.put({
                            "ip": host,
                            "port": p,
                            "service": svc,
                            "status": st,
                            "rtt_ms": None
                        })
                        if st == "open":
                            logger.info(f"Nmap found open: {p}/{proto} ({svc})")
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            self.result_queue.put({"error": str(e)})
        self.result_queue.put({"done": True})
        logger.info(f"Nmap scan completed for {target}")

# ==================== Firewall Simulator ====================
class FirewallSimulator:
    def __init__(self):
        self.rules = []
        self.next_id = 1
        logger.info("Firewall simulator initialized")

    def add_rule(self, action, ip_spec, port_spec, protocol, priority=100, note=""):
        rule = {
            "id": self.next_id,
            "action": action.lower(),
            "ip": ip_spec.strip(),
            "port": port_spec.strip(),
            "protocol": protocol.lower(),
            "priority": int(priority),
            "note": note
        }
        self.next_id += 1
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r["priority"])
        logger.info(f"Added rule: {rule}")
        return rule

    def remove_rule(self, rid):
        self.rules = [r for r in self.rules if r["id"] != rid]
        logger.info(f"Removed rule ID: {rid}")

    def test_packet(self, ip, port, protocol):
        for r in self.rules:
            if (self._matches(r["ip"], ip) and 
                self._port_matches(r["port"], port) and 
                (r["protocol"] == "any" or r["protocol"] == protocol.lower())):
                logger.info(f"Packet {ip}:{port}/{protocol} matched rule {r['id']}")
                return {"action": r["action"], "rule": r}
        logger.info(f"Packet {ip}:{port}/{protocol} default allow")
        return {"action": "allow", "rule": None}

    def _matches(self, rule_ip, ip):
        rule_ip = rule_ip.strip()
        if rule_ip == "" or rule_ip.lower() == "any":
            return True
        if "/" in rule_ip:
            try:
                import ipaddress
                net = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(ip) in net
            except Exception:
                return False
        if "-" in rule_ip:
            try:
                a,b = rule_ip.split("-")
                ai = tuple(map(int, a.split(".")))
                bi = tuple(map(int, b.split(".")))
                ipt = tuple(map(int, ip.split(".")))
                return ai <= ipt <= bi
            except Exception:
                return False
        return rule_ip == ip

    def _port_matches(self, rule_port, port):
        rule_port = rule_port.strip()
        if rule_port == "" or rule_port.lower() == "any":
            return True
        if "-" in rule_port:
            try:
                a,b = map(int, rule_port.split("-"))
                return a <= int(port) <= b
            except:
                return False
        if "," in rule_port:
            parts = [int(p.strip()) for p in rule_port.split(",") if p.strip().isdigit()]
            return int(port) in parts
        try:
            return int(rule_port) == int(port)
        except:
            return False

    def to_json(self):
        return json.dumps(self.rules, indent=2)

    def from_json(self, txt):
        rules = json.loads(txt)
        self.rules = rules
        self.next_id = max((r.get("id",0) for r in self.rules), default=0) + 1
        self.rules.sort(key=lambda r: r["priority"])
        logger.info(f"Loaded {len(self.rules)} rules from JSON")

# ==================== Pydantic Models ====================
class ScanRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "target": "127.0.0.1",
            "ports": "80,443,22,8080,20-30",
            "scan_type": "tcp-connect",
            "timeout_ms": 2000
        }
    })
    
    target: str = Field(..., description="Target IP address or hostname")
    ports: str = Field("1-1024", description="Ports to scan. Examples: '80,443,22' or '20-30' or '80,443,22-25,8080' or 'all' for 1-65535")
    scan_type: str = Field("tcp-connect", description="Scan type: tcp-connect, udp, syn(nmap)")
    timeout_ms: int = Field(2000, description="Timeout in milliseconds")

class FirewallRule(BaseModel):
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "action": "deny",
            "ip": "192.168.1.0/24",
            "port": "80",
            "protocol": "tcp",
            "priority": 100,
            "note": "Example rule"
        }
    })
    
    action: str = Field(..., description="allow or deny")
    ip: str = Field("any", description="IP address, CIDR, or range")
    port: str = Field("any", description="Port number or range")
    protocol: str = Field("any", description="any, tcp, or udp")
    priority: int = Field(100, description="Priority 1-1000")
    note: Optional[str] = None

class TestPacket(BaseModel):
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "ip": "127.0.0.1",
            "port": 80,
            "protocol": "tcp"
        }
    })
    
    ip: str = Field(..., description="Source IP")
    port: int = Field(..., description="Port number")
    protocol: str = Field(..., description="tcp or udp")

# ==================== IMPROVED Port Parser ====================
def parse_ports_spec(spec: str) -> List[int]:
    """
    Parse port specification string into list of port numbers.
    Supports:
    - Single port: "80"
    - Multiple ports: "80,443,22"
    - Range: "20-30"
    - Mixed: "80,443,20-30,8080"
    - All ports: "all" or "1-65535"
    - Default: "1-1024" if empty
    """
    spec = spec.strip().lower()
    
    # If empty, return default 1-1024
    if not spec:
        return list(range(1, 1025))
    
    # If "all", return all ports 1-65535
    if spec == "all":
        logger.info("Scanning all ports (1-65535)")
        return list(range(1, 65536))
    
    # Remove spaces and split by commas
    ports = []
    parts = [p.strip() for p in spec.split(',')]
    
    for part in parts:
        if not part:
            continue
            
        # Check if it's a range (e.g., "20-30")
        if '-' in part:
            try:
                start, end = part.split('-')
                start = int(start.strip())
                end = int(end.strip())
                
                # Validate range
                if start < 1 or end > 65535:
                    raise ValueError(f"Ports must be between 1-65535: {part}")
                if start > end:
                    start, end = end, start  # Swap if reversed
                
                ports.extend(range(start, end + 1))
                logger.debug(f"Added range {start}-{end} ({end - start + 1} ports)")
                
            except ValueError as e:
                raise ValueError(f"Invalid port range '{part}': {e}")
        
        # Single port
        else:
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port must be between 1-65535: {port}")
                ports.append(port)
            except ValueError as e:
                raise ValueError(f"Invalid port number '{part}': {e}")
    
    # Remove duplicates and sort
    unique_ports = sorted(set(ports))
    
    # Warn if too many ports
    if len(unique_ports) > 1000:
        logger.warning(f"Scanning {len(unique_ports)} ports - this may take a while!")
    
    logger.info(f"Parsed {len(unique_ports)} unique ports from spec: '{spec}'")
    return unique_ports

# ==================== Helper Functions ====================
def generate_visualization() -> Optional[str]:
    if not HAS_MATPLOTLIB:
        return None
    
    plt.figure(figsize=(10, 6))
    ax = plt.gca()
    
    G = nx.DiGraph()
    G.add_node("Incoming", type="in")
    
    for r in firewall_sim.rules:
        label = f"#{r['id']} {r['action'].upper()}\n{r['ip']}:{r['port']}\n{r['protocol']}\nprio {r['priority']}"
        G.add_node(label, type="rule", rule=r)
        G.add_edge("Incoming", label)
    
    G.add_node("Decision", type="out")
    if firewall_sim.rules:
        last_rule = firewall_sim.rules[-1]
        last_label = f"#{last_rule['id']} {last_rule['action'].upper()}\n{last_rule['ip']}:{last_rule['port']}\n{last_rule['protocol']}\nprio {last_rule['priority']}"
        G.add_edge(last_label, "Decision")
    else:
        G.add_edge("Incoming", "Decision")

    pos = nx.spring_layout(G, seed=42)
    node_colors = []
    labels = {}
    
    for n in G.nodes(data=True):
        labels[n[0]] = n[0]
        t = n[1].get("type", "")
        if t == "in" or t == "out":
            node_colors.append("#00d2ff")
        else:
            node_colors.append("#bdbdbd")

    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=1500)
    nx.draw_networkx_labels(G, pos, labels=labels, ax=ax, font_size=8, font_color="#0b2a33")
    
    edge_colors = ["#888888" for _ in G.edges()]
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color=edge_colors, arrows=True)
    ax.axis('off')
    plt.tight_layout()
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
    plt.close()
    buf.seek(0)
    
    img_str = base64.b64encode(buf.read()).decode('utf-8')
    return f"data:image/png;base64,{img_str}"

# ==================== FastAPI App ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global firewall_sim
    firewall_sim = FirewallSimulator()
    logger.info("Application starting up...")
    
    # Add some default rules
    firewall_sim.add_rule("allow", "127.0.0.1", "any", "any", 10, "Localhost")
    firewall_sim.add_rule("deny", "any", "22", "tcp", 50, "Block SSH")
    firewall_sim.add_rule("allow", "any", "80,443", "tcp", 100, "Allow HTTP/HTTPS")
    
    cleanup_task = asyncio.create_task(cleanup_old_scans())
    yield
    # Shutdown
    cleanup_task.cancel()

# Create FastAPI app
app = FastAPI(
    title="Network Scanner & Firewall Visualizer API",
    version="2.0.0",
    description="""
    Advanced Network Scanner with Flexible Port Configuration.
    
    **Features:**
    - Scan any port combination (single, multiple, ranges)
    - TCP Connect, UDP, and Nmap SYN scans
    - Firewall rule management
    - Real-time packet testing
    - Visual firewall rule representation
    
    **Port Examples:**
    - Single: `80`
    - Multiple: `80,443,22`
    - Range: `20-30`
    - Mixed: `80,443,20-30,8080`
    - All ports: `all` or `1-65535`
    """,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== API Endpoints ====================
@app.get("/")
async def root():
    return HTMLResponse("""
    <html>
    <head>
        <title>🔍 Advanced Network Scanner</title>
        <style>
            body { font-family: Arial; margin: 40px; background: #f5f5f5; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 5px 20px rgba(0,0,0,0.1); }
            h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
            .card { background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 5px solid #2196F3; }
            code { background: #2d2d2d; color: #f8f8f2; padding: 2px 6px; border-radius: 4px; }
            .example { background: #e8f5e8; padding: 15px; border-radius: 6px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Advanced Network Scanner API</h1>
            <p><strong>Status:</strong> ✅ Running</p>
            
            <div class="card">
                <h3>🚀 Quick Start</h3>
                <p>Test these endpoints:</p>
                <ul>
                    <li><a href="/api/health" target="_blank">/api/health</a> - Health check</li>
                    <li><a href="/api/firewall/rules" target="_blank">/api/firewall/rules</a> - Get firewall rules</li>
                    <li><a href="/docs" target="_blank">/docs</a> - Interactive API documentation</li>
                </ul>
            </div>
            
            <div class="card">
                <h3>🎯 Flexible Port Scanning</h3>
                <p>Scan <strong>ANY</strong> port combination:</p>
                <div class="example">
                    <strong>Examples:</strong><br>
                    • Single port: <code>80</code><br>
                    • Multiple ports: <code>80,443,22</code><br>
                    • Range: <code>20-30</code><br>
                    • Mixed: <code>80,443,20-30,8080</code><br>
                    • All ports: <code>all</code> or <code>1-65535</code>
                </div>
            </div>
            
            <div class="card">
                <h3>🔧 API Endpoints</h3>
                <pre>
POST   /api/scan/start              - Start scan with custom ports
GET    /api/scan/results/{scan_id}  - Get scan results
POST   /api/scan/cancel/{scan_id}   - Cancel scan
GET    /api/firewall/rules          - Get all firewall rules
POST   /api/firewall/rules          - Add firewall rule
DELETE /api/firewall/rules/{id}     - Delete firewall rule
POST   /api/firewall/test           - Test packet against firewall
POST   /api/firewall/visualize      - Get firewall visualization
                </pre>
            </div>
            
            <div class="card">
                <h3>📱 Test Scanner</h3>
                <p>Try a quick scan:</p>
                <button onclick="testScan()" style="background:#4CAF50;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;">
                    Test Scan Localhost Ports 80,443,22
                </button>
                <div id="result" style="margin-top:10px;"></div>
            </div>
        </div>
        
        <script>
        async function testScan() {
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '⏳ Starting scan...';
            
            try {
                const response = await fetch('/api/scan/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        target: '127.0.0.1',
                        ports: '80,443,22',
                        scan_type: 'tcp-connect',
                        timeout_ms: 2000
                    })
                });
                
                const data = await response.json();
                resultDiv.innerHTML = `✅ Scan started! ID: ${data.scan_id}<br>⏳ Getting results...`;
                
                // Get results after 3 seconds
                setTimeout(async () => {
                    const res = await fetch(`/api/scan/results/${data.scan_id}`);
                    const results = await res.json();
                    resultDiv.innerHTML += `<br>📊 Found ${results.results?.length || 0} ports`;
                }, 3000);
                
            } catch (error) {
                resultDiv.innerHTML = `❌ Error: ${error.message}`;
            }
        }
        </script>
    </body>
    </html>
    """)

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "nmap_available": HAS_NMAP,
        "visualization_available": HAS_MATPLOTLIB,
        "active_scans": len(active_scans),
        "firewall_rules": len(firewall_sim.rules) if firewall_sim else 0,
        "port_range_supported": "1-65535 (flexible input)"
    }

@app.post("/api/scan/start")
async def start_scan(request: ScanRequest):
    logger.info(f"Received scan request: target={request.target}, ports={request.ports}, type={request.scan_type}")
    
    try:
        ports = parse_ports_spec(request.ports)
        logger.info(f"Parsed {len(ports)} ports for scanning")
        
        # Limit warning for large scans
        if len(ports) > 10000:
            logger.warning(f"Large scan requested: {len(ports)} ports. This may take several minutes.")
        
    except ValueError as e:
        logger.error(f"Invalid port specification '{request.ports}': {e}")
        raise HTTPException(
            status_code=422, 
            detail={
                "error": "Invalid port specification",
                "message": str(e),
                "examples": {
                    "single": "80",
                    "multiple": "80,443,22",
                    "range": "20-30",
                    "mixed": "80,443,20-30,8080",
                    "all": "all or 1-65535"
                }
            }
        )
    
    scan_id = str(uuid.uuid4())
    result_queue = queue.Queue()
    scanner = Scanner(result_queue=result_queue, timeout=request.timeout_ms/1000)
    
    active_scans[scan_id] = {
        "scanner": scanner,
        "thread": None,
        "results": [],
        "complete": False,
        "start_time": datetime.now(),
        "target": request.target,
        "ports": request.ports,
        "total_ports": len(ports)
    }
    
    def scan_thread():
        session = active_scans[scan_id]
        try:
            logger.info(f"Starting {request.scan_type} scan on {request.target} ({len(ports)} ports)")
            
            if request.scan_type == "syn(nmap)" and HAS_NMAP:
                scanner.nmap_scan(request.target, request.ports, "syn")
            elif request.scan_type == "udp":
                scanner.udp_probe(request.target, ports)
            else:  # tcp-connect (default)
                scanner.tcp_connect_scan(request.target, ports)
                
        except Exception as e:
            logger.error(f"Scan error: {e}")
            result_queue.put({"error": str(e)})
        finally:
            session["complete"] = True
            logger.info(f"Scan {scan_id} completed")
    
    thread = threading.Thread(target=scan_thread, daemon=True)
    thread.start()
    active_scans[scan_id]["thread"] = thread
    
    logger.info(f"Started scan {scan_id} ({len(ports)} ports)")
    return {
        "scan_id": scan_id, 
        "message": "Scan started successfully", 
        "target": request.target,
        "ports": request.ports,
        "total_ports": len(ports),
        "scan_type": request.scan_type,
        "estimated_time": f"{(len(ports) * request.timeout_ms/1000):.1f} seconds"
    }

@app.get("/api/scan/results/{scan_id}")
async def get_scan_results(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    session = active_scans[scan_id]
    scanner = session["scanner"]
    results = session["results"]
    
    try:
        while True:
            item = scanner.result_queue.get_nowait()
            if item.get("done"):
                session["complete"] = True
                continue
            if item.get("error"):
                return {"error": item.get("error"), "results": results, "complete": True}
            if "ip" in item:
                results.append(item)
    except queue.Empty:
        pass
    
    # Count open ports
    open_ports = [r for r in results if r.get("status") == "open" or "open" in str(r.get("status", ""))]
    
    logger.info(f"Returning {len(results)} results for scan {scan_id} ({len(open_ports)} open)")
    return {
        "scan_id": scan_id,
        "target": session.get("target", "unknown"),
        "ports_spec": session.get("ports", ""),
        "results": results,
        "complete": session["complete"],
        "total_scanned": len(results),
        "open_ports": len(open_ports),
        "open_ports_list": [r["port"] for r in open_ports]
    }

@app.post("/api/scan/cancel/{scan_id}")
async def cancel_scan(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    session = active_scans[scan_id]
    session["scanner"].stop()
    session["complete"] = True
    
    logger.info(f"Cancelled scan {scan_id}")
    return {"message": "Scan cancelled", "scan_id": scan_id}

@app.get("/api/firewall/rules")
async def get_firewall_rules():
    rules = firewall_sim.rules if firewall_sim else []
    logger.info(f"Returning {len(rules)} firewall rules")
    return rules

@app.post("/api/firewall/rules")
async def add_firewall_rule(rule: FirewallRule):
    try:
        new_rule = firewall_sim.add_rule(
            action=rule.action,
            ip_spec=rule.ip,
            port_spec=rule.port,
            protocol=rule.protocol,
            priority=rule.priority,
            note=rule.note or ""
        )
        logger.info(f"Added new firewall rule: {new_rule}")
        return new_rule
    except Exception as e:
        logger.error(f"Error adding rule: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/api/firewall/rules/{rule_id}")
async def delete_firewall_rule(rule_id: int):
    firewall_sim.remove_rule(rule_id)
    logger.info(f"Deleted firewall rule {rule_id}")
    return {"message": f"Rule {rule_id} deleted"}

@app.post("/api/firewall/test")
async def test_firewall_packet(packet: TestPacket):
    result = firewall_sim.test_packet(packet.ip, packet.port, packet.protocol)
    logger.info(f"Packet test result: {result}")
    return result

@app.post("/api/firewall/visualize")
async def visualize_firewall():
    img_data = generate_visualization()
    if img_data:
        return {"image": img_data}
    else:
        return {"error": "Visualization requires matplotlib and networkx"}

# ==================== Background Tasks ====================
async def cleanup_old_scans():
    while True:
        await asyncio.sleep(300)
        now = datetime.now()
        to_delete = []
        for scan_id, session in active_scans.items():
            if session["complete"] and (now - session["start_time"]).seconds > 600:
                to_delete.append(scan_id)
        for scan_id in to_delete:
            del active_scans[scan_id]
            logger.info(f"Cleaned up old scan {scan_id}")

# ==================== Main Entry ====================
if __name__ == "__main__":
    print("=" * 70)
    print("🚀 ADVANCED NETWORK SCANNER & FIREWALL API")
    print("=" * 70)
    print(f"📡 NMAP available: {HAS_NMAP}")
    print(f"🎨 Visualization available: {HAS_MATPLOTLIB}")
    print("\n🎯 FLEXIBLE PORT INPUT SUPPORTED:")
    print("  • Single port: 80")
    print("  • Multiple: 80,443,22")
    print("  • Range: 20-30")
    print("  • Mixed: 80,443,20-30,8080")
    print("  • All ports: 'all' or '1-65535'")
    print("\n📍 Access Points:")
    print("  http://localhost:8000/              - Home page")
    print("  http://localhost:8000/api/health    - Health check")
    print("  http://localhost:8000/docs          - Swagger UI")
    print("\n🔧 Starting server...")
    print("=" * 70)
    
    # Run with uvicorn
    uvicorn.run(
        "backend:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
