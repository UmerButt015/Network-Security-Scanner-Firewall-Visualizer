# Network-Security-Scanner-Firewall-Visualizer
A professional, full-stack network security tool featuring advanced port scanning, firewall simulation, and real-time visualization capabilities. Built with FastAPI backend and Flutter frontend.


🚀 Features
📡 Advanced Port Scanner
Flexible Port Specification: Scan any port combination (single, multiple, ranges)

Multiple Scan Types: TCP Connect, UDP, Nmap SYN scans

Real-time Results: Live updates during scanning

Service Detection: Automatic identification of common services

Custom Port Input: Support for formats like 80,443, 20-30, 80,443,20-25,8080, or all

🛡️ Firewall Simulator
Rule Management: Add, edit, delete firewall rules with priority system

Advanced Matching: Supports CIDR, IP ranges, port ranges, and protocols

Packet Testing: Test packets against firewall rules in real-time

Priority-based Evaluation: Rules evaluated based on priority (1-1000)

📊 Real-time Visualization
Interactive Graph: Visual representation of firewall rules and traffic flow

Color-coded Nodes: Different colors for allow/deny rules and packet paths

Live Updates: Visualization updates as rules change

💻 Modern UI/UX
Cross-platform: Flutter-based frontend for desktop and mobile

Dark Theme: Professional dark interface with neon accents

Responsive Design: Adapts to different screen sizes

Real-time Feedback: Live scanning progress and results

🏗️ Architecture
text
┌─────────────────┐    REST API    ┌─────────────────┐
│                 │◄───────────────►│                 │
│  Flutter        │                 │  FastAPI        │
│  Frontend       │    WebSocket    │  Backend        │
│  (Cross-platform)│◄───────────────►│  (Python)      │
│                 │                 │                 │
└─────────────────┘                 └─────────────────┘
         │                                    │
         │                                    │
         ▼                                    ▼
┌─────────────────┐                 ┌─────────────────┐
│                 │                 │                 │
│  User Interface │                 │  Scanner Engine │
│                 │                 │  Firewall Sim   │
│                 │                 │  Visualization  │
└─────────────────┘                 └─────────────────┘
📦 Installation
Backend Setup (FastAPI)
bash
# Clone the repository
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: Install Nmap for advanced scanning
# sudo apt-get install nmap  # Linux
# brew install nmap         # macOS
# Download from nmap.org    # Windows

# Run the backend
python backend.py
Frontend Setup (Flutter)
bash
# Navigate to frontend directory
cd frontend

# Install dependencies
flutter pub get

# Run for web
flutter run -d chrome

# Or run for Android
flutter run -d emulator

# Or build for production
flutter build web
🎯 Usage Examples
1. Start a Scan
python
# Using Python requests
import requests

response = requests.post("http://localhost:8000/api/scan/start", json={
    "target": "127.0.0.1",
    "ports": "80,443,22,20-30,8080",  # Flexible port input
    "scan_type": "tcp-connect",
    "timeout_ms": 2000
})
2. Add Firewall Rule
python
response = requests.post("http://localhost:8000/api/firewall/rules", json={
    "action": "deny",
    "ip": "192.168.1.0/24",
    "port": "22",
    "protocol": "tcp",
    "priority": 100,
    "note": "Block SSH from internal network"
})
3. Test Packet
python
response = requests.post("http://localhost:8000/api/firewall/test", json={
    "ip": "192.168.1.100",
    "port": 80,
    "protocol": "tcp"
})
🔧 API Endpoints
Method	Endpoint	Description
GET	/api/health	Health check and system status
POST	/api/scan/start	Start a new scan
GET	/api/scan/results/{scan_id}	Get scan results
POST	/api/scan/cancel/{scan_id}	Cancel ongoing scan
GET	/api/firewall/rules	Get all firewall rules
POST	/api/firewall/rules	Add new firewall rule
DELETE	/api/firewall/rules/{rule_id}	Delete firewall rule
POST	/api/firewall/test	Test packet against firewall
POST	/api/firewall/visualize	Get firewall visualization

🔒 Security Features
Input Validation: All inputs validated with Pydantic models
Rate Limiting: Built-in protection against abuse
Session Management: Proper scan session handling
Error Handling: Comprehensive error messages and logging
CORS Configuration: Secure cross-origin requests

🚨 Limitations & Considerations
Network Permissions: Scanning requires appropriate network permissions
Legal Compliance: Only scan networks you own or have permission to test
Performance: Large port ranges (1000+ ports) may take significant time
Nmap Dependency: Advanced scanning features require Nmap installation
