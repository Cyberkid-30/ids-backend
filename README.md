# Network Intrusion Detection System (IDS) Backend

A signature-based Network Intrusion Detection System designed for small-scale business networks. Built with Python, FastAPI, and Scapy.

## Features

- **Packet Capture**: Real-time network traffic capture using Scapy
- **Signature-Based Detection**: Pattern matching against known attack signatures
- **REST API**: Full-featured API for management and monitoring
- **Alert Management**: View, filter, and manage security alerts
- **SQLite Database**: Lightweight, file-based storage
- **Extensible Signatures**: JSON-based signature definitions

## Requirements

- Python 3.10+
- Ubuntu Linux (for packet capture)
- Root privileges or CAP_NET_RAW capability

## Quick Start

### 1. Clone and Setup

```bash
cd ids-backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure

```bash
# Copy and edit configuration
cp .env.example .env
nano .env

# Important: Set your network interface
# Use 'ip link' to list available interfaces
NETWORK_INTERFACE=eth0
```

### 3. Initialize Database

```bash
# Load signatures from JSON files
python scripts/load_signatures.py
```

### 4. Run the Server

```bash
# Development mode (requires sudo for packet capture)
sudo venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Or use the startup script
sudo ./scripts/start_ids.sh --dev
```

### 5. Access the API

- **API Documentation**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/ping

## API Endpoints

### System Control

| Method | Endpoint                           | Description       |
| ------ | ---------------------------------- | ----------------- |
| GET    | `/api/v1/system/health`            | Health check      |
| GET    | `/api/v1/system/status`            | System status     |
| POST   | `/api/v1/system/detection/start`   | Start detection   |
| POST   | `/api/v1/system/detection/stop`    | Stop detection    |
| POST   | `/api/v1/system/signatures/reload` | Reload signatures |

### Alerts

| Method | Endpoint                     | Description             |
| ------ | ---------------------------- | ----------------------- |
| GET    | `/api/v1/alerts`             | List alerts (paginated) |
| GET    | `/api/v1/alerts/{id}`        | Get alert details       |
| PATCH  | `/api/v1/alerts/{id}/status` | Update alert status     |
| DELETE | `/api/v1/alerts/{id}`        | Delete alert            |
| GET    | `/api/v1/alerts/stats`       | Alert statistics        |

### Signatures

| Method | Endpoint                         | Description      |
| ------ | -------------------------------- | ---------------- |
| GET    | `/api/v1/signatures`             | List signatures  |
| POST   | `/api/v1/signatures`             | Create signature |
| GET    | `/api/v1/signatures/{id}`        | Get signature    |
| PUT    | `/api/v1/signatures/{id}`        | Update signature |
| DELETE | `/api/v1/signatures/{id}`        | Delete signature |
| POST   | `/api/v1/signatures/{id}/toggle` | Toggle enabled   |

## Usage Examples

### Start Detection

```bash
# Start the detection engine
curl -X POST http://localhost:8000/api/v1/system/detection/start

# Check status
curl http://localhost:8000/api/v1/system/status
```

### View Alerts

```bash
# Get all alerts
curl http://localhost:8000/api/v1/alerts

# Filter by severity
curl "http://localhost:8000/api/v1/alerts?severity=critical"

# Get alert statistics
curl http://localhost:8000/api/v1/alerts/stats
```

### Manage Signatures

```bash
# Create a new signature
curl -X POST http://localhost:8000/api/v1/signatures \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom SSH Alert",
    "description": "Detect SSH connections",
    "protocol": "tcp",
    "dest_port": "22",
    "severity": "medium",
    "category": "monitoring"
  }'

# Toggle signature on/off
curl -X POST http://localhost:8000/api/v1/signatures/1/toggle
```

## Project Structure

```
ids-backend/
├── app/
│   ├── main.py              # FastAPI application entry
│   ├── core/                # Configuration and logging
│   ├── database/            # SQLAlchemy setup
│   ├── models/              # Database models
│   ├── schemas/             # Pydantic schemas
│   ├── services/            # Business logic
│   │   ├── sniffer.py       # Packet capture
│   │   ├── parser.py        # Packet parsing
│   │   ├── matcher.py       # Signature matching
│   │   ├── detector.py      # Detection engine
│   │   └── alert_manager.py # Alert handling
│   ├── api/                 # REST API routes
│   ├── signatures/          # JSON signature files
│   └── workers/             # Background workers
├── data/                    # Database and logs
├── scripts/                 # Utility scripts
├── tests/                   # Test suite
├── requirements.txt
├── .env
└── README.md
```

## Adding Custom Signatures

Edit `app/signatures/custom.json`:

```json
{
  "signatures": [
    {
      "name": "My Custom Rule",
      "description": "Detects specific traffic pattern",
      "protocol": "tcp",
      "dest_port": "8080",
      "pattern": "malicious_pattern",
      "severity": "high",
      "enabled": true,
      "category": "custom"
    }
  ]
}
```

Then reload: `curl -X POST http://localhost:8000/api/v1/system/signatures/reload`

## Permissions for Packet Capture

### Option 1: Run as Root (Development)

```bash
sudo venv/bin/uvicorn app.main:app --reload
```

### Option 2: Set CAP_NET_RAW (Recommended for Production)

```bash
# Set capability on Python interpreter
sudo setcap cap_net_raw+ep $(which python3)

# Or on the venv Python
sudo setcap cap_net_raw+ep venv/bin/python3
```

## Testing with Kali Linux

From the Kali Linux attacker machine:

```bash
# Port scan (will trigger TCP SYN Scan Detection)
nmap -sS <target_ip>

# Ping sweep (will trigger ICMP Ping Sweep)
ping <target_ip>

# SQL Injection attempt (will trigger SQL Injection Attempt)
curl "http://<target_ip>:8080/?id=1' OR '1'='1"
```

## Troubleshooting

### "Permission denied" on packet capture

Run with sudo or set CAP_NET_RAW capability (see above).

### No alerts generated

1. Check detection is running: `GET /api/v1/system/status`
2. Verify signatures are loaded: `GET /api/v1/signatures`
3. Check network interface is correct in `.env`

### Database errors

```bash
# Reset database
rm data/ids.db
python scripts/load_signatures.py
```

## License

MIT License - See LICENSE file for details.

## Author

Final Year Project - Network Intrusion Detection System
