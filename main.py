"""
Zero Trust SOC - FastAPI Backend
WebSocket live stream + REST API endpoints
No pydantic — pure FastAPI with plain dicts for Python 3.14 compatibility
"""

import asyncio
import json
import random
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Zero Trust SOC Backend")

# Serve the React SPA from /static — mount AFTER API routes are declared
STATIC_DIR = Path(__file__).parent / "static"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Serve frontend ──────────────────────────────────────────────────────────

@app.get("/")
async def serve_frontend():
    return FileResponse(STATIC_DIR / "index.html")

# ─── In-Memory Store ────────────────────────────────────────────────────────

VALID_PASSWORD = "ZERO"
VALID_MFA = "zeroperson"

sessions: Dict[str, dict] = {}

employees: List[dict] = [
    {"id": 1,  "name": "Alice Mercer",    "role": "Security Analyst",      "status": "PENDING",  "remote": False, "ip": "10.0.1.15",       "department": "SOC",        "avatar": "AM", "lastSeen": "2 min ago"},
    {"id": 2,  "name": "Bob Nguyen",      "role": "Network Engineer",       "status": "APPROVED", "remote": True,  "ip": "203.0.113.47",    "department": "NetOps",     "avatar": "BN", "lastSeen": "Just now"},
    {"id": 3,  "name": "Carol Diaz",      "role": "DevOps Engineer",        "status": "PENDING",  "remote": True,  "ip": "198.51.100.89",   "department": "Engineering","avatar": "CD", "lastSeen": "5 min ago"},
    {"id": 4,  "name": "Dan Kowalski",    "role": "IT Administrator",       "status": "APPROVED", "remote": False, "ip": "10.0.1.22",       "department": "IT Ops",     "avatar": "DK", "lastSeen": "1 min ago"},
    {"id": 5,  "name": "Eve Thornton",    "role": "Threat Intel Analyst",   "status": "REJECTED", "remote": True,  "ip": "192.0.2.201",     "department": "SOC",        "avatar": "ET", "lastSeen": "12 min ago"},
    {"id": 6,  "name": "Frank Osei",      "role": "Cloud Architect",        "status": "PENDING",  "remote": True,  "ip": "203.0.113.112",   "department": "Cloud",      "avatar": "FO", "lastSeen": "3 min ago"},
    {"id": 7,  "name": "Grace Lee",       "role": "Compliance Officer",     "status": "APPROVED", "remote": False, "ip": "10.0.2.44",       "department": "GRC",        "avatar": "GL", "lastSeen": "Just now"},
    {"id": 8,  "name": "Hank Patel",      "role": "Pen Tester",             "status": "PENDING",  "remote": True,  "ip": "198.51.100.77",   "department": "Red Team",   "avatar": "HP", "lastSeen": "8 min ago"},
    {"id": 9,  "name": "Ivan Romanov",    "role": "UNKNOWN / UNVERIFIED",   "status": "REJECTED", "remote": True,  "ip": "185.220.101.34",  "department": "UNKNOWN",    "avatar": "IR", "lastSeen": "30 sec ago"},
    {"id": 10, "name": "Julia Santos",    "role": "SOC Manager",            "status": "APPROVED", "remote": False, "ip": "10.0.1.5",        "department": "SOC",        "avatar": "JS", "lastSeen": "Just now"},
    {"id": 11, "name": "Kevin Wu",        "role": "Incident Responder",     "status": "PENDING",  "remote": True,  "ip": "203.0.113.198",   "department": "SOC",        "avatar": "KW", "lastSeen": "4 min ago"},
    {"id": 12, "name": "Lena Muller",     "role": "Malware Analyst",        "status": "APPROVED", "remote": False, "ip": "10.0.3.67",       "department": "SOC",        "avatar": "LM", "lastSeen": "Just now"},
]

event_log: List[dict] = []

# ─── WebSocket Connection Manager ────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, data: dict):
        dead = set()
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.active.discard(ws)

manager = ConnectionManager()

# ─── Simulation Data ─────────────────────────────────────────────────────────

ZONES = ["Corporate Network", "WFH / Remote Nodes", "DMZ Server Zone", "Cloud Services"]
PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "RDP"]
BENIGN_IPS = [
    "10.0.1.15", "10.0.1.22", "10.0.2.44", "10.0.1.5", "10.0.3.67",
    "172.16.0.12", "172.16.0.45", "172.16.1.9",
]
ATTACK_IPS = [
    "185.220.101.34", "45.33.32.156", "23.95.97.58", "103.21.244.0",
    "194.165.16.11", "91.108.56.130", "109.248.9.17", "5.188.62.140",
    "198.51.100.42", "192.0.2.201", "203.0.113.251",
]

attack_counter = 0
packet_counter = 0


def ts():
    return datetime.utcnow().strftime("%H:%M:%S")


def make_benign_packet():
    global packet_counter
    packet_counter += 1
    src_zone = random.choice(ZONES)
    dst_zone = random.choice([z for z in ZONES if z != src_zone])
    return {
        "type": "PACKET",
        "id": packet_counter,
        "timestamp": ts(),
        "src_ip": random.choice(BENIGN_IPS),
        "dst_ip": random.choice(BENIGN_IPS),
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "protocol": random.choice(PROTOCOLS),
        "bytes": random.randint(64, 1500),
        "status": "ALLOWED",
        "threat": False,
    }


def make_attack_event():
    global attack_counter, packet_counter
    attack_counter += 1
    packet_counter += 1
    attack_types = ["DoS SYN Flood", "DDoS UDP Flood", "DDoS HTTP Flood", "DoS ICMP Flood", "DDoS Amplification"]
    attack_type = random.choice(attack_types)
    target_zone = random.choice(ZONES)
    attack_ip = random.choice(ATTACK_IPS)
    pps = random.randint(8000, 250000)
    return {
        "type": "ATTACK",
        "id": packet_counter,
        "timestamp": ts(),
        "attack_id": attack_counter,
        "attack_type": attack_type,
        "src_ip": attack_ip,
        "dst_zone": target_zone,
        "pps": pps,
        "status": "AUTOMATICALLY DENIED",
        "threat": True,
        "message": f"[AUTOMATED ACTION] Blocked {attack_type} from IP {attack_ip} -> {target_zone} (Action: Denied)",
    }


async def stream_loop():
    """Continuously broadcast simulated traffic to all connected WebSocket clients."""
    while True:
        await asyncio.sleep(random.uniform(0.8, 1.8))
        roll = random.random()
        if roll < 0.25:
            event = make_attack_event()
            event_log.insert(0, {
                "timestamp": event["timestamp"],
                "level": "CRITICAL",
                "message": event["message"],
            })
            if len(event_log) > 500:
                event_log.pop()
        else:
            event = make_benign_packet()

        await manager.broadcast(event)

        # Occasionally broadcast a stats snapshot
        if random.random() < 0.15:
            await manager.broadcast({
                "type": "STATS",
                "timestamp": ts(),
                "total_packets": packet_counter,
                "total_attacks_blocked": attack_counter,
                "active_connections": len(manager.active),
                "threat_level": "HIGH" if attack_counter % 5 < 2 else "MEDIUM",
            })


# ─── Startup ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(stream_loop())


# ─── Auth Endpoints ───────────────────────────────────────────────────────────

@app.post("/api/auth/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    if password != VALID_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    session_id = f"sess_{int(time.time()*1000)}_{random.randint(1000,9999)}"
    sessions[session_id] = {
        "username": username,
        "mfa_verified": False,
        "created_at": time.time(),
    }
    log_event("INFO", f"Login successful for user '{username}' — MFA required")
    return JSONResponse({"session_id": session_id, "username": username, "requires_mfa": True})


@app.post("/api/auth/verify-mfa")
async def verify_mfa(request: Request):
    body = await request.json()
    session_id = body.get("session_id", "")
    mfa_code = body.get("mfa_code", "")
    if session_id not in sessions:
        raise HTTPException(status_code=401, detail="Invalid session")
    if mfa_code != VALID_MFA:
        log_event("WARNING", f"MFA verification FAILED for session {session_id}")
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    sessions[session_id]["mfa_verified"] = True
    sessions[session_id]["mfa_at"] = time.time()
    log_event("SUCCESS", f"MFA verified — session {session_id} granted Zero Trust access")
    return JSONResponse({"verified": True, "message": "MFA verified. Access granted."})


# ─── Employee Endpoints ───────────────────────────────────────────────────────

@app.get("/api/employees")
async def get_employees():
    return JSONResponse({"employees": employees})


@app.post("/api/employees/{emp_id}/action")
async def employee_action(emp_id: int, request: Request):
    body = await request.json()
    action = body.get("action", "")
    if action not in ("APPROVED", "REJECTED"):
        raise HTTPException(status_code=400, detail="action must be APPROVED or REJECTED")
    for emp in employees:
        if emp["id"] == emp_id:
            old_status = emp["status"]
            emp["status"] = action
            action_word = "APPROVED access for" if action == "APPROVED" else "REJECTED / REVOKED access for"
            msg = f"[SOC MANAGER] {action_word} employee '{emp['name']}' ({emp['role']}) — previous: {old_status}"
            log_event("CRITICAL" if action == "REJECTED" else "SUCCESS", msg)
            await manager.broadcast({
                "type": "EMPLOYEE_UPDATE",
                "employee_id": emp_id,
                "name": emp["name"],
                "new_status": action,
                "timestamp": ts(),
                "message": msg,
            })
            return JSONResponse({"success": True, "employee": emp})
    raise HTTPException(status_code=404, detail="Employee not found")


# ─── Logs Endpoint ────────────────────────────────────────────────────────────

@app.get("/api/logs")
async def get_logs():
    return JSONResponse({"logs": event_log[:100]})


# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await websocket.send_json({
            "type": "CONNECTED",
            "message": "Zero Trust SOC stream active",
            "timestamp": ts(),
        })
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "PING", "timestamp": ts()})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return JSONResponse({"status": "ok", "timestamp": ts()})


# ─── Helpers ─────────────────────────────────────────────────────────────────

def log_event(level: str, message: str):
    event_log.insert(0, {"timestamp": ts(), "level": level, "message": message})
    if len(event_log) > 500:
        event_log.pop()
