"""Execute one real, isolated attack probe and emit JSON-lines results."""
import json
import os
import sys
import time
import base64

import requests


def emit(event_type, payload, **details):
    print(json.dumps({"type": event_type, "payload": payload, "details": details}), flush=True)


def brute_force(target, params):
    attempts = int(params["attempts"])
    username = params.get("username", "invalid-user")
    for index in range(attempts):
        response = requests.post(
            f"{target}/login-secure",
            data={"username": username, "password": os.urandom(12).hex()},
            timeout=5,
        )
        emit("login_attempt", f"Attempt {index + 1}/{attempts}", status_code=response.status_code)


def sqli(target, params):
    for payload in params["payloads"]:
        response = requests.post(f"{target}/login", data={"username": payload, "password": "probe"}, timeout=5)
        emit("sqli_payload", payload, status_code=response.status_code, response=response.text[:500])


def xss(target, params):
    for payload in params["payloads"]:
        response = requests.get(f"{target}/search", params={"q": payload}, timeout=5)
        emit("xss_payload", payload, status_code=response.status_code, reflected=payload in response.text)


def port_scan(target, params):
    import nmap
    scanner = nmap.PortScanner()
    result = scanner.scan(target, params.get("ports", "1-1024"), arguments="-sV --open")
    emit("port_scan", "nmap scan completed", result=result.get("scan", {}))


def vuln_scan(target, params):
    """Inspect the live sandbox target's response headers from the attacker network."""
    response = requests.get(f"{target}/", timeout=5)
    headers = {name.lower(): value for name, value in response.headers.items()}
    checks = {
        "https": target.startswith("https://"),
        "hsts": "strict-transport-security" in headers,
        "csp": "content-security-policy" in headers,
        "x_frame_options": "x-frame-options" in headers,
        "x_content_type_options": "x-content-type-options" in headers,
    }
    emit(
        "vulnerability_headers",
        "Sandbox target headers inspected",
        status_code=response.status_code,
        checks=checks,
        server=headers.get("server"),
    )


def packet_capture(target, params):
    """Capture only packets visible inside this isolated attacker container."""
    from scapy.all import AsyncSniffer, IP, TCP, UDP

    duration = params.get("duration_seconds")
    if not isinstance(duration, (int, float)) or not 1 <= duration <= 60:
        raise ValueError("packet_capture requires duration_seconds between 1 and 60")

    sniffer = AsyncSniffer(iface="eth0", store=True)
    sniffer.start()
    try:
        # Generate real internal traffic while the capture is active.
        requests.get(f"{target}/", timeout=5)
        time.sleep(float(duration))
    finally:
        packets = sniffer.stop()

    for packet in packets:
        details = {
            "type": packet.lastlayer().name,
            "src": packet[IP].src if IP in packet else None,
            "dst": packet[IP].dst if IP in packet else None,
            "port": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None,
            "flags": str(packet[TCP].flags) if TCP in packet else None,
            "length": len(packet),
        }
        emit("packet_captured", packet.summary(), **details)
    emit("packet_capture_complete", f"Captured {len(packets)} sandbox packets", packet_count=len(packets))


def main():
    sim_type = os.environ["SIM_TYPE"]
    target = os.environ["TARGET_URL"].rstrip("/")
    encoded_params = os.environ.get("SIM_PARAMS_B64")
    if encoded_params:
        params = json.loads(base64.b64decode(encoded_params).decode("utf-8"))
    else:
        params = json.loads(os.environ.get("SIM_PARAMS", "{}"))
    handlers = {
        "brute_force": brute_force,
        "sqli": sqli,
        "xss": xss,
        "port_scan": port_scan,
        "vuln_scan": vuln_scan,
        "packet_capture": packet_capture,
    }
    if sim_type not in handlers:
        raise ValueError(f"unsupported container simulation: {sim_type}")
    handlers[sim_type](target, params)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        emit("error", str(exc))
        sys.exit(1)
