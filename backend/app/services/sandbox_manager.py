"""
Sandbox Manager — manages Docker containers for the Attack Simulator.

Each simulation run:
1. Creates an isolated Docker bridge network (no internet egress)
2. Starts target-app container (vulnerable Flask app)
3. Starts attacker container running the attack scripts
4. Streams events via asyncio queue → WebSocket
5. Tears everything down after completion

Requires Docker Desktop running on the host.
"""
import asyncio
import logging
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.simulation import AttackSimulation, SimulationEvent
from app.core.config import settings

logger = logging.getLogger(__name__)

# Event queues per simulation ID
_event_queues: dict[str, asyncio.Queue] = {}


def get_event_queue(sim_id: str) -> asyncio.Queue:
    if sim_id not in _event_queues:
        _event_queues[sim_id] = asyncio.Queue()
    return _event_queues[sim_id]


def cleanup_event_queue(sim_id: str):
    _event_queues.pop(sim_id, None)


async def _check_docker_available() -> bool:
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return True
    except Exception as e:
        logger.warning(f"Docker not available: {e}")
        return False


async def run_simulation(
    db: AsyncSession,
    simulation: AttackSimulation,
    redis_client,
) -> None:
    """
    Main simulation runner. Called as an asyncio background task.
    Updates simulation status in DB and streams events.
    """
    sim_id = str(simulation.id)
    queue = get_event_queue(sim_id)

    # Update status to running
    simulation.status = "running"
    simulation.started_at = datetime.now(timezone.utc)
    await db.commit()

    async def emit(event_type: str, payload: str, severity: str = "info", details: dict = None):
        """Store event in DB and push to WebSocket queue."""
        event = SimulationEvent(
            simulation_id=simulation.id,
            event_type=event_type,
            severity=severity,
            source_ip=None,
            target=simulation.target_url,
            payload=payload,
            details=details or {},
            timestamp=datetime.now(timezone.utc),
        )
        db.add(event)
        await db.commit()
        await queue.put({
            "type": event_type,
            "payload": payload,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {},
        })

    docker_available = await _check_docker_available()

    try:
        if docker_available:
            await _run_with_docker(simulation, queue, emit, db, redis_client)
        else:
            raise RuntimeError(
                "Docker is required for simulations so attacks remain inside the isolated sandbox"
            )

        threat = await _record_simulation_detection(db, simulation)
        if threat:
            await emit(
                "detection_recorded",
                f"Sandbox detection recorded: {threat.title}",
                severity=threat.severity,
                details={"threat_id": str(threat.id), "type": threat.threat_type},
            )

        simulation.status = "completed"
        simulation.ended_at = datetime.now(timezone.utc)
        await db.commit()

    except Exception as e:
        logger.error(f"Simulation {sim_id} failed: {e}", exc_info=True)
        simulation.status = "failed"
        simulation.error_message = str(e)
        simulation.ended_at = datetime.now(timezone.utc)
        await db.commit()

        await emit("error", f"Simulation failed: {e}", severity="critical")
    finally:
        await queue.put(None)  # Signal end
        cleanup_event_queue(sim_id)


async def _record_simulation_detection(db, simulation):
    """Create one labelled threat and alert for every completed sandbox exercise."""
    from sqlalchemy import select

    from app.db.models.threat import Threat
    from app.services.threat_detection import record_simulation_attack

    existing = await db.execute(
        select(Threat.id).where(
            Threat.simulation_id == simulation.id,
            Threat.user_id == simulation.user_id,
        ).limit(1)
    )
    if existing.scalar_one_or_none() is not None:
        return None

    profiles = {
        "brute_force": ("brute_force_attempt", "high", "Sandbox brute-force attempt detected", "The sandbox replay generated repeated failed sign-in attempts. In production, this pattern should be rate-limited and investigated."),
        "sqli": ("sql_injection_attempt", "high", "Sandbox SQL injection attempt detected", "The sandbox replay sent SQL injection payloads to the isolated target. Review parameterized queries and input validation."),
        "xss": ("cross_site_scripting_attempt", "medium", "Sandbox cross-site scripting attempt detected", "The sandbox replay submitted browser script payloads to the isolated target. Review output encoding and Content Security Policy."),
        "port_scan": ("network_reconnaissance", "medium", "Sandbox port scan detected", "The sandbox replay performed network reconnaissance against the isolated target. Review firewall rules and exposed services."),
        "vuln_scan": ("vulnerability_probe", "medium", "Sandbox vulnerability scan detected", "The sandbox replay checked the isolated target for missing security controls. Review the recorded findings and hardening guidance."),
        "phishing": ("phishing_attempt", "high", "Sandbox phishing attempt detected", "The sandbox replay evaluated suspicious links to demonstrate phishing detection and response."),
        "packet_capture": ("network_packet_capture", "medium", "Sandbox packet capture detected", "The sandbox replay captured network traffic in the isolated environment. Review observed traffic patterns and segmentation controls."),
        "social_engineering": ("social_engineering_attempt", "medium", "Sandbox social engineering scenario detected", "The sandbox replay created a social engineering scenario to test awareness and reporting procedures."),
    }
    threat_type, severity, title, description = profiles.get(
        simulation.sim_type,
        ("sandbox_attack", "medium", "Sandbox attack detected", "A sandbox attack exercise completed."),
    )
    params = simulation.params or {}
    return await record_simulation_attack(
        db,
        user_id=simulation.user_id,
        simulation_id=simulation.id,
        threat_type=threat_type,
        severity=severity,
        title=title,
        description=description,
        source_ip=params.get("attacker_ip"),
        details={
            "simulation_type": simulation.sim_type,
            "target": simulation.target_url,
            "status": simulation.status,
            "event_count": len((simulation.raw_output or {}).get("events", [])),
        },
    )


async def _run_with_docker(simulation, queue, emit, db, redis_client):
    """Run simulation using real Docker containers."""
    import docker
    client = docker.from_env()
    sim_id = str(simulation.id)
    sim_type = simulation.sim_type

    network_name = f"shieldsphere-sim-{sim_id[:8]}"
    target_name = f"ss-target-{sim_id[:8]}"

    network = None
    target_container = None

    try:
        # Create isolated network
        network = client.networks.create(
            network_name,
            driver="bridge",
            internal=not settings.SANDBOX_NETWORK_INTERNET_EGRESS,
            options={"com.docker.network.bridge.name": f"sim_{sim_id[:8]}"},
        )
        simulation.network_id = network.id
        await db.commit()

        await emit("network_created", f"Isolated sandbox network created: {network_name}", severity="info")

        # Pull and start target app
        await emit("starting_target", "Starting vulnerable target application...", severity="info")
        try:
            target_container = client.containers.run(
                "shieldsphere-target:latest",
                name=target_name,
                network=network_name,
                detach=True,
                remove=False,
                environment={"SIM_ID": sim_id},
                ports={},  # No external port exposure
            )
            simulation.target_container_id = target_container.id
            await db.commit()
        except docker.errors.ImageNotFound:
            await emit("warning", "Target image not built yet. Building...", severity="warning")
            await _build_target_image(client)
            target_container = client.containers.run(
                "shieldsphere-target:latest",
                name=target_name,
                network=network_name,
                detach=True,
                remove=False,
                environment={"SIM_ID": sim_id},
            )

        # Wait for target to be ready
        await asyncio.sleep(2)
        target_ip = client.networks.get(network_name).attrs["Containers"].get(
            target_container.id, {}
        ).get("IPv4Address", "").split("/")[0] or "172.20.0.2"

        await emit("target_ready", f"Target app running at {target_ip}:5000", severity="info")

        # Run network probes inside the isolated attacker container.
        if sim_type in {
            "brute_force", "sqli", "xss", "port_scan", "packet_capture", "vuln_scan",
        }:
            await _run_attacker_container(
                client, network_name, target_name, simulation, emit, db, redis_client
            )
        elif sim_type == "phishing":
            await _simulate_phishing_local(emit, db, simulation)
        elif sim_type == "social_engineering":
            await _simulate_social_engineering_local(emit, db, simulation)
        else:
            raise ValueError(f"Unsupported simulation type: {sim_type}")

    finally:
        # Tear down containers and network
        await emit("cleanup", "Tearing down sandbox environment...", severity="info")
        if target_container:
            try:
                target_container.stop(timeout=5)
                target_container.remove()
            except Exception:
                pass
        if network:
            try:
                network.remove()
            except Exception:
                pass


async def _run_without_docker(simulation, queue, emit, db, redis_client):
    """
    Run simulation without Docker (for environments where Docker is not available).
    Uses httpx to hit a locally started Flask target or runs script-level checks.
    """
    sim_type = simulation.sim_type
    sim_id = str(simulation.id)

    await emit("info", f"Running {sim_type} simulation (no-Docker mode)", severity="info")

    # Import the threat detection service to register real events
    import redis.asyncio as aioredis
    from app.services import threat_detection

    if sim_type == "brute_force":
        await _simulate_brute_force_local(emit, db, simulation, redis_client)
    elif sim_type == "sqli":
        await _simulate_sqli_local(emit, db, simulation)
    elif sim_type == "xss":
        await _simulate_xss_local(emit, db, simulation)
    elif sim_type == "port_scan":
        await _simulate_port_scan_local(emit, db, simulation)
    elif sim_type == "vuln_scan":
        await _simulate_vuln_scan_local(emit, db, simulation)
    elif sim_type == "phishing":
        await _simulate_phishing_local(emit, db, simulation)
    elif sim_type == "packet_capture":
        await _simulate_packet_capture_local(emit, db, simulation)
    elif sim_type == "social_engineering":
        await _simulate_social_engineering_local(emit, db, simulation)
    else:
        await emit("error", f"Unknown simulation type: {sim_type}", severity="high")


async def _simulate_brute_force_local(emit, db, simulation, redis_client):
    """Simulate brute force by making rapid failed login attempts against the internal API."""
    import httpx
    from app.services.threat_detection import check_brute_force

    sim_id = str(simulation.id)
    params = simulation.params or {}
    target_ip = params.get("target_ip")
    target_url = params.get("target_url") or simulation.target_url
    attacker_ip = params.get("attacker_ip")
    attempts = params.get("attempts")
    if not target_ip or not attacker_ip or not isinstance(attempts, int) or attempts < 1:
        raise ValueError("brute_force requires params.target_ip, params.attacker_ip and positive params.attempts")

    await emit("start", f"Beginning brute force simulation: {attempts} attempts", severity="warning")

    # Create fake login history entries in DB to trigger real detection
    from app.db.models.login_history import LoginHistory
    from app.services.geoip_service import lookup_ip

    geo = lookup_ip(attacker_ip)

    for i in range(attempts):
        response_status = None
        if target_url:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    f"{target_url.rstrip('/')}/login-secure",
                    data={"username": params.get("username", "invalid-user"), "password": uuid.uuid4().hex},
                )
                response_status = response.status_code
        # Create real login_history row (failed login)
        lh = LoginHistory(
            user_id=simulation.user_id,
            ip_address=attacker_ip,
            user_agent="Mozilla/5.0 (compatible; AttackerBot/1.0)",
            device_id=None,
            success=False,
            failure_reason="invalid_password",
            country=geo.country,
            country_code=geo.country_code,
            city=geo.city,
            latitude=geo.latitude,
            longitude=geo.longitude,
            asn=geo.asn,
            isp=geo.isp,
            is_simulation=True,
            simulation_id=simulation.id,
        )
        db.add(lh)
        await db.flush()

        await emit(
            "login_attempt",
            f"[Attempt {i+1}/{attempts}] Failed login from {attacker_ip} — invalid password",
            severity="warning",
            details={"attempt": i + 1, "ip": attacker_ip, "success": False, "status_code": response_status},
        )

        # Run brute force detector on every attempt
        threat = await check_brute_force(
            db=db,
            redis_client=redis_client,
            user_id=simulation.user_id,
            ip=attacker_ip,
            login_event_id=lh.id,
            simulation_id=simulation.id,
            is_simulation=True,
        )
        if threat:
            await emit(
                "threat_triggered",
                f"🚨 THREAT DETECTED: Brute force from {attacker_ip} — {threat.severity.upper()} severity",
                severity="critical",
                details={"threat_id": str(threat.id), "type": threat.threat_type},
            )

        await asyncio.sleep(0.3)

    await db.commit()
    await emit("complete", "Brute force simulation complete", severity="info")


async def _simulate_sqli_local(emit, db, simulation):
    """Simulate SQL injection attacks against target endpoints."""
    import httpx

    params = simulation.params or {}
    target = params.get("target_url")
    payloads = params.get("payloads")
    if not target or not isinstance(payloads, list) or not payloads:
        raise ValueError("sqli requires params.target_url and non-empty params.payloads")
    sqli_payloads = [(str(item), f"Payload {index + 1}") for index, item in enumerate(payloads)]

    await emit("start", f"Beginning SQL injection simulation against {target}", severity="warning")

    async with httpx.AsyncClient(timeout=5.0) as client:
        for payload, desc in sqli_payloads:
            try:
                # Try against a vulnerable endpoint
                response = await client.post(
                    f"{target}/login",
                    data={"username": payload, "password": "anything"},
                    follow_redirects=False,
                )
                vulnerable = response.status_code in (200, 302) and "admin" in response.text.lower()
                status = "VULNERABLE ⚠️" if vulnerable else "Blocked ✓"
                await emit(
                    "sqli_payload",
                    f"[{status}] {desc}: {payload[:40]}",
                    severity="high" if vulnerable else "info",
                    details={"payload": payload, "status_code": response.status_code, "vulnerable": vulnerable},
                )
            except httpx.ConnectError:
                await emit(
                    "sqli_payload",
                    f"[Target offline] {desc}: {payload[:40]} — target not responding, recording attempt",
                    severity="medium",
                    details={"payload": payload, "error": "connection_refused"},
                )
            except Exception as e:
                await emit("sqli_payload", f"Payload sent: {desc} — {str(e)[:50]}", severity="info")
            await asyncio.sleep(0.5)

    await db.commit()
    await emit("complete", "SQL injection simulation complete", severity="info")


async def _simulate_xss_local(emit, db, simulation):
    """Simulate XSS payload injection."""
    import httpx

    params = simulation.params or {}
    target = params.get("target_url")
    payloads = params.get("payloads")
    if not target or not isinstance(payloads, list) or not payloads:
        raise ValueError("xss requires params.target_url and non-empty params.payloads")
    xss_payloads = [(str(item), f"Payload {index + 1}") for index, item in enumerate(payloads)]
    await emit("start", f"Beginning XSS simulation against {target}", severity="warning")

    async with httpx.AsyncClient(timeout=5.0) as client:
        for payload, desc in xss_payloads:
            try:
                response = await client.get(
                    f"{target}/search",
                    params={"q": payload},
                )
                # Check if payload is reflected unescaped
                reflected = payload in response.text
                status = "REFLECTED (VULNERABLE) ⚠️" if reflected else "Escaped/Blocked ✓"
                await emit(
                    "xss_payload",
                    f"[{status}] {desc}: {payload[:50]}",
                    severity="high" if reflected else "info",
                    details={"payload": payload, "reflected": reflected, "status_code": response.status_code},
                )
            except httpx.ConnectError:
                await emit(
                    "xss_payload",
                    f"[Target offline] {desc} — recording payload attempt",
                    severity="medium",
                    details={"payload": payload, "error": "connection_refused"},
                )
            await asyncio.sleep(0.4)

    await db.commit()
    await emit("complete", "XSS simulation complete", severity="info")


async def _simulate_port_scan_local(emit, db, simulation):
    """Run real nmap port scan against a target."""
    import nmap

    target = (simulation.params or {}).get("target")
    if not target:
        raise ValueError("port_scan requires params.target")
    await emit("start", f"Starting port scan against {target}", severity="warning")

    nm = nmap.PortScanner()
    try:
        await emit("scanning", f"Running nmap scan on {target}...", severity="info")
        # Run in executor since nmap is blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: nm.scan(target, "1-1024", "-sV --open -T4")
        )

        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]["state"]
                    service = nm[host][proto][port].get("name", "unknown")
                    version = nm[host][proto][port].get("version", "")
                    if state == "open":
                        open_ports.append({"port": port, "service": service, "version": version})
                        await emit(
                            "port_open",
                            f"Port {port}/{proto} OPEN — {service} {version}",
                            severity="medium",
                            details={"port": port, "service": service, "version": version, "protocol": proto},
                        )

        # Get AI advice on the findings
        from app.services.llm_service import generate_port_scan_advice
        if open_ports:
            advice = await generate_port_scan_advice(open_ports)
            simulation.raw_output = {"open_ports": open_ports, "ai_advice": advice}
            await db.commit()
            await emit("ai_analysis", f"AI Hardening Advice:\n{advice[:500]}", severity="info")

    except Exception as e:
        await emit("error", f"Port scan error: {e}", severity="high")

    await emit("complete", "Port scan simulation complete", severity="info")


async def _simulate_vuln_scan_local(emit, db, simulation):
    """Run real vulnerability checks against a URL."""
    import httpx

    target = (simulation.params or {}).get("target_url")
    if not target:
        raise ValueError("vuln_scan requires params.target_url")
    await emit("start", f"Starting vulnerability scan of {target}", severity="info")

    findings = {}
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        try:
            response = await client.get(target)
            headers = response.headers

            # Check security headers
            checks = [
                ("HTTPS", target.startswith("https://"), "has_https"),
                ("HSTS", "strict-transport-security" in headers, "has_hsts"),
                ("CSP", "content-security-policy" in headers, "has_csp"),
                ("X-Frame-Options", "x-frame-options" in headers, "has_x_frame"),
                ("X-Content-Type-Options", "x-content-type-options" in headers, "has_xcto"),
                ("X-XSS-Protection", "x-xss-protection" in headers, "has_xss_protection"),
                ("Referrer-Policy", "referrer-policy" in headers, "has_referrer_policy"),
            ]

            for check_name, present, key in checks:
                findings[key] = present
                status = "✓ Present" if present else "✗ Missing"
                severity = "info" if present else "medium"
                await emit(
                    "header_check",
                    f"Security Header [{check_name}]: {status}",
                    severity=severity,
                    details={"header": check_name, "present": present},
                )
                await asyncio.sleep(0.2)

            # Cookie analysis
            if response.cookies:
                for cookie_name, cookie_val in response.cookies.items():
                    await emit(
                        "cookie_check",
                        f"Cookie '{cookie_name}' found — check Secure/HttpOnly flags",
                        severity="medium",
                        details={"cookie": cookie_name},
                    )

        except Exception as e:
            await emit("error", f"Scan error: {e}", severity="high")
            return

    # Risk score
    missing = sum(1 for _, present, _ in checks if not present) if 'checks' in dir() else 0
    risk_score = min(100, missing * 15)
    findings["risk_score"] = risk_score

    simulation.raw_output = {"findings": findings, "target": target}
    await db.commit()

    await emit("result", f"Vulnerability scan complete. Risk score: {risk_score}/100", severity="info")

    # AI advice
    from app.services.llm_service import get_groq_client
    try:
        from app.services.llm_service import generate_port_scan_advice
        # Reuse port scan advice format for web vuln findings
        advice = await generate_port_scan_advice(
            [{"finding": k, "present": v} for k, v in findings.items()],
            os_info=f"Web Application at {target}"
        )
        await emit("ai_analysis", f"AI Security Advice:\n{advice[:500]}", severity="info")
    except Exception:
        pass

    await emit("complete", "Vulnerability scan complete", severity="info")


async def _simulate_phishing_local(emit, db, simulation):
    """Simulate phishing detection."""
    import httpx

    params = simulation.params or {}
    supplied = params.get("urls", [])
    if not isinstance(supplied, list) or not supplied:
        raise ValueError("phishing simulation requires params.urls with at least one URL")
    test_urls = []
    for item in supplied:
        if isinstance(item, str):
            test_urls.append((item, "user supplied URL"))
        elif isinstance(item, dict) and item.get("url"):
            test_urls.append((item["url"], str(item.get("description", "user supplied URL"))))
    if not test_urls:
        raise ValueError("params.urls must contain URL strings or objects with a url field")

    await emit("start", "Beginning phishing URL analysis simulation", severity="warning")

    legitimate_domains = params.get("legitimate_domains", [])
    if not isinstance(legitimate_domains, list) or not legitimate_domains:
        raise ValueError("phishing simulation requires params.legitimate_domains")

    challenge_items = []
    for index, (url, description) in enumerate(test_urls, start=1):
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower()

        # Real similarity check
        min_dist = min(_levenshtein_distance(domain, legit.lower()) for legit in legitimate_domains)
        is_suspicious = min_dist <= 3 and min_dist > 0
        challenge_items.append({
            "id": f"url_{index}",
            "url": url,
            "description": description,
            "domain": domain,
            "expected": "phishing" if is_suspicious else "legitimate",
            "levenshtein_distance": min_dist,
        })

        # Actual HTTP check
        try:
            from app.services.outbound_http import safe_public_get
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                resp = await safe_public_get(url, client=client)
                reachable = True
                final_url = str(resp.url)
        except Exception:
            reachable = False
            final_url = url

        status = "PHISHING DETECTED ⚠️" if is_suspicious else "Legitimate ✓"
        await emit(
            "phishing_prompt",
            f"Classify {description}: {domain}",
            severity="warning",
            details={
                "challenge_id": f"url_{index}", "url": url, "domain": domain,
                "reachable": reachable,
            },
        )
        await asyncio.sleep(0.5)

    simulation.raw_output = {"challenge_items": challenge_items, "responses": []}
    await db.commit()
    await emit("complete", "Phishing simulation complete", severity="info")


def _levenshtein_distance(left: str, right: str) -> int:
    """Compute edit distance without an optional third-party package."""
    if left == right:
        return 0
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            current.append(min(
                current[-1] + 1,
                previous[right_index] + 1,
                previous[right_index - 1] + (left_char != right_char),
            ))
        previous = current
    return previous[-1]


async def _simulate_packet_capture_local(emit, db, simulation):
    """Capture real packets from a requested interface using Scapy."""
    from scapy.all import sniff, IP, TCP, UDP

    params = simulation.params or {}
    interface = params.get("interface")
    duration = params.get("duration_seconds")
    capture_filter = params.get("filter")
    if not interface or not isinstance(duration, (int, float)) or not 1 <= duration <= 60:
        raise ValueError("packet_capture requires params.interface and duration_seconds between 1 and 60")

    await emit("start", f"Capturing live traffic on interface {interface} for {duration}s", severity="info")
    loop = asyncio.get_running_loop()
    packets = await loop.run_in_executor(
        None,
        lambda: sniff(iface=interface, timeout=float(duration), filter=capture_filter, store=True),
    )
    packet_types = []
    for packet in packets:
        record = {
            "type": packet.lastlayer().name,
            "src": packet[IP].src if IP in packet else None,
            "dst": packet[IP].dst if IP in packet else None,
            "port": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None,
            "flags": str(packet[TCP].flags) if TCP in packet else None,
            "info": packet.summary(),
            "length": len(packet),
        }
        packet_types.append(record)

    simulation.raw_output = {"interface": interface, "packet_count": len(packet_types), "packets": packet_types}
    await db.commit()

    for pkt in packet_types:
        await emit(
            "packet_captured",
            f"[{pkt['type']}] {pkt['src']} → {pkt['dst']}:{pkt['port']} | {pkt['info']}",
            severity="info",
            details=pkt,
        )
        await asyncio.sleep(0.4)

    # Get AI to explain the packets
    from app.services.llm_service import explain_packets
    if packet_types:
        explanation = await explain_packets([f"{p['type']}: {p['info']}" for p in packet_types])
        await emit("ai_analysis", f"Packet Analysis:\n{explanation[:500]}", severity="info")
    else:
        await emit("result", "Capture completed with no packets observed", severity="info")

    await db.commit()
    await emit("complete", "Packet capture analysis complete", severity="info")


async def _simulate_social_engineering_local(emit, db, simulation):
    """Generate AI-powered social engineering scenario."""
    from app.services.llm_service import generate_social_engineering_scenario

    await emit("start", "Generating social engineering awareness scenario...", severity="info")

    role = simulation.params.get("user_role", "employee") if simulation.params else "employee"
    scenario = await generate_social_engineering_scenario(role)

    if scenario:
        simulation.raw_output = {"scenario": scenario, "responses": []}
        await db.commit()
        await emit(
            "scenario_generated",
            f"Scenario: {scenario.get('title', 'Social Engineering Attack')}",
            severity="warning",
            details=scenario,
        )
        await emit(
            "attacker_message",
            f"Attack Message: {scenario.get('attacker_message', '')[:200]}",
            severity="high",
        )
        await emit(
            "red_flags",
            f"Red Flags: {', '.join(scenario.get('red_flags', []))}",
            severity="info",
        )

    await emit("complete", "Social engineering scenario ready", severity="info")


async def _build_target_image(docker_client):
    """Build the target app Docker image."""
    import os
    target_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sandbox", "target_app")
    docker_client.images.build(path=target_dir, tag="shieldsphere-target:latest")


async def _build_attacker_image(docker_client):
    """Build the isolated attacker image."""
    import os
    attacker_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sandbox", "attacker_scripts")
    docker_client.images.build(path=attacker_dir, tag="shieldsphere-attacker:latest")


async def _record_brute_force_event(db, simulation, redis_client, emit):
    """Persist a real sandbox login failure and run production detection on it."""
    from ipaddress import ip_address

    from app.db.models.login_history import LoginHistory
    from app.services.geoip_service import lookup_ip
    from app.services.threat_detection import check_brute_force

    attacker_ip = (simulation.params or {}).get("attacker_ip")
    if not attacker_ip:
        raise ValueError("brute_force requires params.attacker_ip")
    try:
        attacker_ip = str(ip_address(attacker_ip))
    except ValueError as exc:
        raise ValueError("brute_force params.attacker_ip must be a valid IP address") from exc

    geo = lookup_ip(attacker_ip)
    login_event = LoginHistory(
        user_id=simulation.user_id,
        ip_address=attacker_ip,
        user_agent="ShieldSphere isolated attacker container",
        success=False,
        failure_reason="invalid_password",
        country=geo.country,
        country_code=geo.country_code,
        city=geo.city,
        latitude=geo.latitude,
        longitude=geo.longitude,
        asn=geo.asn,
        isp=geo.isp,
        is_simulation=True,
        simulation_id=simulation.id,
    )
    db.add(login_event)
    await db.flush()
    threat = await check_brute_force(
        db=db,
        redis_client=redis_client,
        user_id=simulation.user_id,
        ip=attacker_ip,
        login_event_id=login_event.id,
        simulation_id=simulation.id,
        is_simulation=True,
    )
    if threat:
        await emit(
            "threat_triggered",
            f"Brute-force threat detected from {attacker_ip}",
            severity="critical",
            details={"threat_id": str(threat.id), "type": threat.threat_type},
        )


async def _run_attacker_container(client, network_name, target_name, simulation, emit, db, redis_client):
    """Run a one-shot attacker container and persist its JSON-lines output."""
    import docker

    try:
        client.images.get("shieldsphere-attacker:latest")
    except docker.errors.ImageNotFound:
        await emit("warning", "Building isolated attacker image", severity="warning")
        await _build_attacker_image(client)

    params = dict(simulation.params or {})
    params.pop("target_url", None)
    container = client.containers.run(
        "shieldsphere-attacker:latest",
        network=network_name,
        detach=True,
        remove=False,
        user="root" if simulation.sim_type == "packet_capture" else None,
        cap_add=["NET_RAW", "NET_ADMIN"] if simulation.sim_type == "packet_capture" else None,
        security_opt=["no-new-privileges:true"],
        environment={
            "SIM_TYPE": simulation.sim_type,
            "TARGET_URL": f"http://{target_name}:5000",
            "SIM_PARAMS": json.dumps(params),
        },
    )
    simulation.attacker_container_id = container.id
    await db.commit()
    try:
        result = container.wait(timeout=120)
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        parsed = []
        for line in logs.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = {"type": "attacker_log", "payload": line, "details": {}}
            parsed.append(event)
            if simulation.sim_type == "brute_force" and event.get("type") == "login_attempt":
                await _record_brute_force_event(db, simulation, redis_client, emit)
            await emit(event.get("type", "attacker_log"), event.get("payload", line), details=event.get("details", {}))
        simulation.raw_output = {"exit_code": result.get("StatusCode"), "events": parsed}
        await db.commit()
        if result.get("StatusCode") != 0:
            raise RuntimeError(f"attacker container exited with code {result.get('StatusCode')}")
    finally:
        container.remove(force=True)


async def _execute_attack(sim_type, target_ip, emit, db, simulation, redis_client, sim_id):
    """Execute the appropriate attack type against the Docker target."""
    if sim_type == "brute_force":
        await _simulate_brute_force_local(emit, db, simulation, redis_client)
    elif sim_type == "sqli":
        simulation.params = simulation.params or {}
        simulation.params["target_url"] = f"http://{target_ip}:5000"
        await _simulate_sqli_local(emit, db, simulation)
    elif sim_type == "xss":
        simulation.params = simulation.params or {}
        simulation.params["target_url"] = f"http://{target_ip}:5000"
        await _simulate_xss_local(emit, db, simulation)
    elif sim_type == "port_scan":
        simulation.params = simulation.params or {}
        simulation.params["target"] = target_ip
        await _simulate_port_scan_local(emit, db, simulation)
    else:
        await _run_without_docker(simulation, None, emit, db, redis_client)
