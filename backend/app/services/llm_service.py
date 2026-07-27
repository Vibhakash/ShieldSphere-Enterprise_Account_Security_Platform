"""
Groq LLM service.
Provides structured prompt templates that inject real DB data before calling Groq.
"""
import logging
import uuid
from typing import Optional, AsyncGenerator
from groq import AsyncGroq

from app.core.config import settings

logger = logging.getLogger(__name__)

_client: Optional[AsyncGroq] = None


def get_groq_client() -> AsyncGroq:
    global _client
    if _client is None:
        _client = AsyncGroq(api_key=settings.require_api_key("groq"))
    return _client


GROQ_MODEL = "llama-3.3-70b-versatile"


def _local_copilot_answer(user_message: str, context: dict) -> str:
    """Build an account-specific answer when the hosted LLM is unavailable."""
    question = user_message.strip() or "How can I improve my account security?"
    lowered = question.lower()
    analytics = context.get("analytics_7d", {})
    destinations = [
        ("threat", "Threats", "Open **Threats** from the sidebar. Use the Simulator-generated filter to review sandbox detections."),
        ("alert", "Alerts", "Open **Alerts** from the sidebar to review, mark read, or block a real source IP."),
        ("login", "Dashboard", "Open **Dashboard** and use **Recent login history** for successful and failed sign-ins."),
        ("session", "Active sessions", "Open **Active sessions** from the sidebar to review locations and revoke an unfamiliar session."),
        ("device", "Recognized devices", "Open **Recognized devices** from the sidebar to review trusted devices and their locations."),
        ("password", "Assessments", "Open **Assessments** and choose **Password** or **Breach check**."),
        ("vulnerab", "Assessments", "Open **Assessments** and choose **Website vulnerability scan**. Scan results explain each protection and include a scrollable finding list."),
        ("scan", "Assessments", "Open **Assessments** from the sidebar, then choose the relevant scan tab."),
        ("block", "IP blocklist", "Open **IP blocklist** from the sidebar to add, review, or remove account IP blocks."),
        ("passkey", "Settings", "Open **Settings**, then use the **Passkeys** section to register or manage a passkey."),
        ("simulat", "Attack simulator", "Open **Attack simulator** from the sidebar, choose an exercise, paste its sandbox parameters, and start the replay."),
        ("report", "Compliance & reports", "Open **Compliance & reports** to generate an executive report, download its PDF, export GDPR data, or manage audit records."),
        ("audit", "Compliance & reports", "Open **Compliance & reports** and scroll to **Audit log**. Each of your records has a delete action."),
        ("behavio", "Behaviour analytics", "Open **Behaviour analytics** from the sidebar. A baseline is now available after two successful login samples."),
    ]
    navigation = next((item for item in destinations if item[0] in lowered), None)
    score = context.get("security_score", "not yet calculated")
    threats = int(context.get("unresolved_threats", 0) or 0)
    snapshot = (
        f"**Security score:** {score}/100\n"
        f"**Real login attempts (7 days):** {analytics.get('real_login_attempts', 0)} ({analytics.get('failed_login_attempts', 0)} failed)\n"
        f"**Real threats (7 days):** {analytics.get('real_threats', 0)}; **open:** {threats}\n"
        f"**Unread alerts:** {analytics.get('unread_alerts', 0)}\n"
        f"**Sandbox exercises (7 days):** {analytics.get('sandbox_exercises', 0)}; **sandbox detections:** {analytics.get('sandbox_threats', 0)}"
    )
    if navigation:
        answer = f"## Where to find it\n\n{navigation[2]}\n\n## Current account snapshot\n\n{snapshot}"
    else:
        priorities = []
        if context.get("password_breached"):
            priorities.append("Change the account password immediately and do not reuse the old password.")
        if not context.get("totp_enabled"):
            priorities.append("Enable two-factor authentication or add a passkey in Settings.")
        if threats:
            priorities.append(f"Review and resolve the {threats} unresolved real threat(s) in Threats.")
        priorities.append(f"Review the {context.get('active_sessions', 0)} active session(s) and revoke any you do not recognize.")
        answer = f"## Current account snapshot\n\n{snapshot}\n\n## Recommended next steps\n\n" + "\n".join(f"{index}. {item}" for index, item in enumerate(priorities[:4], 1))
    return f"## Your question\n\n{question}\n\n{answer}\n\nThe live AI provider is temporarily unavailable, so this answer was generated locally from your current ShieldSphere data."


def _local_executive_report(data: dict) -> str:
    score = data.get("security_score")
    score_text = f"{score}/100" if score is not None else "not yet calculated"
    threats = int(data.get("threat_count", 0) or 0)
    resolved = int(data.get("resolved_threats", 0) or 0)
    failed = int(data.get("failed_logins", 0) or 0)
    critical = int(data.get("critical_threats", 0) or 0)
    return (
        f"The account's current security score is {score_text}. During this reporting period, ShieldSphere recorded "
        f"{data.get('total_logins', 0)} login event(s), including {failed} failed attempt(s).\n\n"
        f"The platform detected {threats} threat(s); {resolved} have been resolved and {critical} were classified as critical. "
        f"It also completed {data.get('simulation_count', 0)} controlled attack simulation(s).\n\n"
        "Prioritize unresolved or critical threats, review unfamiliar sessions and devices, enable strong authentication, "
        "and continue regular vulnerability scans. This summary was generated locally because the external AI provider was unavailable."
    )


async def generate_threat_rca(threat_data: dict) -> str:
    """
    Generate root-cause analysis for a detected threat.
    threat_data is built from real DB fields: threat type, signals, IP, device, geo, etc.
    """
    prompt = f"""You are an enterprise security analyst AI. A threat has been detected in the ShieldSphere security platform. Analyze the following real security event and provide:

1. **Root Cause Analysis** — What actually happened and why this was flagged
2. **Attack Path Hypothesis** — The likely sequence of events/attacker steps
3. **Risk Assessment** — Who is at risk and what could happen if unaddressed
4. **Remediation Steps** — Specific, actionable steps to resolve this threat

Threat Data (real, from the security platform):
- Type: {threat_data.get('threat_type')}
- Severity: {threat_data.get('severity')}
- Source IP: {threat_data.get('source_ip', 'unknown')}
- Country: {threat_data.get('country', 'unknown')}
- Failed Attempts: {threat_data.get('failed_attempts', 'N/A')}
- Time Window: {threat_data.get('time_window', 'N/A')}
- Device: {threat_data.get('device_info', 'unknown')}
- Distance from last login: {threat_data.get('travel_distance_km', 'N/A')} km
- Time since last login: {threat_data.get('time_since_last_login', 'N/A')}
- User's typical login hours: {threat_data.get('typical_hours', 'N/A')}
- Current login hour: {threat_data.get('current_hour', 'N/A')}
- Breach status: {threat_data.get('breach_status', 'unknown')}
- Additional context: {threat_data.get('additional_context', 'none')}

Provide a clear, professional security analysis. Be specific and reference the actual data points above."""

    try:
        client = get_groq_client()
        chat = await client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are ShieldSphere's AI Security Analyst. Provide concise, actionable security analysis based on real threat data."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1000,
            temperature=0.3,
        )
        return chat.choices[0].message.content or "Analysis unavailable."
    except Exception as e:
        logger.error(f"Groq RCA generation failed: {e}")
        return (
            f"Root cause: ShieldSphere detected a {threat_data.get('severity', 'security')} "
            f"{threat_data.get('threat_type', 'threat')} event from "
            f"{threat_data.get('source_ip', 'an unknown source')}. Review the related login and device activity, "
            "contain the source if it is unfamiliar, reset exposed credentials, and resolve the threat after verification. "
            "This analysis was generated locally because the external AI provider was unavailable."
        )


async def copilot_chat(
    user_message: str,
    user_context: dict,
    chat_history: list,
) -> AsyncGenerator[str, None]:
    """
    Stream a response from the AI Security Copilot.
    user_context is built from real DB data: recent threats, alerts, score, etc.
    """
    system_prompt = f"""You are ShieldSphere's AI Security Copilot — an expert enterprise security assistant. You have access to this user's real security data and answer questions about their specific security posture.

Current User Security Context (real, live data):
- Security Score: {user_context.get('security_score', 'N/A')}/100
- 2FA Enabled: {user_context.get('totp_enabled', False)}
- Active Sessions: {user_context.get('active_sessions', 0)}
- Unresolved Threats: {user_context.get('unresolved_threats', 0)}
- Recent Threats (last 7 days): {user_context.get('recent_threats_summary', 'none')}
- Recent Alerts: {user_context.get('recent_alerts', 'none')}
- Password Breached: {user_context.get('password_breached', False)}
- Known Devices: {user_context.get('known_devices', 0)}
- Last Login: {user_context.get('last_login', 'unknown')}
- Recent Login Locations: {user_context.get('recent_locations', 'unknown')}
- Recent Website Vulnerability Scans: {user_context.get('vulnerability_scans', [])}
- Detailed Recent Threat Records: {user_context.get('recent_threat_records', [])}
- Detailed Recent Alert Records: {user_context.get('recent_alert_records', [])}
- Seven-day analytics: {user_context.get('analytics_7d', {})}

Application navigation guide:
- Dashboard: account score, real login history, activity chart, sandbox detection totals.
- Threats: detected threats; sandbox detections are labelled and can be filtered.
- Alerts: actionable notifications; only real source IPs can be blocked.
- Active sessions and Recognized devices: current sessions, trusted devices, and location maps.
- IP blocklist: manual and automatic IP blocks.
- Assessments: password, breach, URL/IP reputation, and website vulnerability scans.
- Behaviour analytics: login baseline and anomaly signals; baseline starts after two samples.
- Attack simulator: safe isolated attack exercises and replay timeline.
- Compliance & reports: executive reports, PDF download, GDPR Excel export, and audit log management.
- Settings: authentication, passkeys, notification integrations, and account settings.

Answer the user's actual question first, then give relevant next steps. If asked about threats, reference the actual threats above. If asked for recommendations, base them on the real security score and issues. The Security Score is for the user's account, not for a website, so never use it as evidence that a website is vulnerable. For website questions, use only Recent Website Vulnerability Scans; if there is no completed scan for that website, say that its vulnerability is not yet known and direct the user to Assessments > Vulnerability. Never make up data not in the context above.

Write for a non-technical user. Use short paragraphs, descriptive headings, and bullet or numbered lists with normal spaces between words. Explain technical terms briefly. Do not return raw JSON. Keep the structure clean and directly actionable."""

    messages = [{"role": "system", "content": system_prompt}]
    for msg in chat_history[-10:]:  # Last 10 messages for context
        messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": user_message})

    try:
        client = get_groq_client()
        stream = await client.chat.completions.create(
            model=GROQ_MODEL,
            messages=messages,
            max_tokens=800,
            temperature=0.5,
            stream=True,
        )
        async for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content
    except Exception as e:
        logger.error(f"Groq copilot error: {e}")
        yield _local_copilot_answer(user_message, user_context)


async def generate_simulation_summary(sim_data: dict) -> str:
    """Generate AI summary of an attack simulation run from real event data."""
    prompt = f"""You are a cybersecurity educator explaining an attack simulation to an enterprise security team. Summarize the following real sandbox simulation results:

Simulation Type: {sim_data.get('sim_type')}
Status: {sim_data.get('status')}
Events Captured: {sim_data.get('event_count', 0)} real events
Threats Triggered: {sim_data.get('threats_triggered', 0)}
Key Findings: {sim_data.get('key_findings', 'none')}
Sample Events: {sim_data.get('sample_events', [])}

Provide:
1. What the simulation demonstrated
2. What real threats were detected and why
3. Key security lessons from this specific simulation
4. Concrete hardening recommendations based on the actual findings

Be specific about the actual events captured, not generic advice."""

    try:
        client = get_groq_client()
        chat = await client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are a cybersecurity educator. Explain simulation results clearly to security teams."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=800,
            temperature=0.4,
        )
        return chat.choices[0].message.content or "Summary unavailable."
    except Exception as e:
        logger.error(f"Groq simulation summary failed: {e}")
        return (
            f"The {sim_data.get('sim_type', 'attack')} simulation finished with status "
            f"{sim_data.get('status', 'unknown')} and recorded {sim_data.get('event_count', 0)} event(s). "
            f"It triggered {sim_data.get('threats_triggered', 0)} threat(s). Review the replay timeline, confirm the "
            "matching defensive control, and repeat the exercise after hardening. This summary was generated locally."
        )


async def generate_executive_report(report_data: dict) -> str:
    """Generate an AI executive security report from real aggregated data."""
    prompt = f"""You are a CISO writing an executive security report for a company. Based on the following real security metrics and events, write a professional executive summary:

Reporting Period: {report_data.get('period_start')} to {report_data.get('period_end')}
Total Login Events: {report_data.get('total_logins', 0)}
Successful Logins: {report_data.get('successful_logins', 0)}
Failed Logins: {report_data.get('failed_logins', 0)}
Threats Detected: {report_data.get('threat_count', 0)}
Threats Resolved: {report_data.get('resolved_threats', 0)}
Critical Threats: {report_data.get('critical_threats', 0)}
Active Sessions: {report_data.get('active_sessions', 0)}
IPs Auto-blocked: {report_data.get('blocked_ips', 0)}
Security Score: {report_data.get('security_score', 'N/A')}/100
Simulations Run: {report_data.get('simulation_count', 0)}
Breach Checks: {report_data.get('breach_checks', 0)}
Top Threat Types: {report_data.get('top_threat_types', [])}
Geographic Risk Areas: {report_data.get('risk_countries', [])}

Write a 3-4 paragraph executive summary with:
1. Overall security posture assessment
2. Key incidents and their resolution status
3. Risk trends
4. Strategic recommendations for the next period"""

    try:
        client = get_groq_client()
        chat = await client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are a CISO providing executive security briefings. Write professionally and concisely."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=800,
            temperature=0.3,
        )
        return chat.choices[0].message.content or "Report unavailable."
    except Exception as e:
        logger.error(f"Groq executive report failed: {e}")
        return _local_executive_report(report_data)


async def generate_social_engineering_scenario(user_role: str = "employee") -> dict:
    """Generate a unique social engineering scenario per session."""
    prompt = f"""Create a realistic social engineering awareness training scenario for a {user_role}. 

Return ONLY valid JSON in this exact format:
{{
  "scenario_id": "unique_id",
  "title": "scenario title",
  "description": "detailed scenario description (2-3 sentences)",
  "attacker_message": "the exact message/email/call script the attacker uses",
  "red_flags": ["flag1", "flag2", "flag3"],
  "options": [
    {{"id": "A", "text": "response option A", "is_correct": false, "explanation": "why this is wrong"}},
    {{"id": "B", "text": "response option B", "is_correct": true, "explanation": "why this is correct"}},
    {{"id": "C", "text": "response option C", "is_correct": false, "explanation": "why this is wrong"}},
    {{"id": "D", "text": "response option D", "is_correct": false, "explanation": "why this is wrong"}}
  ],
  "attack_type": "phishing|vishing|pretexting|baiting|tailgating"
}}

Make the scenario realistic and varied each time. Return only the JSON, no markdown."""

    try:
        client = get_groq_client()
        chat = await client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are a security training scenario generator. Return only valid JSON."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=600,
            temperature=0.8,
        )
        import json
        content = chat.choices[0].message.content
        if not content:
            raise RuntimeError("Groq returned an empty scenario")
        scenario = json.loads(content)
        if not isinstance(scenario, dict) or not scenario.get("options"):
            raise RuntimeError("Groq returned an invalid scenario payload")
        return scenario
    except Exception as e:
        logger.error(f"Groq scenario generation failed: {e}")
        return {
            "scenario_id": str(uuid.uuid4()),
            "title": "Urgent account verification request",
            "description": f"A {user_role} receives an urgent message claiming that their account will be suspended unless they verify it immediately.",
            "attacker_message": "Security alert: verify your account using this link within 15 minutes to avoid suspension.",
            "red_flags": ["Artificial urgency", "Unverified link", "Request for sign-in credentials"],
            "options": [
                {"id": "A", "text": "Open the link and sign in", "is_correct": False, "explanation": "The link may capture your credentials."},
                {"id": "B", "text": "Report the message and verify through the official portal", "is_correct": True, "explanation": "This uses a trusted channel and alerts the security team."},
                {"id": "C", "text": "Forward it to coworkers", "is_correct": False, "explanation": "Forwarding increases exposure."},
                {"id": "D", "text": "Reply with your password", "is_correct": False, "explanation": "Passwords must never be shared."},
            ],
            "attack_type": "phishing",
        }


async def generate_port_scan_advice(open_ports: list, os_info: str = "unknown") -> str:
    """Generate hardening advice from real nmap scan results."""
    prompt = f"""A network port scan revealed the following open ports/services on a target system. Provide specific security hardening advice:

OS/System: {os_info}
Open Ports Found: {open_ports}

For each open port/service, explain:
1. What the service is
2. Whether it should be open (and why or why not)
3. Specific hardening steps
4. Any known CVEs for this service/version if applicable

Be specific and reference the actual ports found."""

    try:
        client = get_groq_client()
        chat = await client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are a network security expert providing port hardening advice."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=800,
            temperature=0.3,
        )
        return chat.choices[0].message.content or "Advice unavailable."
    except Exception as e:
        logger.error(f"Groq port scan advice failed: {e}")
        return (
            f"Review the {len(open_ports)} observed service or header finding(s) for {os_info}. "
            "Close services that are not required, restrict access with firewall rules, enable the missing security controls, "
            "and patch exposed software. This advice was generated locally because the external AI provider was unavailable."
        )


async def explain_packets(packet_summary: list) -> str:
    """Explain real captured network packets in plain language."""
    prompt = f"""Explain the following real network packets captured during a security simulation in plain language for a security team:

Captured Packets:
{packet_summary}

Explain:
1. What each type of packet represents
2. What the traffic pattern reveals about the attack
3. What this would look like in a real network intrusion
4. How to detect and block this pattern in production"""

    try:
        client = get_groq_client()
        chat = await client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are a network forensics expert explaining captured traffic to security analysts."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=600,
            temperature=0.3,
        )
        return chat.choices[0].message.content or "Explanation unavailable."
    except Exception as e:
        logger.error(f"Groq packet explanation failed: {e}")
        return (
            f"The capture contains {len(packet_summary)} packet summary item(s). Compare source and destination addresses, "
            "ports, and repeated connection patterns to identify scanning or brute-force behavior. Apply rate limits, network "
            "segmentation, and alerting for the same pattern in production. This explanation was generated locally."
        )
