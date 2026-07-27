import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Shield,
  Radar,
  Bot,
  Fingerprint,
  Eye,
  Terminal,
  ShieldCheck,
  Zap,
  Lock,
  Activity,
  Bug,
  LayoutDashboard,
  MapPin,
  Ban,
  Wifi,
  Bell,
} from "lucide-react";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useAuth } from "@/lib/auth";
import { useTheme } from "@/lib/theme";

export const Route = createFileRoute("/")({
  component: BrandingPage,
});

/* ── Marquee items (all real features) ─────────────────────────── */
const MARQUEE_ITEMS = [
  { icon: MapPin, label: "Login Map" },
  { icon: Ban, label: "IP Blocklist" },
  { icon: Wifi, label: "Packet Capture" },
  { icon: Lock, label: "Auth & 2FA" },
  { icon: Bell, label: "Live Alerts" },
  { icon: Radar, label: "Threat Detection" },
  { icon: Bot, label: "AI Copilot" },
  { icon: Eye, label: "Behaviour Analytics" },
  { icon: Terminal, label: "Attack Simulator" },
  { icon: Bug, label: "Security Assessments" },
  { icon: ShieldCheck, label: "Compliance Reports" },
  { icon: Fingerprint, label: "Device Control" },
];

/* ── Feature cards ─────────────────────────────────────────────── */
const FEATURES = [
  {
    icon: Activity,
    color: "#38bdf8",
    title: "Live Security Dashboard",
    desc: "Real-time login stats, active sessions, unresolved threats, and a live-computed security score.",
  },
  {
    icon: Radar,
    color: "#f87171",
    title: "Threat Detection",
    desc: "Backend-owned detection with severity, source IP, risk score, LLM RCA and remediation.",
  },
  {
    icon: Fingerprint,
    color: "#a78bfa",
    title: "Sessions & Devices",
    desc: "Inspect and revoke sessions, trust or remove recognised devices, everywhere you're signed in.",
  },
  {
    icon: Bug,
    color: "#fb923c",
    title: "Vulnerability Scans",
    desc: "URL reputation, IP reputation, and website security-header vulnerability scans with AI advice.",
  },
  {
    icon: Bot,
    color: "#34d399",
    title: "AI Security Copilot",
    desc: "Streaming assistant grounded on your live threats, alerts, sessions and account state.",
  },
  {
    icon: Eye,
    color: "#60a5fa",
    title: "Behavior Analytics",
    desc: "Personal baseline of hours, devices, countries — with anomaly history for suspicious logins.",
  },
  {
    icon: Terminal,
    color: "#f472b6",
    title: "Attack Simulator",
    desc: "Eight isolated Docker simulations: brute-force, SQLi, XSS, port scan, phishing, and more.",
  },
  {
    icon: ShieldCheck,
    color: "#4ade80",
    title: "Compliance & Reports",
    desc: "Audit log, GDPR/JSON export, and AI-generated executive incident reports.",
  },
];

/* ── Stats ─────────────────────────────────────────────────────── */
const STATS = [
  { value: "8", label: "Attack Simulations" },
  { value: "12+", label: "Modules" },
  { value: "WS + SSE", label: "Live feed" },
];

/* ── FAQ ────────────────────────────────────────────────────────── */
const FAQ = [
  {
    q: "Is the data real?",
    a: "Yes. Every metric, threat, scan, and report is retrieved from the ShieldSphere API. Nothing is mocked, seeded, or fabricated.",
  },
  {
    q: "Do the attack simulations touch public targets?",
    a: "No. Simulations run in an isolated Docker network against a disposable, deliberately-vulnerable sandbox target. Egress is disabled.",
  },
  {
    q: "Does the AI copilot know my account?",
    a: "The backend grounds the LLM in your current threats, alerts, sessions, devices, and login history before streaming a response.",
  },
  {
    q: "Where does my password go?",
    a: "Password checks use HIBP k-anonymity server-side. Only a SHA-1 prefix is used for breach lookups; passwords are never stored in plaintext.",
  },
];

/* ══════════════════════════════════════════════════════════════════
   COMPONENT
══════════════════════════════════════════════════════════════════ */
export default function BrandingPage() {
  const { isAuthenticated, user } = useAuth();
  const { theme } = useTheme();
  const isLight = theme === "light";

  return (
    <div
      className={isLight ? "branding-page branding-page--light" : "branding-page"}
      style={{
        minHeight: "100vh",
        background: isLight
          ? "linear-gradient(160deg, #f8fbff 0%, #edf6ff 40%, #f8fafc 100%)"
          : "linear-gradient(160deg, #060c1a 0%, #081428 40%, #071020 100%)",
        color: isLight ? "#0f172a" : "#e2e8f0",
        fontFamily: "'Inter', system-ui, sans-serif",
        overflowX: "hidden",
      }}
    >
      {/* ── Navbar ──────────────────────────────────────────────── */}
      {isLight && (
        <style>{`
          .branding-page--light header { background: rgba(248, 251, 255, 0.94) !important; border-color: rgba(14, 165, 233, 0.24) !important; }
          .branding-page--light [style*="color: #e2e8f0"], .branding-page--light [style*="color: rgb(226, 232, 240)"], .branding-page--light [style*="color: rgba(226, 232, 240"], .branding-page--light [style*="color: rgb(203, 213, 225)"], .branding-page--light [style*="color: rgba(203, 213, 225"] { color: #1e293b !important; }
          .branding-page--light [style*="background: rgb(15, 23, 42)"], .branding-page--light [style*="background: rgb(6, 12, 26)"], .branding-page--light [style*="background: rgba(15, 23, 42"], .branding-page--light [style*="background: rgba(8, 20, 40"], .branding-page--light [style*="background: rgba(6, 12, 26"], .branding-page--light [style*="background: rgba(255, 255, 255, 0.03"], .branding-page--light [style*="background: rgba(255, 255, 255, 0.02"] { background-color: #ffffff !important; }
          .branding-page--light [style*="border: 1px solid rgba(148, 163, 184"], .branding-page--light [style*="border: 1px solid rgba(56, 189, 248"] { border-color: rgba(14, 116, 144, 0.22) !important; }
          .branding-page--light .branding-terminal { background: #ffffff !important; border-color: rgba(190, 24, 93, 0.28) !important; }
          .branding-page--light .branding-terminal [style*="color: rgba(226, 232, 240"] { color: #334155 !important; }
        `}</style>
      )}
      <header
        style={{
          position: "sticky",
          top: 0,
          zIndex: 50,
          borderBottom: "1px solid rgba(56,189,248,0.12)",
          background: "rgba(6,12,26,0.85)",
          backdropFilter: "blur(20px)",
        }}
      >
        <div
          style={{
            maxWidth: 1280,
            margin: "0 auto",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            height: 64,
            padding: "0 24px",
          }}
        >
          {/* Logo */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              fontWeight: 700,
              fontSize: 18,
            }}
          >
            <div
              style={{
                width: 38,
                height: 38,
                borderRadius: 10,
                background: "linear-gradient(135deg, rgba(56,189,248,0.25), rgba(99,102,241,0.25))",
                border: "1px solid rgba(56,189,248,0.4)",
                display: "grid",
                placeItems: "center",
              }}
            >
              <Shield size={20} color="#38bdf8" />
            </div>
            <span style={{ color: "#e2e8f0" }}>ShieldSphere</span>
          </div>

          {/* Nav links */}
          <nav
            style={{
              display: "flex",
              gap: 28,
              fontSize: 14,
              color: "rgba(226,232,240,0.65)",
            }}
          >
            {["Features", "Modules", "Simulator", "FAQ"].map((n) => (
              <a
                key={n}
                href={`#${n.toLowerCase()}`}
                style={{ textDecoration: "none", color: "inherit", transition: "color 0.2s" }}
                onMouseEnter={(e) => ((e.target as HTMLElement).style.color = "#38bdf8")}
                onMouseLeave={(e) =>
                  ((e.target as HTMLElement).style.color = "rgba(226,232,240,0.65)")
                }
              >
                {n}
              </a>
            ))}
          </nav>

          {/* Actions */}
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <ThemeToggle />
            {isAuthenticated ? (
              <>
                <span style={{ fontSize: 13, color: "rgba(226,232,240,0.6)" }}>
                  Hi, <strong style={{ color: "#e2e8f0" }}>{user?.username}</strong>
                </span>
                <Link
                  to="/app/dashboard"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    padding: "8px 18px",
                    borderRadius: 10,
                    background: "linear-gradient(135deg, #0ea5e9, #6366f1)",
                    color: "#fff",
                    fontWeight: 600,
                    fontSize: 13,
                    textDecoration: "none",
                    boxShadow: "0 0 20px rgba(14,165,233,0.35)",
                  }}
                >
                  <LayoutDashboard size={14} /> Go to Console
                </Link>
              </>
            ) : (
              <>
                <Link
                  to="/auth"
                  search={{ mode: "login" } as any}
                  style={{
                    fontSize: 13,
                    color: "rgba(226,232,240,0.7)",
                    textDecoration: "none",
                  }}
                >
                  Sign In
                </Link>
                <Link
                  to="/auth"
                  search={{ mode: "register" } as any}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    padding: "8px 18px",
                    borderRadius: 10,
                    background: "linear-gradient(135deg, #0ea5e9, #6366f1)",
                    color: "#fff",
                    fontWeight: 600,
                    fontSize: 13,
                    textDecoration: "none",
                    boxShadow: "0 0 20px rgba(14,165,233,0.3)",
                  }}
                >
                  Get started
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* ── Hero ────────────────────────────────────────────────── */}
      <section
        id="features"
        style={{
          position: "relative",
          padding: "96px 24px 80px",
          overflow: "hidden",
        }}
      >
        {/* Floating orbs */}
        <FloatingOrbs />

        <div
          style={{
            maxWidth: 1280,
            margin: "0 auto",
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 48,
            alignItems: "center",
          }}
        >
          {/* Left text */}
          <div>
            <div
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                padding: "6px 14px",
                borderRadius: 999,
                border: "1px solid rgba(56,189,248,0.35)",
                background: "rgba(56,189,248,0.08)",
                fontSize: 12,
                fontWeight: 600,
                color: "#38bdf8",
                marginBottom: 24,
                letterSpacing: "0.04em",
                textTransform: "uppercase",
              }}
            >
              <Zap size={11} />
              Enterprise account security, fully instrumented
            </div>
            <h1
              style={{
                fontSize: "clamp(36px, 5vw, 58px)",
                fontWeight: 900,
                lineHeight: 1.1,
                margin: "0 0 20px",
                letterSpacing: "-0.02em",
              }}
            >
              <span
                style={{
                  background: "linear-gradient(120deg, #38bdf8, #818cf8, #34d399)",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  backgroundClip: "text",
                }}
              >
                ShieldSphere
              </span>
              <br />
              <span style={{ color: "#e2e8f0" }}>the account-security</span>
              <br />
              <span style={{ color: "#e2e8f0" }}>platform</span>
            </h1>
            <p
              style={{
                fontSize: 16,
                lineHeight: 1.7,
                color: "rgba(226,232,240,0.65)",
                marginBottom: 36,
                maxWidth: 480,
              }}
            >
              Detect threats, inspect logins, revoke sessions, scan URLs &amp; IPs, chat with an AI
              copilot, and safely rehearse attacks — all in one authenticated command center for
              your account.
            </p>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <Link
                to="/auth"
                search={{ mode: "register" } as any}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "12px 24px",
                  borderRadius: 12,
                  background: "linear-gradient(135deg, #0ea5e9, #6366f1)",
                  color: "#fff",
                  fontWeight: 700,
                  fontSize: 14,
                  textDecoration: "none",
                  boxShadow: "0 0 30px rgba(14,165,233,0.4)",
                }}
              >
                <Shield size={16} />
                Create your account →
              </Link>
              <Link
                to="/auth"
                search={{ mode: "login" } as any}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "12px 24px",
                  borderRadius: 12,
                  background: "rgba(226,232,240,0.06)",
                  border: "1px solid rgba(226,232,240,0.15)",
                  color: "#e2e8f0",
                  fontWeight: 600,
                  fontSize: 14,
                  textDecoration: "none",
                }}
              >
                Sign in
              </Link>
            </div>

            {/* Stats row */}
            <div style={{ display: "flex", gap: 24, marginTop: 40 }}>
              {STATS.map((s) => (
                <div key={s.label}>
                  <div style={{ fontSize: 22, fontWeight: 800, color: "#38bdf8" }}>{s.value}</div>
                  <div style={{ fontSize: 12, color: "rgba(226,232,240,0.5)" }}>{s.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Right shield visual – badges float around the circle */}
          <div
            style={{
              position: "relative",
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
              minHeight: 400,
            }}
          >
            {/* Left-side floating badges (next to the circle) */}
            <FloatingBadge
              icon={<Shield size={15} color="#38bdf8" />}
              style={{
                position: "absolute",
                top: "18%",
                left: "-10px",
                animation: "float-a 7s ease-in-out infinite",
                zIndex: 5,
              }}
              borderColor="rgba(56,189,248,0.4)"
              bg="rgba(56,189,248,0.1)"
              label="Threat detected"
              dot="red"
            />
            <FloatingBadge
              icon={<Lock size={13} color="#818cf8" />}
              style={{
                position: "absolute",
                top: "62%",
                left: "-10px",
                animation: "float-b 8s ease-in-out infinite 1s",
                zIndex: 5,
              }}
              borderColor="rgba(129,140,248,0.35)"
              bg="rgba(129,140,248,0.08)"
              label="2FA enabled"
              dot="green"
            />
            {/* Right-side floating badges */}
            <FloatingBadge
              icon={<Bot size={13} color="#34d399" />}
              style={{
                position: "absolute",
                top: "20%",
                right: "-10px",
                animation: "float-c 6.5s ease-in-out infinite 0.5s",
                zIndex: 5,
              }}
              borderColor="rgba(52,211,153,0.35)"
              bg="rgba(52,211,153,0.08)"
              label="AI Copilot"
              dot="green"
            />
            <FloatingBadge
              icon={<Fingerprint size={13} color="#fb923c" />}
              style={{
                position: "absolute",
                top: "62%",
                right: "-10px",
                animation: "float-a 9s ease-in-out infinite 2s",
                zIndex: 5,
              }}
              borderColor="rgba(251,146,60,0.35)"
              bg="rgba(251,146,60,0.08)"
              label="Device trusted"
              dot="green"
            />
            <HeroShieldVisual />
          </div>
        </div>
      </section>

      {/* ── Marquee tagline ─────────────────────────────────────── */}
      <div
        style={{
          borderTop: "1px solid rgba(56,189,248,0.1)",
          borderBottom: "1px solid rgba(56,189,248,0.1)",
          background: "rgba(14,165,233,0.04)",
          padding: "14px 0",
          overflow: "hidden",
          position: "relative",
        }}
      >
        {/* Fade edges */}
        <div
          style={{
            position: "absolute",
            left: 0,
            top: 0,
            bottom: 0,
            width: 80,
            background: "linear-gradient(to right, #060c1a, transparent)",
            zIndex: 2,
          }}
        />
        <div
          style={{
            position: "absolute",
            right: 0,
            top: 0,
            bottom: 0,
            width: 80,
            background: "linear-gradient(to left, #060c1a, transparent)",
            zIndex: 2,
          }}
        />
        <div
          style={{
            display: "flex",
            gap: 0,
            width: "max-content",
            animation: "marquee 35s linear infinite",
          }}
        >
          {[...MARQUEE_ITEMS, ...MARQUEE_ITEMS].map((item, i) => (
            <span
              key={i}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                padding: "0 28px",
                fontSize: 13,
                fontWeight: 500,
                color: "rgba(226,232,240,0.65)",
                whiteSpace: "nowrap",
                borderRight: "1px solid rgba(56,189,248,0.15)",
              }}
            >
              <item.icon size={14} color="#38bdf8" />
              {item.label}
            </span>
          ))}
        </div>
      </div>

      {/* ── "One platform" section ──────────────────────────────── */}
      <section id="modules" style={{ padding: "80px 24px" }}>
        <div style={{ maxWidth: 1280, margin: "0 auto" }}>
          <div style={{ textAlign: "center", marginBottom: 56 }}>
            <div
              style={{
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: "0.12em",
                textTransform: "uppercase",
                color: "#38bdf8",
                marginBottom: 12,
              }}
            >
              Every module wired to a real API
            </div>
            <h2
              style={{
                fontSize: "clamp(28px, 4vw, 44px)",
                fontWeight: 900,
                color: "#e2e8f0",
                margin: "0 0 12px",
                letterSpacing: "-0.02em",
              }}
            >
              One platform for the whole account-
              <br />
              security surface
            </h2>
            <p
              style={{
                fontSize: 15,
                color: "rgba(226,232,240,0.55)",
                maxWidth: 560,
                margin: "0 auto",
              }}
            >
              Persisted logins, sessions, threats, devices, blocks, and audit trail — every value in
              the UI comes from a live backend endpoint.
            </p>
          </div>

          {/* Feature grid */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(270px, 1fr))",
              gap: 20,
            }}
          >
            {FEATURES.map((f) => (
              <FeatureCard key={f.title} {...f} />
            ))}
          </div>
        </div>
      </section>

      {/* ── Command center section ──────────────────────────────── */}
      <section
        id="simulator"
        style={{
          padding: "80px 24px",
          background: "linear-gradient(180deg, rgba(14,165,233,0.04) 0%, transparent 100%)",
          borderTop: "1px solid rgba(56,189,248,0.08)",
        }}
      >
        <div
          style={{
            maxWidth: 1280,
            margin: "0 auto",
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 64,
            alignItems: "center",
          }}
        >
          <div>
            <div
              style={{
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: "0.12em",
                textTransform: "uppercase",
                color: "#38bdf8",
                marginBottom: 16,
              }}
            >
              The Command Center
            </div>
            <h2
              style={{
                fontSize: "clamp(28px, 3.5vw, 42px)",
                fontWeight: 900,
                color: "#e2e8f0",
                margin: "0 0 20px",
                letterSpacing: "-0.02em",
                lineHeight: 1.15,
              }}
            >
              See attacks land.{" "}
              <span
                style={{
                  background: "linear-gradient(120deg, #38bdf8, #818cf8)",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  backgroundClip: "text",
                }}
              >
                Act in one click.
              </span>
            </h2>
            <p
              style={{
                fontSize: 15,
                lineHeight: 1.7,
                color: "rgba(226,232,240,0.6)",
                marginBottom: 28,
              }}
            >
              Live login history, geolocated map, active-sessions panel, IP blocklist, and
              unresolved threats queue — with a single-click resolve, revoke, and unblock backed by
              real endpoints.
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {[
                "Real-time security score refreshed after each action",
                "Backend-owned detection: no fake alerts, no fabricated scores",
                "Rate-limit → 401/refresh handled transparently",
                "Streaming AI copilot grounded in your live account state",
              ].map((txt) => (
                <div
                  key={txt}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 10,
                    fontSize: 13,
                    color: "rgba(226,232,240,0.65)",
                  }}
                >
                  <span style={{ color: "#34d399", marginTop: 1, flexShrink: 0 }}>✓</span>
                  {txt}
                </div>
              ))}
            </div>
          </div>

          {/* Dashboard preview card */}
          <DashboardPreviewCard />
        </div>
      </section>

      {/* ── Attack Simulator section ────────────────────────────── */}
      <section
        style={{
          padding: "80px 24px",
          borderTop: "1px solid rgba(56,189,248,0.08)",
        }}
      >
        <div
          style={{
            maxWidth: 1280,
            margin: "0 auto",
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 64,
            alignItems: "center",
          }}
        >
          {/* Simulator terminal mock */}
          <SimulatorTerminalCard />

          <div>
            <div
              style={{
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: "0.12em",
                textTransform: "uppercase",
                color: "#f472b6",
                marginBottom: 16,
              }}
            >
              Isolated Attack Simulator
            </div>
            <h2
              style={{
                fontSize: "clamp(26px, 3.5vw, 38px)",
                fontWeight: 900,
                color: "#e2e8f0",
                margin: "0 0 16px",
                letterSpacing: "-0.02em",
                lineHeight: 1.2,
              }}
            >
              Rehearse the attack.{" "}
              <span
                style={{
                  background: "linear-gradient(120deg, #f472b6, #fb923c)",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  backgroundClip: "text",
                }}
              >
                Learn the defense.
              </span>
            </h2>
            <p
              style={{
                fontSize: 14,
                lineHeight: 1.7,
                color: "rgba(226,232,240,0.6)",
                marginBottom: 28,
              }}
            >
              Eight simulation types run inside a disposable Docker sandbox. Live WebSocket events,
              persisted event history, and phishing / social engineering challenges you can answer
              for a score.
            </p>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: 10,
              }}
            >
              {[
                "brute_force",
                "sql",
                "xss",
                "port_scan",
                "vuln_scan",
                "packet_capture",
                "phishing",
                "social_engineering",
              ].map((sim) => (
                <div
                  key={sim}
                  style={{
                    padding: "10px 14px",
                    borderRadius: 8,
                    border: "1px solid rgba(244,114,182,0.2)",
                    background: "rgba(244,114,182,0.05)",
                    fontSize: 12,
                    fontFamily: "monospace",
                    color: "rgba(226,232,240,0.7)",
                  }}
                >
                  {sim}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── FAQ ─────────────────────────────────────────────────── */}
      <section
        id="faq"
        style={{
          padding: "80px 24px",
          borderTop: "1px solid rgba(56,189,248,0.08)",
        }}
      >
        <div
          style={{
            maxWidth: 1280,
            margin: "0 auto",
            display: "grid",
            gridTemplateColumns: "1fr 2fr",
            gap: 64,
            alignItems: "start",
          }}
        >
          <div>
            <h2
              style={{
                fontSize: 32,
                fontWeight: 900,
                color: "#e2e8f0",
                margin: "0 0 12px",
                letterSpacing: "-0.02em",
              }}
            >
              Frequently asked
            </h2>
            <p
              style={{
                fontSize: 14,
                color: "rgba(226,232,240,0.5)",
                lineHeight: 1.6,
              }}
            >
              Straight answers on what the platform does — and what it doesn't do.
            </p>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {FAQ.map((item) => (
              <FaqItem key={item.q} {...item} />
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ─────────────────────────────────────────────────── */}
      <section style={{ padding: "80px 24px" }}>
        <div style={{ maxWidth: 860, margin: "0 auto" }}>
          <div
            style={{
              borderRadius: 24,
              border: "1px solid rgba(56,189,248,0.2)",
              background: "linear-gradient(135deg, rgba(14,165,233,0.08), rgba(99,102,241,0.08))",
              padding: "56px 40px",
              textAlign: "center",
              position: "relative",
              overflow: "hidden",
            }}
          >
            {/* Glow */}
            <div
              style={{
                position: "absolute",
                top: "50%",
                left: "50%",
                transform: "translate(-50%,-50%)",
                width: 400,
                height: 200,
                background: "radial-gradient(ellipse, rgba(14,165,233,0.15), transparent 70%)",
                pointerEvents: "none",
              }}
            />
            <div style={{ position: "relative" }}>
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: "0.12em",
                  textTransform: "uppercase",
                  color: "#38bdf8",
                  marginBottom: 16,
                }}
              >
                Ready to see your account through an attacker's eyes?
              </div>
              <h2
                style={{
                  fontSize: "clamp(24px, 3vw, 36px)",
                  fontWeight: 900,
                  color: "#e2e8f0",
                  margin: "0 0 12px",
                  letterSpacing: "-0.02em",
                }}
              >
                Sign up in seconds. Enable 2FA. Watch the score climb.
              </h2>
              <div
                style={{
                  display: "flex",
                  gap: 12,
                  justifyContent: "center",
                  marginTop: 32,
                  flexWrap: "wrap",
                }}
              >
                <Link
                  to="/auth"
                  search={{ mode: "register" } as any}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 8,
                    padding: "12px 28px",
                    borderRadius: 12,
                    background: "linear-gradient(135deg, #0ea5e9, #6366f1)",
                    color: "#fff",
                    fontWeight: 700,
                    fontSize: 14,
                    textDecoration: "none",
                    boxShadow: "0 0 30px rgba(14,165,233,0.4)",
                  }}
                >
                  <Shield size={16} />
                  Create free account
                </Link>
                <Link
                  to="/auth"
                  search={{ mode: "login" } as any}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 8,
                    padding: "12px 28px",
                    borderRadius: 12,
                    background: "rgba(226,232,240,0.06)",
                    border: "1px solid rgba(226,232,240,0.15)",
                    color: "#e2e8f0",
                    fontWeight: 600,
                    fontSize: 14,
                    textDecoration: "none",
                  }}
                >
                  Sign in
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────────── */}
      <footer
        style={{
          borderTop: "1px solid rgba(56,189,248,0.1)",
          padding: "28px 24px",
        }}
      >
        <div
          style={{
            maxWidth: 1280,
            margin: "0 auto",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 12,
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              fontWeight: 700,
              fontSize: 14,
              color: "#e2e8f0",
            }}
          >
            <Shield size={16} color="#38bdf8" />
            ShieldSphere
          </div>
          <p style={{ fontSize: 12, color: "rgba(226,232,240,0.4)" }}>
            Enterprise Account Security Platform · Built with FastAPI + React
          </p>
        </div>
      </footer>

      {/* ── Global animation keyframes ───────────────────────────── */}
      <style>{`
        @keyframes marquee {
          from { transform: translateX(0); }
          to   { transform: translateX(-50%); }
        }
        @keyframes float-a {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50%       { transform: translateY(-18px) rotate(3deg); }
        }
        @keyframes float-b {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50%       { transform: translateY(-12px) rotate(-4deg); }
        }
        @keyframes float-c {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          50%       { transform: translateY(-22px) rotate(2deg); }
        }
        @keyframes pulse-ring {
          0%, 100% { opacity: 0.35; transform: scale(1); }
          50%       { opacity: 0.65; transform: scale(1.06); }
        }
        @keyframes orbit-dot {
          from { transform: rotate(var(--start-deg)) translateX(130px) rotate(calc(-1 * var(--start-deg))); }
          to   { transform: rotate(calc(var(--start-deg) + 360deg)) translateX(130px) rotate(calc(-1 * (var(--start-deg) + 360deg))); }
        }
        @keyframes scan {
          0%   { transform: translateY(-100%); opacity: 0.7; }
          100% { transform: translateY(400%);  opacity: 0; }
        }
        @keyframes glow-blink {
          0%, 100% { opacity: 0.7; }
          50%       { opacity: 1; }
        }
        @keyframes shield-pulse {
          0%, 100% { transform: scale(1); opacity: 1; }
          50%       { transform: scale(1.05); opacity: 0.9; }
        }
      `}</style>
    </div>
  );
}

/* ── Floating security orbs (background glows only) ─────────────── */
function FloatingOrbs() {
  return (
    <div style={{ position: "absolute", inset: 0, pointerEvents: "none", overflow: "hidden" }}>
      {/* Large teal glow top-center */}
      <div
        style={{
          position: "absolute",
          top: -120,
          left: "40%",
          width: 600,
          height: 600,
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(14,165,233,0.12) 0%, transparent 70%)",
          animation: "pulse-ring 6s ease-in-out infinite",
        }}
      />
      {/* Purple glow right */}
      <div
        style={{
          position: "absolute",
          top: 80,
          right: -80,
          width: 400,
          height: 400,
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(99,102,241,0.1) 0%, transparent 70%)",
          animation: "float-c 9s ease-in-out infinite",
        }}
      />
    </div>
  );
}

function FloatingBadge({
  icon,
  style,
  bg,
  borderColor,
  label,
  dot,
}: {
  icon: React.ReactNode;
  style?: React.CSSProperties;
  bg: string;
  borderColor: string;
  label: string;
  dot: "red" | "green";
}) {
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        padding: "8px 14px",
        borderRadius: 999,
        background: bg,
        border: `1px solid ${borderColor}`,
        backdropFilter: "blur(10px)",
        fontSize: 12,
        fontWeight: 600,
        color: "#e2e8f0",
        whiteSpace: "nowrap",
        ...style,
      }}
    >
      {icon}
      {label}
      <span
        style={{
          width: 7,
          height: 7,
          borderRadius: "50%",
          background: dot === "red" ? "#f87171" : "#34d399",
          animation: "glow-blink 2s ease-in-out infinite",
          flexShrink: 0,
        }}
      />
    </div>
  );
}

/* ── Hero shield visual ─────────────────────────────────────────── */
function HeroShieldVisual() {
  const ORBIT_COLORS = ["#38bdf8", "#818cf8", "#34d399", "#f87171", "#fb923c"];
  const ORBIT_DEGS = [0, 72, 144, 216, 288];

  return (
    <div
      style={{
        position: "relative",
        width: 340,
        height: 340,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      {/* Outer dashed rotating ring */}
      <div
        style={{
          position: "absolute",
          width: 310,
          height: 310,
          borderRadius: "50%",
          border: "1px dashed rgba(56,189,248,0.22)",
        }}
      />
      {/* Middle pulsing ring */}
      <div
        style={{
          position: "absolute",
          width: 220,
          height: 220,
          borderRadius: "50%",
          border: "1px solid rgba(99,102,241,0.2)",
          animation: "pulse-ring 4s ease-in-out infinite",
        }}
      />
      {/* Inner glow */}
      <div
        style={{
          position: "absolute",
          width: 140,
          height: 140,
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(14,165,233,0.2), transparent 70%)",
          animation: "pulse-ring 3s ease-in-out infinite 0.5s",
        }}
      />
      {/* Center shield */}
      <div
        style={{
          width: 90,
          height: 90,
          borderRadius: 22,
          background: "linear-gradient(135deg, rgba(14,165,233,0.25), rgba(99,102,241,0.25))",
          border: "1.5px solid rgba(56,189,248,0.5)",
          display: "grid",
          placeItems: "center",
          boxShadow: "0 0 40px rgba(14,165,233,0.4), inset 0 0 20px rgba(14,165,233,0.1)",
          zIndex: 2,
          animation: "shield-pulse 3s ease-in-out infinite",
        }}
      >
        <Shield size={44} color="#38bdf8" />
      </div>

      {/* Orbiting dots */}
      {ORBIT_DEGS.map((deg, i) => (
        <div
          key={i}
          style={{
            position: "absolute",
            width: 9,
            height: 9,
            borderRadius: "50%",
            background: ORBIT_COLORS[i],
            boxShadow: `0 0 10px ${ORBIT_COLORS[i]}`,
            top: "50%",
            left: "50%",
            marginTop: -4.5,
            marginLeft: -4.5,
            transform: `rotate(${deg}deg) translateX(130px)`,
            animation: `orbit-dot ${12 + i * 1.5}s linear infinite`,
            // CSS variable for animation
          }}
        />
      ))}

      {/* Scan line */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: "50%",
          transform: "translateX(-50%)",
          width: 2,
          height: "38%",
          background: "linear-gradient(to bottom, transparent, rgba(56,189,248,0.7))",
          animation: "scan 3s linear infinite",
          borderRadius: 2,
          zIndex: 3,
        }}
      />
    </div>
  );
}

/* ── Feature card ───────────────────────────────────────────────── */
function FeatureCard({
  icon: Icon,
  color,
  title,
  desc,
}: {
  icon: any;
  color: string;
  title: string;
  desc: string;
}) {
  return (
    <div
      style={{
        borderRadius: 16,
        border: "1px solid rgba(226,232,240,0.07)",
        background: "rgba(255,255,255,0.03)",
        padding: "24px",
        transition: "all 0.25s",
        cursor: "default",
      }}
      onMouseEnter={(e) => {
        const el = e.currentTarget as HTMLElement;
        el.style.borderColor = `${color}40`;
        el.style.background = `rgba(255,255,255,0.05)`;
        el.style.transform = "translateY(-3px)";
        el.style.boxShadow = `0 8px 30px ${color}18`;
      }}
      onMouseLeave={(e) => {
        const el = e.currentTarget as HTMLElement;
        el.style.borderColor = "rgba(226,232,240,0.07)";
        el.style.background = "rgba(255,255,255,0.03)";
        el.style.transform = "translateY(0)";
        el.style.boxShadow = "none";
      }}
    >
      <div
        style={{
          width: 42,
          height: 42,
          borderRadius: 12,
          background: `${color}18`,
          border: `1px solid ${color}30`,
          display: "grid",
          placeItems: "center",
          marginBottom: 16,
        }}
      >
        <Icon size={20} color={color} />
      </div>
      <h3 style={{ fontSize: 15, fontWeight: 700, color: "#e2e8f0", marginBottom: 8 }}>{title}</h3>
      <p style={{ fontSize: 13, lineHeight: 1.65, color: "rgba(226,232,240,0.55)" }}>{desc}</p>
    </div>
  );
}

/* ── Dashboard preview card ─────────────────────────────────────── */
function DashboardPreviewCard() {
  return (
    <div
      style={{
        borderRadius: 16,
        border: "1px solid rgba(56,189,248,0.15)",
        background: "rgba(6,12,26,0.7)",
        overflow: "hidden",
        boxShadow: "0 20px 60px rgba(14,165,233,0.12)",
      }}
    >
      {/* Window chrome */}
      <div
        style={{
          padding: "10px 16px",
          borderBottom: "1px solid rgba(56,189,248,0.1)",
          display: "flex",
          alignItems: "center",
          gap: 8,
          background: "rgba(255,255,255,0.03)",
        }}
      >
        <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#f87171" }} />
        <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#fbbf24" }} />
        <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#34d399" }} />
        <span
          style={{
            marginLeft: 8,
            fontSize: 11,
            color: "rgba(226,232,240,0.4)",
            fontFamily: "monospace",
          }}
        >
          shieldsphere / dashboard
        </span>
      </div>
      {/* Content */}
      <div style={{ padding: 20 }}>
        <div style={{ display: "flex", gap: 16, marginBottom: 20 }}>
          {[
            { label: "Score", v: "87", c: "#34d399" },
            { label: "Threats", v: "3", c: "#f87171" },
            { label: "Sessions", v: "5", c: "#38bdf8" },
          ].map((s) => (
            <div key={s.label}>
              <div style={{ fontSize: 11, color: "rgba(226,232,240,0.45)", marginBottom: 4 }}>
                {s.label}
              </div>
              <div style={{ fontSize: 28, fontWeight: 900, color: s.c }}>{s.v}</div>
            </div>
          ))}
        </div>
        {/* Login sparkline */}
        <div style={{ fontSize: 11, color: "rgba(226,232,240,0.4)", marginBottom: 8 }}>
          Logins (last 14 days)
        </div>
        <svg viewBox="0 0 200 48" style={{ width: "100%", height: 48 }}>
          <polyline
            points="0,40 20,32 40,35 60,20 80,28 100,18 120,24 140,12 160,16 180,8 200,14"
            fill="none"
            stroke="#38bdf8"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <polyline
            points="0,40 20,32 40,35 60,20 80,28 100,18 120,24 140,12 160,16 180,8 200,14 200,48 0,48"
            fill="rgba(56,189,248,0.08)"
            strokeWidth="0"
          />
        </svg>
        {/* Threat alert pills */}
        <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 8 }}>
          <div
            style={{
              borderRadius: 8,
              background: "rgba(248,113,113,0.1)",
              border: "1px solid rgba(248,113,113,0.25)",
              padding: "10px 14px",
            }}
          >
            <div style={{ fontSize: 12, fontWeight: 600, color: "#f87171" }}>
              🔴 Brute-force attempt
            </div>
            <div style={{ fontSize: 11, color: "rgba(226,232,240,0.45)", marginTop: 2 }}>
              182.234.114.4 · 24 failed logins
            </div>
          </div>
          <div
            style={{
              borderRadius: 8,
              background: "rgba(52,211,153,0.08)",
              border: "1px solid rgba(52,211,153,0.2)",
              padding: "10px 14px",
            }}
          >
            <div style={{ fontSize: 12, fontWeight: 600, color: "#34d399" }}>🟢 2FA enabled</div>
            <div style={{ fontSize: 11, color: "rgba(226,232,240,0.45)", marginTop: 2 }}>
              TOTP verified 2 mins ago
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Simulator terminal card ────────────────────────────────────── */
function SimulatorTerminalCard() {
  return (
    <div
      className="branding-terminal"
      style={{
        borderRadius: 16,
        border: "1px solid rgba(244,114,182,0.15)",
        background: "rgba(6,12,26,0.8)",
        overflow: "hidden",
        fontFamily: "monospace",
        fontSize: 12,
        boxShadow: "0 20px 60px rgba(244,114,182,0.08)",
      }}
    >
      <div
        style={{
          padding: "10px 16px",
          borderBottom: "1px solid rgba(244,114,182,0.1)",
          display: "flex",
          alignItems: "center",
          gap: 8,
          background: "rgba(255,255,255,0.02)",
        }}
      >
        <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#f87171" }} />
        <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#fbbf24" }} />
        <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#34d399" }} />
        <span style={{ marginLeft: 8, fontSize: 11, color: "rgba(226,232,240,0.4)" }}>
          shieldsphere-simulator — brute_force
        </span>
      </div>
      <div style={{ padding: 20, lineHeight: 1.8 }}>
        <TermLine color="#38bdf8" prefix="[queue]" text="simulation accepted" />
        <TermLine
          color="#fbbf24"
          prefix="[start]"
          text="target container ready → net: shieldsphere_sandbox"
        />
        <TermLine
          color="#f87171"
          prefix="[login_attempt]"
          text="attacker-100.38.11.4 user-admin → 401"
        />
        <TermLine
          color="#f87171"
          prefix="[login_attempt]"
          text="attacker-100.38.11.4 user-admin → 401"
        />
        <TermLine
          color="#fb923c"
          prefix="[detect]"
          text="brute_force threshold crossed → auto_blocked"
        />
        <TermLine
          color="#34d399"
          prefix="[complete]"
          text="26 attempts → 0 successful → threat persisted"
        />
      </div>
    </div>
  );
}

function TermLine({ color, prefix, text }: { color: string; prefix: string; text: string }) {
  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
      <span style={{ color, fontWeight: 700 }}>{prefix}</span>
      <span style={{ color: "rgba(226,232,240,0.65)" }}>{text}</span>
    </div>
  );
}

/* ── FAQ item ───────────────────────────────────────────────────── */
function FaqItem({ q, a }: { q: string; a: string }) {
  return (
    <div
      style={{
        borderRadius: 12,
        border: "1px solid rgba(56,189,248,0.1)",
        background: "rgba(255,255,255,0.03)",
        padding: "18px 20px",
      }}
    >
      <div style={{ fontWeight: 700, fontSize: 14, color: "#e2e8f0", marginBottom: 8 }}>{q}</div>
      <div style={{ fontSize: 13, lineHeight: 1.65, color: "rgba(226,232,240,0.55)" }}>{a}</div>
    </div>
  );
}
