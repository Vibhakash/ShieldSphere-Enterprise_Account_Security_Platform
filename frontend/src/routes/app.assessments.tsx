import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type {
  BreachCheckResponse,
  IpReputationOut,
  PasswordStrengthResponse,
  UrlScanOut,
  VulnScanOut,
} from "@/lib/types";
import { useAuth } from "@/lib/auth";
import {
  PageHeader,
  LoadingBlock,
  ErrorState,
  EmptyState,
  fmtDate,
  StatusBadge,
  statusTone,
} from "@/components/common";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { Bug } from "lucide-react";

export const Route = createFileRoute("/app/assessments")({ component: AssessmentsPage });

function AssessmentsPage() {
  return (
    <>
      <PageHeader
        title="Assessments"
        description="Password strength, breach check, URL and IP reputation, website vulnerability scans."
      />
      <Tabs defaultValue="password" className="w-full">
        <TabsList className="flex w-full flex-wrap justify-start">
          <TabsTrigger value="password">Password</TabsTrigger>
          <TabsTrigger value="breach">Breach</TabsTrigger>
          <TabsTrigger value="url">URL scan</TabsTrigger>
          <TabsTrigger value="ip">IP reputation</TabsTrigger>
          <TabsTrigger value="vuln">Vulnerability</TabsTrigger>
        </TabsList>
        <TabsContent value="password">
          <PasswordTool />
        </TabsContent>
        <TabsContent value="breach">
          <BreachTool />
        </TabsContent>
        <TabsContent value="url">
          <UrlTool />
        </TabsContent>
        <TabsContent value="ip">
          <IpTool />
        </TabsContent>
        <TabsContent value="vuln">
          <VulnTool />
        </TabsContent>
      </Tabs>
    </>
  );
}

function PasswordTool() {
  const [pw, setPw] = useState("");
  const [result, setResult] = useState<PasswordStrengthResponse | null>(null);
  const m = useMutation({
    mutationFn: (password: string) =>
      api<PasswordStrengthResponse>("/assessment/password-strength", { body: { password } }),
    onSuccess: setResult,
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });
  const scoreColor = [
    "bg-destructive",
    "bg-destructive/80",
    "bg-warning",
    "bg-success/80",
    "bg-success",
  ];
  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle>Password strength</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (pw) m.mutate(pw);
          }}
        >
          <Input
            type="password"
            placeholder="Enter a password to evaluate"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
          />
          <Button type="submit" disabled={!pw || m.isPending}>
            Check
          </Button>
        </form>
        {result && (
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="text-2xl font-bold">{result.strength_label}</div>
              <StatusBadge
                status={result.is_breached ? `Breached x${result.breach_count}` : "Not breached"}
                tone={result.is_breached ? "danger" : "success"}
              />
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
              <div
                className={`h-full transition-all ${scoreColor[result.score]}`}
                style={{ width: `${(result.score + 1) * 20}%` }}
              />
            </div>
            <div className="text-sm text-muted-foreground">
              Estimated crack time: <span className="font-mono">{result.crack_time_display}</span> ·
              Entropy: <span className="font-mono">{result.entropy_bits.toFixed(1)} bits</span>
            </div>
            {result.warning && <div className="text-sm text-warning">{result.warning}</div>}
            {result.suggestions?.length > 0 && (
              <ul className="list-inside list-disc text-sm text-muted-foreground">
                {result.suggestions.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function BreachTool() {
  const auth = useAuth();
  const [pw, setPw] = useState("");
  const [result, setResult] = useState<BreachCheckResponse | null>(null);
  const m = useMutation({
    mutationFn: (password: string) =>
      api<BreachCheckResponse>("/assessment/breach-check", { body: { password } }),
    onSuccess: async (data) => {
      setResult(data);
      if (data.account_status_updated) await auth.refresh();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });
  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle>Breach check (HIBP)</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Password is checked server-side using SHA-1 k-anonymity. Only a prefix is used to look up
          HIBP.
        </p>
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (pw) m.mutate(pw);
          }}
        >
          <Input
            type="password"
            placeholder="Password to check"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
          />
          <Button type="submit" disabled={!pw || m.isPending}>
            Check
          </Button>
        </form>
        {result && (
          <div className="rounded-lg border border-border bg-muted/40 p-4 text-sm">
            <div className="mb-1 flex items-center gap-2">
              <StatusBadge
                status={result.is_breached ? "Breached" : "Not breached"}
                tone={result.is_breached ? "danger" : "success"}
              />
              {result.is_breached && (
                <span className="font-mono text-xs">
                  seen {result.breach_count.toLocaleString()} times
                </span>
              )}
            </div>
            <div className="text-muted-foreground">{result.message}</div>
            <div className="mt-2 text-xs font-medium">
              {result.is_current_password
                ? "Account status: this matches your current password."
                : "Standalone result: this is not your current account password."}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function UrlTool() {
  const qc = useQueryClient();
  const [url, setUrl] = useState("");
  const [activeId, setActiveId] = useState<string | null>(null);
  const list = useQuery<UrlScanOut[]>({
    queryKey: ["url-scans"],
    queryFn: () => api("/assessment/url-scans"),
  });
  const active = useQuery<UrlScanOut>({
    queryKey: ["url-scan", activeId],
    queryFn: () => api(`/assessment/url-scan/${activeId}`),
    enabled: !!activeId,
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return s && !["done", "error", "timeout"].includes(s) ? 5000 : false;
    },
  });
  useEffect(() => {
    if (active.data && ["done", "error", "timeout"].includes(active.data.status)) {
      qc.invalidateQueries({ queryKey: ["url-scans"] });
    }
  }, [active.data, qc]);

  const submit = useMutation({
    mutationFn: (u: string) => api<UrlScanOut>("/assessment/url-scan", { body: { url: u } }),
    onSuccess: (d) => {
      setActiveId(d.id);
      toast.success("Scan queued");
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });

  return (
    <div className="mt-4 grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>URL reputation scan</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (url) submit.mutate(url);
            }}
          >
            <Input
              type="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            <Button type="submit" disabled={!url || submit.isPending}>
              Scan
            </Button>
          </form>
          {active.data && (
            <div className="rounded-lg border border-border p-4">
              <div className="mb-2 flex items-center gap-2">
                <StatusBadge status={active.data.status} tone={statusTone(active.data.status)} />
                <span className="truncate font-mono text-xs">{active.data.url}</span>
              </div>
              {active.data.status === "done" && (
                <>
                  <div className="grid grid-cols-3 gap-2 text-center text-sm">
                    <div className="rounded-md border border-border p-2">
                      <div className="text-destructive font-bold">
                        {active.data.malicious_count ?? 0}
                      </div>
                      <div className="text-xs text-muted-foreground">Malicious</div>
                    </div>
                    <div className="rounded-md border border-border p-2">
                      <div className="text-warning font-bold">
                        {active.data.suspicious_count ?? 0}
                      </div>
                      <div className="text-xs text-muted-foreground">Suspicious</div>
                    </div>
                    <div className="rounded-md border border-border p-2">
                      <div className="text-success font-bold">
                        {active.data.harmless_count ?? 0}
                      </div>
                      <div className="text-xs text-muted-foreground">Harmless</div>
                    </div>
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                    These numbers show how many VirusTotal security engines classified this URL as
                    malicious, suspicious, or harmless. They are engine votes, not numbers of
                    attacks or visitors.
                  </p>
                </>
              )}
              {active.data.verdict && (
                <div className="mt-2 text-sm">
                  Verdict: <span className="font-medium">{active.data.verdict}</span>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Recent scans</CardTitle>
        </CardHeader>
        <CardContent>
          {list.isLoading ? (
            <LoadingBlock />
          ) : list.error ? (
            <ErrorState description={(list.error as any).message} />
          ) : !list.data?.length ? (
            <EmptyState title="No scan history is available." />
          ) : (
            <ul className="space-y-2 text-sm">
              {list.data.map((s) => (
                <li
                  key={s.id}
                  className="cursor-pointer rounded-md border border-border p-2 hover:bg-muted"
                  onClick={() => setActiveId(s.id)}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-xs">{s.url}</span>
                    <StatusBadge status={s.status} tone={statusTone(s.status)} />
                  </div>
                  <div className="mt-0.5 text-xs text-muted-foreground">
                    {fmtDate(s.submitted_at)}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function IpTool() {
  const [ip, setIp] = useState("");
  const list = useQuery<IpReputationOut[]>({
    queryKey: ["ip-rep"],
    queryFn: () => api("/assessment/ip-reputation"),
  });
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: (v: string) =>
      api<IpReputationOut>("/assessment/ip-reputation", { body: { ip: v } }),
    onSuccess: () => {
      toast.success("Checked");
      qc.invalidateQueries({ queryKey: ["ip-rep"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });
  return (
    <div className="mt-4 grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>IP reputation</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (ip) m.mutate(ip);
            }}
          >
            <Input
              placeholder="8.8.8.8 or 2001:db8::1"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
            />
            <Button type="submit" disabled={!ip || m.isPending}>
              Check
            </Button>
          </form>
          {m.data && <IpCard r={m.data} />}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Recent checks</CardTitle>
        </CardHeader>
        <CardContent>
          {list.isLoading ? (
            <LoadingBlock />
          ) : list.error ? (
            <ErrorState description={(list.error as any).message} />
          ) : !list.data?.length ? (
            <EmptyState title="No IP reputation checks yet." />
          ) : (
            <ul className="space-y-2">
              {list.data.map((r) => (
                <li key={r.id}>
                  <IpCard r={r} />
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function IpCard({ r }: { r: IpReputationOut }) {
  return (
    <div className="rounded-md border border-border p-3 text-sm">
      <div className="flex items-center justify-between">
        <span className="font-mono">{r.ip_address}</span>
        <StatusBadge
          status={r.overall_verdict}
          tone={
            r.overall_verdict?.toLowerCase() === "clean"
              ? "success"
              : r.overall_verdict?.toLowerCase().includes("malicious")
                ? "danger"
                : "warn"
          }
        />
      </div>
      <div className="mt-1 grid grid-cols-2 gap-2 text-xs text-muted-foreground">
        <div>
          VT malicious:{" "}
          <span className="font-mono text-foreground">{r.virustotal_malicious ?? "—"}</span>
        </div>
        <div>
          VT suspicious:{" "}
          <span className="font-mono text-foreground">{r.virustotal_suspicious ?? "—"}</span>
        </div>
        <div>
          Abuse score:{" "}
          <span className="font-mono text-foreground">{r.abuse_confidence_score ?? "—"}</span>
        </div>
        <div>
          Abuse reports:{" "}
          <span className="font-mono text-foreground">{r.abuse_total_reports ?? "—"}</span>
        </div>
      </div>
      <div className="mt-1 text-xs text-muted-foreground">{fmtDate(r.checked_at)}</div>
    </div>
  );
}

function VulnTool() {
  const [url, setUrl] = useState("");
  const [pollingId, setPollingId] = useState<string | null>(null);
  const list = useQuery<VulnScanOut[]>({
    queryKey: ["vuln-scans"],
    queryFn: () => api("/assessment/vuln-scans"),
    refetchInterval: pollingId ? 5000 : false,
  });
  const m = useMutation({
    mutationFn: (u: string) =>
      api<VulnScanOut>("/assessment/vuln-scan", { body: { target_url: u } }),
    onSuccess: (d) => {
      setPollingId(d.id);
      toast.success("Scan started");
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });
  useEffect(() => {
    if (!pollingId) return;
    const cur = list.data?.find((s) => s.id === pollingId);
    if (cur && ["completed", "error"].includes(cur.status)) setPollingId(null);
  }, [list.data, pollingId]);

  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle>Website vulnerability scan</CardTitle>
        <p className="text-sm text-muted-foreground">
          Check a website's transport and browser protections. Each result explains what was found
          and why it matters.
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (url) m.mutate(url);
          }}
        >
          <Input
            type="url"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <Button type="submit" disabled={!url || m.isPending}>
            <Bug className="mr-1 h-4 w-4" /> Scan
          </Button>
        </form>
        {list.isLoading ? (
          <LoadingBlock />
        ) : list.error ? (
          <ErrorState description={(list.error as any).message} />
        ) : !list.data?.length ? (
          <EmptyState title="No scan history is available." />
        ) : (
          <div className="max-h-[640px] space-y-3 overflow-y-auto pr-1">
            {list.data.map((s) => (
              <div key={s.id} className="rounded-lg border border-border p-3 text-sm">
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <StatusBadge status={s.status} tone={statusTone(s.status)} />
                  <span className="truncate font-mono text-xs">{s.target_url}</span>
                  <span className="ml-auto text-xs text-muted-foreground">
                    {fmtDate(s.scanned_at)}
                  </span>
                </div>
                {s.status === "completed" && (
                  <>
                    <div className="mb-2 flex flex-wrap items-center gap-4 text-xs">
                      <Header label="HTTPS" ok={s.has_https} />
                      <Header label="HSTS" ok={s.has_hsts} />
                      <Header label="CSP" ok={s.has_csp} />
                      {s.risk_score != null && (
                        <div>
                          Risk: <span className="font-mono">{s.risk_score}</span>
                        </div>
                      )}
                    </div>
                    {s.risk_score != null && (
                      <>
                        <Progress value={s.risk_score} className="h-2" />
                        <p className="mt-2 text-xs text-muted-foreground">
                          The risk score is based on missing transport and browser-protection
                          headers. Higher means more protections are missing.
                        </p>
                      </>
                    )}
                    {s.findings && <StructuredSecurityAdvice findings={s.findings} />}
                    {s.findings && <VulnerabilityFindings findings={s.findings} />}
                  </>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Header({ label, ok }: { label: string; ok: boolean | null }) {
  const cls =
    ok === true ? "text-success" : ok === false ? "text-destructive" : "text-muted-foreground";
  return (
    <div className={cls}>
      <span className="font-semibold">{label}:</span>{" "}
      {ok === true ? "yes" : ok === false ? "no" : "—"}
    </div>
  );
}

function StructuredSecurityAdvice({ findings }: { findings: Record<string, unknown> }) {
  const controls = [
    {
      key: "https",
      title: "Encrypted connection (HTTPS)",
      why: "Encrypts information between a visitor's browser and the website.",
      action: "Serve the site over HTTPS and redirect every HTTP request to HTTPS.",
    },
    {
      key: "hsts",
      title: "HTTPS enforcement (HSTS)",
      why: "Tells browsers to use HTTPS automatically on future visits.",
      action:
        "Add a Strict-Transport-Security header after confirming HTTPS works on all subdomains.",
    },
    {
      key: "csp",
      title: "Content Security Policy (CSP)",
      why: "Limits which scripts, styles, and content the browser is allowed to load.",
      action:
        "Add a restrictive Content-Security-Policy and refine it in report-only mode before enforcing it.",
    },
    {
      key: "x_frame_options",
      title: "Clickjacking protection",
      why: "Prevents another site from embedding this website in a misleading frame.",
      action: "Set X-Frame-Options to DENY or SAMEORIGIN, or use CSP frame-ancestors.",
    },
    {
      key: "x_content_type",
      title: "Content-type protection",
      why: "Stops browsers from guessing an unsafe file type when handling content.",
      action: "Set X-Content-Type-Options to nosniff on web responses.",
    },
  ].filter(({ key }) => typeof findings[key] === "boolean");
  const missing = controls.filter(({ key }) => findings[key] === false).length;

  return (
    <section className="mt-4 overflow-hidden rounded-lg border border-primary/30 bg-primary/5">
      <div className="border-b border-primary/20 bg-primary/10 px-4 py-3">
        <h3 className="font-semibold text-foreground">Security hardening guidance</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          {missing === 0
            ? "All checked protections are present."
            : `${missing} protection${missing === 1 ? " is" : "s are"} missing and should be addressed.`}
        </p>
      </div>
      <div className="max-h-80 space-y-3 overflow-y-auto p-4 pr-3 text-sm text-muted-foreground">
        {controls.map(({ key, title, why, action }) => {
          const present = findings[key] === true;
          return (
            <article key={key} className="rounded-md border border-border bg-background/60 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h4 className="font-semibold text-foreground">{title}</h4>
                <span
                  className={
                    present ? "font-semibold text-success" : "font-semibold text-destructive"
                  }
                >
                  {present ? "Present" : "Missing"}
                </span>
              </div>
              <p className="mt-2 leading-6">
                <strong className="text-foreground">Why it matters:</strong> {why}
              </p>
              <p className="mt-1 leading-6">
                <strong className="text-foreground">Recommended action:</strong>{" "}
                {present
                  ? "Keep this control enabled and verify it after deployment changes."
                  : action}
              </p>
            </article>
          );
        })}
        {typeof findings.server === "string" && (
          <article className="rounded-md border border-border bg-background/60 p-3">
            <h4 className="font-semibold text-foreground">Server information</h4>
            <p className="mt-2 leading-6">
              <strong className="text-foreground">Observed value:</strong> {findings.server}
            </p>
            <p className="mt-1 leading-6">
              <strong className="text-foreground">What this means:</strong> The scan does not
              identify CVEs from a server header alone. Avoid exposing unnecessary version details
              and keep the server patched.
            </p>
          </article>
        )}
      </div>
    </section>
  );
}

function VulnerabilityFindings({ findings }: { findings: Record<string, unknown> }) {
  if (typeof findings.error === "string") {
    return (
      <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">
        The scan could not be completed: {findings.error}
      </div>
    );
  }

  const protections = [
    {
      key: "https",
      label: "Encrypted connection (HTTPS)",
      help: "Protects data while it travels between the visitor and website.",
    },
    {
      key: "hsts",
      label: "HTTPS enforcement (HSTS)",
      help: "Tells browsers to use HTTPS for future visits.",
    },
    {
      key: "csp",
      label: "Content Security Policy (CSP)",
      help: "Limits which scripts and content the browser may load.",
    },
    {
      key: "x_frame_options",
      label: "Clickjacking protection",
      help: "Prevents the site from being embedded in an unauthorized frame.",
    },
    {
      key: "x_content_type",
      label: "Content-type protection",
      help: "Stops browsers from guessing unsafe file types.",
    },
  ].filter(({ key }) => typeof findings[key] === "boolean");
  const missing =
    typeof findings.missing_headers === "number"
      ? findings.missing_headers
      : protections.filter(({ key }) => findings[key] === false).length;

  return (
    <div className="mt-3 rounded-md border border-border bg-muted/30 p-3">
      <div className="font-semibold">What the scanner found</div>
      <p className="mt-1 text-xs text-muted-foreground">
        {missing === 0
          ? "All checked protections are present."
          : `${missing} of ${protections.length} checked protections ${missing === 1 ? "is" : "are"} missing.`}
      </p>
      <ul className="mt-3 space-y-2">
        {protections.map(({ key, label, help }) => {
          const ok = findings[key] === true;
          return (
            <li key={key} className="flex items-start justify-between gap-3 text-xs">
              <div>
                <div className="font-medium text-foreground">{label}</div>
                <div className="text-muted-foreground">{help}</div>
              </div>
              <span
                className={`shrink-0 font-semibold ${ok ? "text-success" : "text-destructive"}`}
              >
                {ok ? "Present" : "Missing"}
              </span>
            </li>
          );
        })}
      </ul>
      {typeof findings.server === "string" && (
        <div className="mt-3 border-t border-border pt-2 text-xs text-muted-foreground">
          Web server identified itself as{" "}
          <span className="font-mono text-foreground">{findings.server}</span>.
        </div>
      )}
    </div>
  );
}
