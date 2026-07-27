import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type {
  ActivityDay,
  ContainmentPreview,
  ContainmentResult,
  DashboardStats,
  SecurityScore,
  LoginHistoryOut,
  LoginLocationOut,
} from "@/lib/types";
import {
  PageHeader,
  LoadingBlock,
  ErrorState,
  EmptyState,
  fmtDate,
  fmtRelative,
} from "@/components/common";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Activity,
  Bell,
  Fingerprint,
  Radar,
  ShieldCheck,
  Ban,
  UsersRound,
  TrendingUp,
  CheckCircle2,
  CircleAlert,
  ShieldAlert,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Legend,
} from "recharts";
import { Button } from "@/components/ui/button";
import { BlockIpDialog } from "@/components/block-ip-dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { toast } from "sonner";

export const Route = createFileRoute("/app/dashboard")({ component: Dashboard });

function Dashboard() {
  const [containment, setContainment] = useState<ContainmentResult | null>(null);
  const stats = useQuery<DashboardStats>({
    queryKey: ["dash", "stats"],
    queryFn: () => api("/dashboard/stats"),
  });
  const score = useQuery<SecurityScore>({
    queryKey: ["dash", "score"],
    queryFn: () => api("/dashboard/security-score"),
  });
  const activity = useQuery<ActivityDay[]>({
    queryKey: ["dash", "activity"],
    queryFn: () => api("/dashboard/activity-timeline", { query: { days: 30 } }),
  });
  const history = useQuery<LoginHistoryOut[]>({
    queryKey: ["dash", "history"],
    queryFn: () => api("/dashboard/login-history", { query: { page: 1, per_page: 8 } }),
  });
  const locations = useQuery<LoginLocationOut[]>({
    queryKey: ["dash", "locations"],
    queryFn: () => api("/dashboard/login-locations"),
  });

  return (
    <>
      <PageHeader
        title="Security dashboard"
        description="Live account-security signal from your backend."
        actions={<SecureAccountButton onComplete={setContainment} />}
      />
      {containment && (
        <Card className="mb-4 border-success/40 bg-success/5">
          <CardContent className="flex flex-col gap-3 pt-6 sm:flex-row sm:items-start">
            <ShieldCheck className="h-5 w-5 shrink-0 text-success" />
            <div className="flex-1 text-sm">
              <div className="font-semibold">Account containment completed</div>
              <p className="mt-1 text-muted-foreground">
                Revoked {containment.sessions_revoked} other session(s), distrusted{" "}
                {containment.devices_distrusted} device(s), and blocked {containment.ips_blocked}{" "}
                threat source IP(s). Your current session was preserved.
              </p>
              <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-muted-foreground">
                {containment.recommendations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
            <Button size="sm" variant="ghost" onClick={() => setContainment(null)}>
              Dismiss
            </Button>
          </CardContent>
        </Card>
      )}
      {stats.isLoading ? (
        <LoadingBlock />
      ) : stats.error ? (
        <ErrorState description={(stats.error as any).message} />
      ) : (
        stats.data && (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard
              icon={<ShieldCheck className="h-4 w-4" />}
              label="Security score"
              value={String(stats.data.security_score)}
              accent="primary"
              hint={score.data ? `Updated ${fmtRelative(score.data.computed_at)}` : undefined}
            />
            <MetricCard
              icon={<Radar className="h-4 w-4" />}
              label="Unresolved threats"
              value={String(stats.data.unresolved_threats)}
              accent={stats.data.unresolved_threats ? "danger" : "success"}
            />
            <MetricCard
              icon={<UsersRound className="h-4 w-4" />}
              label="Active sessions"
              value={String(stats.data.active_sessions)}
              accent="accent"
            />
            <MetricCard
              icon={<Bell className="h-4 w-4" />}
              label="Unread alerts"
              value={String(stats.data.unread_alerts)}
              accent={stats.data.unread_alerts ? "warn" : "muted"}
            />
            <MetricCard
              icon={<Activity className="h-4 w-4" />}
              label="Logins today"
              value={String(stats.data.total_logins_today)}
              hint={`${stats.data.successful_logins_today} ok · ${stats.data.failed_logins_today} failed`}
            />
            <MetricCard
              icon={<TrendingUp className="h-4 w-4" />}
              label="Success rate"
              value={`${Math.round(stats.data.login_success_rate)}%`}
            />
            <MetricCard
              icon={<Fingerprint className="h-4 w-4" />}
              label="Devices"
              value={String(stats.data.devices_count)}
            />
            <MetricCard
              icon={<Ban className="h-4 w-4" />}
              label="Blocked IPs"
              value={String(stats.data.blocked_ips)}
              accent={stats.data.blocked_ips ? "warn" : "muted"}
            />
            <MetricCard
              icon={<ShieldAlert className="h-4 w-4" />}
              label="Sandbox detections"
              value={String(stats.data.simulation_threats)}
              accent={stats.data.simulation_threats ? "warn" : "muted"}
              hint={`${stats.data.simulation_alerts} unread alert(s) · ${stats.data.simulation_login_attempts} simulated login attempt(s) today`}
            />
          </div>
        )
      )}

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Login activity (last 30 days)</CardTitle>
          </CardHeader>
          <CardContent>
            {activity.isLoading ? (
              <LoadingBlock />
            ) : activity.error ? (
              <ErrorState description={(activity.error as any).message} />
            ) : !activity.data?.length ? (
              <EmptyState
                title="No activity data yet"
                description="Sign-in and threat activity will appear here."
              />
            ) : (
              <div className="h-64 w-full">
                <ResponsiveContainer>
                  <AreaChart data={activity.data}>
                    <defs>
                      <linearGradient id="s" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--color-primary)" stopOpacity={0.5} />
                        <stop offset="100%" stopColor="var(--color-primary)" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="f" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--color-destructive)" stopOpacity={0.45} />
                        <stop offset="100%" stopColor="var(--color-destructive)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid
                      stroke="color-mix(in oklch, var(--color-foreground) 8%, transparent)"
                      strokeDasharray="3 3"
                    />
                    <XAxis
                      dataKey="date"
                      stroke="var(--color-muted-foreground)"
                      fontSize={11}
                      tickFormatter={(v) => v?.slice(5)}
                    />
                    <YAxis
                      stroke="var(--color-muted-foreground)"
                      fontSize={11}
                      allowDecimals={false}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "var(--color-card)",
                        border: "1px solid var(--color-border)",
                        borderRadius: 8,
                      }}
                    />
                    <Legend />
                    <Area
                      type="monotone"
                      dataKey="successes"
                      name="Successful"
                      stroke="var(--color-primary)"
                      fill="url(#s)"
                      strokeWidth={2}
                    />
                    <Area
                      type="monotone"
                      dataKey="failures"
                      name="Failed"
                      stroke="var(--color-destructive)"
                      fill="url(#f)"
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Score factors</CardTitle>
          </CardHeader>
          <CardContent>
            {score.isLoading ? (
              <LoadingBlock />
            ) : score.error ? (
              <ErrorState description={(score.error as any).message} />
            ) : score.data ? (
              <FactorsView factors={score.data.factors} score={score.data.score} />
            ) : null}
          </CardContent>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Recent login history</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          {history.isLoading ? (
            <LoadingBlock />
          ) : history.error ? (
            <ErrorState description={(history.error as any).message} />
          ) : !history.data?.length ? (
            <EmptyState title="No login history yet" />
          ) : (
            <table className="w-full min-w-[780px] text-sm">
              <thead className="text-left text-muted-foreground">
                <tr className="border-b border-border">
                  <th className="py-2">When</th>
                  <th className="py-2">IP</th>
                  <th className="py-2">Location</th>
                  <th className="py-2">Result</th>
                  <th className="py-2">Anomaly</th>
                  <th className="py-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((l) => (
                  <tr key={l.id} className="border-b border-border/60 last:border-0">
                    <td className="py-2">{fmtDate(l.timestamp)}</td>
                    <td className="py-2 font-mono text-xs">{l.ip_address}</td>
                    <td className="py-2">
                      {[l.city, l.country].filter(Boolean).join(", ") || "—"}
                    </td>
                    <td className="py-2">
                      {l.success ? (
                        <span className="text-success">Success</span>
                      ) : (
                        <span className="text-destructive">
                          Failed{l.failure_reason ? ` · ${l.failure_reason}` : ""}
                        </span>
                      )}
                    </td>
                    <td className="py-2">
                      {l.anomaly_score != null ? l.anomaly_score.toFixed(2) : "—"}
                    </td>
                    <td className="py-2 text-right">
                      {!l.success && !l.is_simulation && (
                        <BlockIpDialog
                          ipAddress={l.ip_address}
                          defaultReason={`Failed sign-in${l.failure_reason ? `: ${l.failure_reason}` : ""}`}
                        />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Recent login locations</CardTitle>
        </CardHeader>
        <CardContent>
          {locations.isLoading ? (
            <LoadingBlock />
          ) : locations.error ? (
            <ErrorState description={(locations.error as any).message} />
          ) : !locations.data?.length ? (
            <EmptyState title="No login locations available yet" />
          ) : (
            <ul className="space-y-2 text-sm">
              {locations.data.map((location) => (
                <li
                  key={`${location.latitude}-${location.longitude}-${location.last_seen}`}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border p-3"
                >
                  <span>
                    {[location.city, location.country].filter(Boolean).join(", ") ||
                      "Unknown location"}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {location.count} login{location.count === 1 ? "" : "s"} · last seen{" "}
                    {fmtDate(location.last_seen)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </>
  );
}

function SecureAccountButton({ onComplete }: { onComplete: (result: ContainmentResult) => void }) {
  const qc = useQueryClient();
  const preview = useQuery<ContainmentPreview>({
    queryKey: ["containment-preview"],
    queryFn: () => api("/security-actions/containment-preview"),
  });
  const secure = useMutation({
    mutationFn: () =>
      api<ContainmentResult>("/security-actions/secure-account", { method: "POST", body: {} }),
    onSuccess: (result) => {
      onComplete(result);
      toast.success("Account containment completed");
      qc.invalidateQueries();
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Containment failed"),
  });
  const item = preview.data;
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="destructive" size="sm">
          <ShieldAlert className="mr-1 h-4 w-4" /> Secure my account
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Contain suspicious account access?</AlertDialogTitle>
          <AlertDialogDescription>
            This preserves the session you are using now. It does not change your password or mark
            threats resolved.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="grid grid-cols-2 gap-2 text-sm">
          <ContainmentCount label="Other sessions revoked" value={item?.other_active_sessions} />
          <ContainmentCount label="Other devices reviewed" value={item?.other_devices} />
          <ContainmentCount
            label="Serious threats contained"
            value={item?.serious_unresolved_threats}
          />
          <ContainmentCount label="Source IPs blocked" value={item?.blockable_source_ips} />
        </div>
        {preview.error && (
          <p className="text-sm text-destructive">Could not load the containment preview.</p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={() => secure.mutate()}
            disabled={secure.isPending || preview.isLoading}
          >
            Apply containment
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function ContainmentCount({ label, value }: { label: string; value?: number }) {
  return (
    <div className="rounded-md border border-border p-3">
      <div className="text-2xl font-bold">{value ?? "—"}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}

function MetricCard({
  icon,
  label,
  value,
  hint,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  hint?: string;
  accent?: "primary" | "danger" | "warn" | "success" | "muted" | "accent";
}) {
  const bg =
    accent === "danger"
      ? "text-destructive"
      : accent === "warn"
        ? "text-warning"
        : accent === "success"
          ? "text-success"
          : accent === "accent"
            ? "text-accent"
            : accent === "muted"
              ? "text-muted-foreground"
              : "text-primary";
  return (
    <Card>
      <CardContent className="pt-6">
        <div className={`mb-2 flex items-center gap-2 text-xs font-medium ${bg}`}>
          {icon}
          <span className="uppercase tracking-wide">{label}</span>
        </div>
        <div className="text-3xl font-bold">{value}</div>
        {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
      </CardContent>
    </Card>
  );
}

function FactorsView({ factors, score }: { factors: Record<string, unknown>; score: number }) {
  const order = [
    "base_score",
    "2fa_enabled",
    "password_safe",
    "password_breached",
    "unresolved_threats",
    "trusted_devices",
    "active_sessions",
  ];
  const rank = (key: string) => {
    const index = order.indexOf(key);
    return index === -1 ? order.length : index;
  };
  const entries = Object.entries(factors ?? {})
    .filter(([key]) => key !== "final_score")
    .sort(([left], [right]) => rank(left) - rank(right));
  const calculation = entries.map(([key, value]) => ({ key, impact: factorImpact(value) }));
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-primary/25 bg-primary/5 p-4 text-center">
        <div className="text-5xl font-bold text-gradient">{score}</div>
        <div className="text-xs text-muted-foreground">out of 100</div>
        <div className="mt-3 h-2 overflow-hidden rounded-full bg-muted">
          <div
            className="h-full rounded-full bg-primary transition-all"
            style={{ width: `${score}%` }}
          />
        </div>
      </div>
      <p className="text-xs leading-relaxed text-muted-foreground">
        Your score starts at 50. Account protections add points, while verified risks remove points.
        The result is kept between 0 and 100.
      </p>
      <ul className="space-y-2 text-sm">
        {entries.map(([k, v]) => (
          <li key={k} className="rounded-md border border-border/70 p-3">
            <div className="flex items-start justify-between gap-3">
              <div className="flex min-w-0 gap-2">
                <FactorIcon value={v} />
                <div>
                  <div className="font-medium">{factorTitle(k)}</div>
                  <div className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                    {factorExplanation(k, v)}
                  </div>
                </div>
              </div>
              <span
                className={`shrink-0 font-mono text-xs font-semibold ${factorImpact(v) < 0 ? "text-destructive" : factorImpact(v) > 0 ? "text-success" : "text-muted-foreground"}`}
              >
                {formatImpact(factorImpact(v))}
              </span>
            </div>
          </li>
        ))}
      </ul>
      <div className="rounded-md bg-muted/40 p-3 text-xs">
        <div className="mb-1 font-semibold">How this score was calculated</div>
        <div className="leading-relaxed text-muted-foreground">
          {calculation.map(({ key, impact }, index) => (
            <span key={key}>
              {index > 0 ? (impact < 0 ? " − " : " + ") : ""}
              {index > 0 ? Math.abs(impact) : impact} {factorShortTitle(key)}
            </span>
          ))}{" "}
          = <span className="font-semibold text-foreground">{score}</span>
        </div>
      </div>
    </div>
  );
}

type FactorData = {
  value?: boolean;
  count?: number;
  points?: number;
  penalty?: number;
  available_points?: number;
  description?: string;
};

function asFactorData(value: unknown): FactorData {
  return value && typeof value === "object" ? (value as FactorData) : {};
}

function factorImpact(value: unknown) {
  if (typeof value === "number") return 0;
  const data = asFactorData(value);
  return Number(data.points ?? 0) + Number(data.penalty ?? 0);
}

function factorTitle(key: string) {
  return (
    (
      {
        base_score: "Starting score",
        "2fa_enabled": "Two-factor authentication",
        password_safe: "Password breach status",
        password_breached: "Password breach status",
        unresolved_threats: "Unresolved serious threats",
        trusted_devices: "Trusted devices",
        active_sessions: "Active sessions",
      } as Record<string, string>
    )[key] ?? key.replace(/_/g, " ")
  );
}

function factorShortTitle(key: string) {
  return (
    (
      {
        base_score: "base",
        "2fa_enabled": "2FA",
        password_safe: "safe password",
        password_breached: "breached password",
        unresolved_threats: "threats",
        trusted_devices: "trusted device",
        active_sessions: "sessions",
      } as Record<string, string>
    )[key] ?? key.replace(/_/g, " ")
  );
}

function factorExplanation(key: string, value: unknown) {
  const data = asFactorData(value);
  if (key === "base_score") return data.description ?? "Every account begins with 50 points.";
  if (key === "2fa_enabled")
    return data.value
      ? "Enabled. This extra sign-in check adds 25 points."
      : `Not enabled. Turn it on to gain ${data.available_points ?? 25} points.`;
  if (key === "password_safe")
    return "Your current password was not found in known breach data when last checked.";
  if (key === "password_breached")
    return `Your current password was found ${Number(data.count ?? 0).toLocaleString()} times in known breach data.`;
  if (key === "unresolved_threats")
    return `${data.count ?? 0} unresolved high or critical threat${data.count === 1 ? "" : "s"} in the last 30 days. Each removes 10 points, up to 30.`;
  if (key === "trusted_devices")
    return `${data.count ?? 0} trusted device${data.count === 1 ? "" : "s"}. Having at least one adds 5 points.`;
  if (key === "active_sessions")
    return `${data.count ?? 0} active session${data.count === 1 ? "" : "s"}. More than five removes 3 points per extra session, up to 15.`;
  return data.description ?? "Included in the current security score.";
}

function formatImpact(impact: number) {
  if (impact > 0) return `+${impact} points`;
  if (impact < 0) return `${impact} points`;
  return "No change";
}

function FactorIcon({ value }: { value: unknown }) {
  const impact = factorImpact(value);
  return impact < 0 ? (
    <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
  ) : (
    <CheckCircle2
      className={`mt-0.5 h-4 w-4 shrink-0 ${impact > 0 ? "text-success" : "text-muted-foreground"}`}
    />
  );
}
