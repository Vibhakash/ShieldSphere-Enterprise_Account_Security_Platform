import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { UBAAnomaly, UBADeviceActivity, UBAProfileOut } from "@/lib/types";
import { PageHeader, LoadingBlock, ErrorState, EmptyState, fmtDate } from "@/components/common";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Eye, MonitorSmartphone, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

export const Route = createFileRoute("/app/uba")({ component: UBAPage });

function UBAPage() {
  const queryClient = useQueryClient();
  const profile = useQuery<UBAProfileOut>({
    queryKey: ["uba", "profile"],
    queryFn: () => api("/uba/profile"),
  });
  const anomalies = useQuery<UBAAnomaly[]>({
    queryKey: ["uba", "anomalies"],
    queryFn: () => api("/uba/anomalies", { query: { days: 30 } }),
  });
  const deviceActivity = useQuery<UBADeviceActivity[]>({
    queryKey: ["uba", "device-activity"],
    queryFn: () => api("/uba/device-activity"),
  });
  const rebuild = useMutation({
    mutationFn: () => api<{ message: string }>("/uba/rebuild", { method: "POST", body: {} }),
    onSuccess: (data) => {
      toast.success(data.message);
      window.setTimeout(
        () => queryClient.invalidateQueries({ queryKey: ["uba", "profile"] }),
        1500,
      );
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not queue baseline rebuild"),
  });

  return (
    <>
      <PageHeader
        title="User behavior analytics"
        description="Baseline of your normal activity and recent anomalies."
        actions={
          <Button
            size="sm"
            variant="outline"
            onClick={() => rebuild.mutate()}
            disabled={rebuild.isPending}
          >
            <RefreshCw className="mr-1 h-4 w-4" />{" "}
            {rebuild.isPending ? "Queuing…" : "Rebuild baseline"}
          </Button>
        }
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Behavioral baseline</CardTitle>
          </CardHeader>
          <CardContent>
            {profile.isLoading ? (
              <LoadingBlock />
            ) : profile.error ? (
              profile.error instanceof ApiError && profile.error.status === 404 ? (
                <EmptyState
                  title="No behavior profile is available yet."
                  description="Use ShieldSphere successfully from two different recognized devices. The baseline begins after two successful sign-ins from those two devices and becomes more accurate as normal activity is recorded."
                  icon={<Eye className="h-6 w-6" />}
                />
              ) : (
                <ErrorState description={(profile.error as any).message} />
              )
            ) : !profile.data ? (
              <EmptyState
                title="No behavior profile is available yet."
                icon={<Eye className="h-6 w-6" />}
              />
            ) : (
              <dl className="grid grid-cols-2 gap-3 text-sm">
                <Field label="Samples" value={String(profile.data.sample_count)} />
                <Field
                  label="Avg logins / day"
                  value={profile.data.avg_logins_per_day?.toFixed(2) ?? "—"}
                />
                <Field
                  label="Known devices"
                  value={String(listValues(profile.data.known_device_ids).length)}
                />
                <Field
                  label="Known countries"
                  value={String(listValues(profile.data.known_countries).length)}
                />
                <Field
                  label="Known ASNs"
                  value={String(listValues(profile.data.known_asns).length)}
                />
                <Field label="Last updated" value={fmtDate(profile.data.last_updated)} />
              </dl>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Recent anomalies</CardTitle>
          </CardHeader>
          <CardContent>
            {anomalies.isLoading ? (
              <LoadingBlock />
            ) : anomalies.error ? (
              <ErrorState description={(anomalies.error as any).message} />
            ) : !anomalies.data?.length ? (
              <EmptyState title="No anomalies detected." />
            ) : (
              <ul className="space-y-2 text-sm">
                {anomalies.data.map((a) => {
                  const pct = Math.round((a.anomaly_score ?? 0) * 100);
                  const tone =
                    pct >= 70
                      ? "text-destructive"
                      : pct >= 40
                        ? "text-warning"
                        : "text-muted-foreground";
                  return (
                    <li key={a.id} className="rounded-md border border-border p-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs">{a.ip}</span>
                        <span className={`font-mono text-xs font-semibold ${tone}`}>{pct}%</span>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {[a.city, a.country].filter(Boolean).join(", ") || "Unknown"} ·{" "}
                        {a.success ? "Success" : "Failed"} · {fmtDate(a.timestamp)}
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </CardContent>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Account device activity</CardTitle>
          </CardHeader>
          <CardContent>
            {deviceActivity.isLoading ? (
              <LoadingBlock />
            ) : deviceActivity.error ? (
              <ErrorState description={(deviceActivity.error as Error).message} />
            ) : !deviceActivity.data?.length ? (
              <EmptyState
                title="No account device activity is available yet."
                description="Device sign-ins, active sessions, and sign-outs will appear here."
                icon={<MonitorSmartphone className="h-6 w-6" />}
              />
            ) : (
              <div className="grid gap-3 xl:grid-cols-2">
                {deviceActivity.data.map((device) => (
                  <DeviceActivityCard key={device.device_id} device={device} />
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border p-3">
      <dt className="text-xs uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className="mt-1 font-semibold">{value}</dd>
    </div>
  );
}

function DeviceActivityCard({ device }: { device: UBADeviceActivity }) {
  return (
    <article className="rounded-lg border border-border p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate font-semibold">{device.name}</div>
          <div className="mt-0.5 truncate font-mono text-xs text-muted-foreground">
            {device.device_id}
          </div>
        </div>
        <span
          className={`rounded-full px-2 py-0.5 text-xs font-medium ${
            device.is_active
              ? "bg-success/15 text-success"
              : device.is_trusted
                ? "bg-primary/10 text-primary"
                : "bg-muted text-muted-foreground"
          }`}
        >
          {device.is_active ? "Active now" : device.is_trusted ? "Trusted" : "Inactive"}
        </span>
      </div>
      <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-2 xl:grid-cols-3">
        <ActivityField label="Location" value={device.location ?? "Location unavailable"} />
        <ActivityField label="Last IP" value={device.last_ip ?? "Unknown"} mono />
        <ActivityField
          label="Device details"
          value={
            [device.device_type, device.browser, device.os].filter(Boolean).join(" · ") || "Unknown"
          }
        />
        <ActivityField
          label="Trust status"
          value={device.is_trusted ? "Trusted device" : "Not trusted"}
        />
        <ActivityField
          label="Last sign-in"
          value={device.last_login ? fmtDate(device.last_login) : "No successful sign-in recorded"}
        />
        <ActivityField
          label="Last sign-out"
          value={
            device.last_logout
              ? fmtDate(device.last_logout)
              : device.is_active
                ? "Session still active"
                : "No sign-out recorded"
          }
        />
      </dl>
      <div className="mt-3 border-t border-border pt-3">
        <div className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Recent activity
        </div>
        <ul className="max-h-44 space-y-2 overflow-y-auto pr-1 text-xs">
          {device.events.map((event, index) => (
            <li key={`${event.timestamp}-${index}`} className="rounded-md bg-muted/45 p-2">
              <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
                <span className="font-medium">{event.event_type}</span>
                <time className="text-muted-foreground">{fmtDate(event.timestamp)}</time>
              </div>
              <div className="mt-1 text-muted-foreground">
                {[event.location, event.ip_address].filter(Boolean).join(" · ") ||
                  "Details unavailable"}
                {event.details ? ` · ${event.details}` : ""}
              </div>
            </li>
          ))}
        </ul>
      </div>
    </article>
  );
}

function ActivityField({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "mt-0.5 font-mono" : "mt-0.5"}>{value}</dd>
    </div>
  );
}

function listValues(source: Record<string, unknown> | null | undefined): string[] {
  if (!source) return [];
  return Object.values(source).flatMap((value) => (Array.isArray(value) ? value.map(String) : []));
}
