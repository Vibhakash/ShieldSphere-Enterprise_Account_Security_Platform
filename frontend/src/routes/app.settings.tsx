import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { EmptyState, fmtDate, LoadingBlock, PageHeader, StatusBadge } from "@/components/common";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Copy,
  Fingerprint,
  KeyRound,
  Mail,
  Power,
  Send,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Webhook,
} from "lucide-react";
import { toast } from "sonner";
import type { IntegrationOut, PasskeyOut } from "@/lib/types";
import { browserSupportsWebAuthn, startRegistration } from "@simplewebauthn/browser";

export const Route = createFileRoute("/app/settings")({ component: SettingsPage });

function SettingsPage() {
  const auth = useAuth();
  const navigate = useNavigate();
  const user = auth.user;

  return (
    <>
      <PageHeader
        title="Account & security settings"
        description="Manage your credentials, two-factor authentication, and account."
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Profile</CardTitle>
          </CardHeader>
          <CardContent>
            {user ? (
              <dl className="grid grid-cols-2 gap-3 text-sm">
                <F label="Full name" value={user.full_name ?? "—"} />
                <F label="Username" value={user.username} />
                <F label="Email" value={user.email} />
                <F label="Role" value={user.role} />
                <F label="2FA" value={user.totp_enabled ? "Enabled" : "Disabled"} />
                <F
                  label="Current password status"
                  value={
                    user.password_breached
                      ? `Breached (${user.password_breach_count.toLocaleString()})`
                      : "Not in known breaches"
                  }
                />
              </dl>
            ) : null}
            <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
              This status belongs only to the password currently saved on your account. It is
              checked when the password is set, or when you test that exact password under
              Assessments → Breach. Testing a different password does not change this status.
            </p>
          </CardContent>
        </Card>

        <ChangePasswordCard
          onDone={async () => {
            await auth.logout();
            navigate({ to: "/auth" });
          }}
        />
        <TotpCard enabled={!!user?.totp_enabled} onChange={auth.refresh} />
        <PasskeyCard />
        <IntegrationsCard />
      </div>
    </>
  );
}

function F({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border p-3">
      <dt className="text-xs uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className="mt-1 truncate font-semibold">{value}</dd>
    </div>
  );
}

function ChangePasswordCard({ onDone }: { onDone: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const m = useMutation({
    mutationFn: () =>
      api<{ message: string }>("/auth/change-password", {
        body: { current_password: current, new_password: next },
      }),
    onSuccess: () => {
      toast.success("Password changed. Please sign in again.");
      onDone();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-4 w-4" /> Change password
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            m.mutate();
          }}
        >
          <div className="space-y-1">
            <Label>Current password</Label>
            <Input
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              required
            />
          </div>
          <div className="space-y-1">
            <Label>New password (min 8 chars)</Label>
            <Input
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              minLength={8}
              required
            />
          </div>
          <Button type="submit" disabled={m.isPending || next.length < 8 || !current}>
            Update password
          </Button>
          <p className="text-xs text-muted-foreground">
            All sessions will be revoked and you will be signed out.
          </p>
        </form>
      </CardContent>
    </Card>
  );
}

function TotpCard({
  enabled,
  onChange,
}: {
  enabled: boolean;
  onChange: () => Promise<void> | void;
}) {
  const [setup, setSetup] = useState<{ secret: string; qr_data_url: string } | null>(null);
  const [code, setCode] = useState("");

  const startSetup = useMutation({
    mutationFn: () =>
      api<{ secret: string; qr_uri: string; qr_data_url: string }>("/auth/2fa/setup", {
        method: "POST",
        body: {},
      }),
    onSuccess: (d) => setSetup(d),
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });
  const confirm = useMutation({
    mutationFn: () => api<{ message: string }>("/auth/2fa/confirm", { body: { code } }),
    onSuccess: async () => {
      toast.success("Two-factor authentication enabled");
      setSetup(null);
      setCode("");
      await onChange();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });
  const disable = useMutation({
    mutationFn: () => api<{ message: string }>("/auth/2fa/disable", { body: { code } }),
    onSuccess: async () => {
      toast.success("Two-factor authentication disabled");
      setCode("");
      await onChange();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });

  return (
    <Card className="lg:col-span-2">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {enabled ? (
            <ShieldCheck className="h-4 w-4 text-success" />
          ) : (
            <ShieldAlert className="h-4 w-4 text-warning" />
          )}
          Two-factor authentication
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {!enabled && !setup && (
          <>
            <p className="text-sm text-muted-foreground">
              Protect your account with a TOTP authenticator app (Google Authenticator, 1Password,
              Authy).
            </p>
            <Button onClick={() => startSetup.mutate()} disabled={startSetup.isPending}>
              Start 2FA setup
            </Button>
          </>
        )}
        {!enabled && setup && (
          <div className="grid gap-4 md:grid-cols-[auto_minmax(0,1fr)]">
            <img
              src={setup.qr_data_url}
              alt="TOTP QR code"
              className="h-40 w-40 rounded-md border border-border bg-white p-2"
            />
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Scan the QR with your authenticator, or enter this secret manually:
              </p>
              <code className="block break-all rounded-md border border-border bg-muted/40 p-2 font-mono text-xs">
                {setup.secret}
              </code>
              <form
                className="flex gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  confirm.mutate();
                }}
              >
                <Input
                  inputMode="numeric"
                  maxLength={6}
                  placeholder="6-digit code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
                <Button type="submit" disabled={code.length !== 6 || confirm.isPending}>
                  Enable
                </Button>
              </form>
            </div>
          </div>
        )}
        {enabled && (
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              disable.mutate();
            }}
          >
            <div className="space-y-1">
              <Label>Current TOTP code</Label>
              <Input
                inputMode="numeric"
                maxLength={6}
                placeholder="6-digit code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </div>
            <Button
              type="submit"
              variant="destructive"
              disabled={code.length !== 6 || disable.isPending}
            >
              Disable 2FA
            </Button>
          </form>
        )}
      </CardContent>
    </Card>
  );
}

function PasskeyCard() {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const passkeys = useQuery<PasskeyOut[]>({
    queryKey: ["passkeys"],
    queryFn: () => api("/auth/passkeys"),
  });
  const add = useMutation({
    mutationFn: async () => {
      if (!browserSupportsWebAuthn()) throw new Error("This browser does not support passkeys");
      const begin = await api<{ ceremony_id: string; options: any }>(
        "/auth/passkeys/register/options",
        { method: "POST", body: {} },
      );
      const credential = await startRegistration({ optionsJSON: begin.options });
      return api<PasskeyOut>("/auth/passkeys/register/verify", {
        body: { ceremony_id: begin.ceremony_id, name: name.trim(), credential },
      });
    },
    onSuccess: () => {
      toast.success("Passkey registered");
      setName("");
      qc.invalidateQueries({ queryKey: ["passkeys"] });
    },
    onError: (e) =>
      toast.error(
        e instanceof ApiError
          ? e.message
          : e instanceof Error
            ? e.message
            : "Passkey registration failed",
      ),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/auth/passkeys/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast.success("Passkey removed");
      qc.invalidateQueries({ queryKey: ["passkeys"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Could not remove passkey"),
  });

  return (
    <Card className="lg:col-span-2">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Fingerprint className="h-4 w-4 text-primary" /> Passkeys
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Use Windows Hello, Touch ID, Face ID, a phone, or a hardware security key for
          phishing-resistant sign-in.
        </p>
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input
            value={name}
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
            placeholder="Name this passkey, e.g. Work laptop"
          />
          <Button onClick={() => add.mutate()} disabled={add.isPending || !name.trim()}>
            <Fingerprint className="mr-1 h-4 w-4" />{" "}
            {add.isPending ? "Waiting for device..." : "Add passkey"}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          Passkeys require the same hostname configured by the server. You are currently using{" "}
          <code>{window.location.origin}</code>.
        </p>
        {passkeys.isLoading ? (
          <LoadingBlock />
        ) : !passkeys.data?.length ? (
          <EmptyState
            title="No passkeys registered"
            description="Add one to enable passwordless sign-in."
          />
        ) : (
          <ul className="space-y-2">
            {passkeys.data.map((item) => (
              <li
                key={item.id}
                className="flex flex-wrap items-center gap-3 rounded-md border border-border p-3 text-sm"
              >
                <Fingerprint className="h-4 w-4 text-primary" />
                <div className="min-w-0 flex-1">
                  <div className="font-semibold">{item.name}</div>
                  <div className="text-xs text-muted-foreground">
                    {item.device_type?.replace(/_/g, " ") ?? "Authenticator"} · added{" "}
                    {fmtDate(item.created_at)} ·{" "}
                    {item.last_used_at ? `last used ${fmtDate(item.last_used_at)}` : "not used yet"}
                  </div>
                </div>
                {item.backed_up && <StatusBadge status="Synced" tone="success" />}
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => remove.mutate(item.id)}
                  disabled={remove.isPending}
                >
                  <Trash2 className="mr-1 h-3.5 w-3.5" /> Remove
                </Button>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

function IntegrationsCard() {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [type, setType] = useState<"webhook" | "email">("webhook");
  const [destination, setDestination] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [includeSimulations, setIncludeSimulations] = useState(true);
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const integrations = useQuery<IntegrationOut[]>({
    queryKey: ["integrations"],
    queryFn: () => api("/integrations"),
  });
  const create = useMutation({
    mutationFn: () =>
      api<IntegrationOut>("/integrations", {
        body: {
          name,
          integration_type: type,
          destination,
          minimum_severity: severity,
          include_simulations: includeSimulations,
        },
      }),
    onSuccess: (item) => {
      setNewSecret(item.signing_secret ?? null);
      setName("");
      setDestination("");
      toast.success("Integration created");
      qc.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Could not create integration"),
  });
  const test = useMutation({
    mutationFn: (id: string) => api(`/integrations/${id}/test`, { method: "POST", body: {} }),
    onSuccess: () => {
      toast.success("Test notification delivered");
      qc.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Test delivery failed"),
  });
  const toggle = useMutation({
    mutationFn: (id: string) => api(`/integrations/${id}/toggle`, { method: "PATCH", body: {} }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["integrations"] }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/integrations/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast.success("Integration removed");
      qc.invalidateQueries({ queryKey: ["integrations"] });
    },
  });

  return (
    <Card className="lg:col-span-2">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Webhook className="h-4 w-4 text-accent" /> Real-time integrations
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <p className="text-sm text-muted-foreground">
          Deliver matching security alerts immediately to a signed public webhook or an email
          address. Delivery results are retained for troubleshooting.
        </p>
        {newSecret && (
          <div className="rounded-md border border-warning/40 bg-warning/10 p-3 text-sm">
            <div className="font-semibold">Copy the webhook signing secret now</div>
            <p className="my-1 text-xs text-muted-foreground">
              It is shown only once. Verify the <code>X-ShieldSphere-Signature</code> HMAC-SHA256
              header in your receiver.
            </p>
            <div className="flex gap-2">
              <code className="min-w-0 flex-1 break-all rounded bg-background p-2 text-xs">
                {newSecret}
              </code>
              <Button
                size="sm"
                variant="outline"
                onClick={() => navigator.clipboard.writeText(newSecret)}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          <div className="space-y-1">
            <Label>Name</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="SOC webhook"
            />
          </div>
          <div className="space-y-1">
            <Label>Channel</Label>
            <select
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
              value={type}
              onChange={(e) => setType(e.target.value as any)}
            >
              <option value="webhook">Signed webhook</option>
              <option value="email">Email</option>
            </select>
          </div>
          <div className="space-y-1 lg:col-span-2">
            <Label>{type === "webhook" ? "Public HTTPS endpoint" : "Recipient email"}</Label>
            <Input
              type={type === "email" ? "email" : "url"}
              value={destination}
              onChange={(e) => setDestination(e.target.value)}
              placeholder={
                type === "webhook" ? "https://example.com/security-events" : "security@example.com"
              }
            />
          </div>
          <div className="space-y-1">
            <Label>Minimum severity</Label>
            <select
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {["low", "medium", "high", "critical"].map((item) => (
                <option key={item}>{item}</option>
              ))}
            </select>
          </div>
          <label className="flex items-center gap-2 self-end pb-2 text-sm">
            <input
              type="checkbox"
              checked={includeSimulations}
              onChange={(e) => setIncludeSimulations(e.target.checked)}
            />{" "}
            Include sandbox alerts
          </label>
          <Button
            className="self-end"
            onClick={() => create.mutate()}
            disabled={create.isPending || !name.trim() || !destination.trim()}
          >
            <Send className="mr-1 h-4 w-4" /> Add integration
          </Button>
        </div>
        {type === "email" && (
          <p className="text-xs text-muted-foreground">
            Email delivery requires SMTP_HOST and SMTP_FROM_EMAIL in the backend environment. Use
            Test after adding the channel.
          </p>
        )}
        {integrations.isLoading ? (
          <LoadingBlock />
        ) : !integrations.data?.length ? (
          <EmptyState title="No integrations configured" />
        ) : (
          <ul className="space-y-2">
            {integrations.data.map((item) => (
              <li
                key={item.id}
                className="flex flex-wrap items-center gap-3 rounded-md border border-border p-3 text-sm"
              >
                {item.integration_type === "email" ? (
                  <Mail className="h-4 w-4" />
                ) : (
                  <Webhook className="h-4 w-4" />
                )}
                <div className="min-w-0 flex-1">
                  <div className="font-semibold">{item.name}</div>
                  <div className="text-xs text-muted-foreground">
                    {item.destination_hint} · {item.minimum_severity}+ ·{" "}
                    {item.include_simulations ? "includes simulations" : "real alerts only"}
                  </div>
                  {item.last_error && (
                    <div className="mt-1 text-xs text-destructive">{item.last_error}</div>
                  )}
                </div>
                <StatusBadge
                  status={item.is_active ? "Active" : "Paused"}
                  tone={item.is_active ? "success" : "muted"}
                />
                {item.last_delivery_status && (
                  <StatusBadge
                    status={`Last: ${item.last_delivery_status}`}
                    tone={item.last_delivery_status === "delivered" ? "success" : "danger"}
                  />
                )}
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => test.mutate(item.id)}
                  disabled={test.isPending}
                >
                  <Send className="mr-1 h-3.5 w-3.5" /> Test
                </Button>
                <Button size="sm" variant="outline" onClick={() => toggle.mutate(item.id)}>
                  <Power className="h-3.5 w-3.5" />
                </Button>
                <Button size="sm" variant="destructive" onClick={() => remove.mutate(item.id)}>
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
