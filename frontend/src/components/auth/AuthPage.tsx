import { useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { toast } from "sonner";
import {
  Shield,
  Lock,
  Radar,
  Bot,
  Eye,
  ShieldCheck,
  Fingerprint,
  Zap,
  ArrowLeft,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useAuth } from "@/lib/auth";
import { api, ApiError, tokenStore } from "@/lib/api";
import { ThemeToggle } from "@/components/ThemeToggle";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import type { TokenResponse } from "@/lib/types";
import { browserSupportsWebAuthn, startAuthentication } from "@simplewebauthn/browser";

export function AuthPage() {
  const search = useSearch({ from: "/auth" });
  const navigate = useNavigate();
  const auth = useAuth();
  const [tab, setTab] = useState<"login" | "register">(search.mode ?? "login");
  const [tempToken, setTempToken] = useState<string | null>(null);

  // Only redirect if user just authenticated (not on initial mount when already logged in)
  // This ensures branding page is always the entry point when opening the website

  return (
    <div className="min-h-screen bg-cyber-radial grid lg:grid-cols-2">
      {/* Left visual */}
      <div className="relative hidden overflow-hidden bg-card/40 lg:block">
        <div className="absolute inset-0 bg-grid opacity-40 [mask-image:radial-gradient(ellipse_at_center,black_30%,transparent_75%)]" />
        <div className="relative flex h-full flex-col justify-between p-10">
          <Link to="/" className="flex w-fit items-center gap-2 font-bold">
            <span className="grid h-9 w-9 place-items-center rounded-lg bg-primary/15 text-primary">
              <Shield className="h-5 w-5" />
            </span>
            <span className="text-lg">ShieldSphere</span>
          </Link>
          <div className="relative mx-auto flex aspect-square w-full max-w-md items-center justify-center">
            <div className="absolute h-full w-full rounded-full border border-primary/20 animate-rotate-slow" />
            <div
              className="absolute h-[80%] w-[80%] rounded-full border border-accent/25 animate-rotate-slow"
              style={{ animationDirection: "reverse", animationDuration: "16s" }}
            />
            <div
              className="absolute h-[60%] w-[60%] rounded-full border border-cyber/35 animate-rotate-slow"
              style={{ animationDuration: "10s" }}
            />
            <div className="relative grid h-32 w-32 place-items-center rounded-3xl border border-primary/40 bg-background/60 backdrop-blur-lg animate-shield-pulse glow-primary">
              <Shield className="h-14 w-14 text-primary" strokeWidth={1.5} />
            </div>
            {[
              {
                icon: Radar,
                cls: "top-2 left-2 animate-float-slow",
                tone: "text-destructive border-destructive/40",
                label: "Threats",
              },
              {
                icon: Bot,
                cls: "top-8 right-0 animate-float-fast",
                tone: "text-accent border-accent/40",
                label: "AI Copilot",
              },
              {
                icon: Eye,
                cls: "bottom-4 left-4 animate-float-fast",
                tone: "text-cyber border-cyber/50",
                label: "UBA",
              },
              {
                icon: Fingerprint,
                cls: "bottom-10 right-4 animate-float-slow",
                tone: "text-primary border-primary/40",
                label: "Trusted",
              },
              {
                icon: ShieldCheck,
                cls: "top-1/2 -left-2 animate-float-slow",
                tone: "text-success border-success/40",
                label: "2FA",
              },
              {
                icon: Zap,
                cls: "top-1/3 -right-2 animate-float-fast",
                tone: "text-warning border-warning/40",
                label: "Live",
              },
            ].map((c, i) => (
              <div
                key={i}
                className={`absolute flex items-center gap-1.5 rounded-full border ${c.tone} bg-card/80 px-2.5 py-1 text-[11px] font-medium backdrop-blur ${c.cls}`}
              >
                <c.icon className="h-3 w-3" />
                {c.label}
              </div>
            ))}
          </div>
          <div className="space-y-2">
            <blockquote className="text-lg font-medium text-foreground">
              "See attacks land. Act in one click."
            </blockquote>
            <p className="text-sm text-muted-foreground">
              Threats, sessions, scans, AI copilot, and safe attack rehearsals — in one
              authenticated command center.
            </p>
          </div>
        </div>
      </div>

      {/* Right form */}
      <div className="relative flex flex-col">
        <div className="flex items-center justify-between p-4 sm:p-6">
          {/* Back to home — visible on ALL screen sizes */}
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-1.5 text-sm font-medium text-foreground transition-all hover:bg-accent/10 hover:border-primary/30 hover:text-primary"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Back to Home
          </Link>
          <div className="ml-auto flex items-center gap-2">
            {auth.isAuthenticated && (
              <Link
                to="/app/dashboard"
                className="text-sm text-primary hover:text-primary/80 font-medium transition-colors"
              >
                Go to Console →
              </Link>
            )}
            <ThemeToggle />
          </div>
        </div>
        <div className="flex flex-1 items-center justify-center p-4 sm:p-6">
          <div className="w-full max-w-md">
            {tempToken ? (
              <TwoFactorForm
                tempToken={tempToken}
                onCancel={() => setTempToken(null)}
                onSuccess={() => navigate({ to: "/app/dashboard" })}
              />
            ) : (
              <>
                <div className="mb-6">
                  <h1 className="text-2xl font-bold">Welcome to ShieldSphere</h1>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Sign in or create your enterprise security account.
                  </p>
                </div>
                <Tabs value={tab} onValueChange={(v) => setTab(v as any)}>
                  <TabsList className="grid w-full grid-cols-2">
                    <TabsTrigger value="login">Sign in</TabsTrigger>
                    <TabsTrigger value="register">Create account</TabsTrigger>
                  </TabsList>
                  <TabsContent value="login" className="mt-6">
                    <LoginForm
                      onNeed2fa={(tok) => setTempToken(tok)}
                      onSuccess={() => navigate({ to: search.redirect ?? "/app/dashboard" })}
                    />
                  </TabsContent>
                  <TabsContent value="register" className="mt-6">
                    <RegisterForm
                      onDone={() => {
                        setTab("login");
                        toast.success("Account created. Please sign in.");
                      }}
                    />
                  </TabsContent>
                </Tabs>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function LoginForm({
  onNeed2fa,
  onSuccess,
}: {
  onNeed2fa: (t: string) => void;
  onSuccess: () => void;
}) {
  const auth = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const t = await auth.login(email, password);
      if (t.requires_2fa) {
        tokenStore.clear();
        onNeed2fa(t.access_token);
      } else {
        toast.success("Signed in");
        onSuccess();
      }
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Sign-in failed");
    } finally {
      setLoading(false);
    }
  };

  const passkeySignIn = async () => {
    setLoading(true);
    try {
      if (!browserSupportsWebAuthn()) throw new Error("This browser does not support passkeys");
      const begin = await api<{ ceremony_id: string; options: any }>(
        "/auth/passkeys/login/options",
        {
          method: "POST",
          body: {},
          auth: false,
        },
      );
      const credential = await startAuthentication({ optionsJSON: begin.options });
      const tokens = await api<TokenResponse>("/auth/passkeys/login/verify", {
        body: { ceremony_id: begin.ceremony_id, credential },
        auth: false,
      });
      await auth.setSession(tokens);
      toast.success("Signed in with passkey");
      onSuccess();
    } catch (e) {
      toast.error(
        e instanceof ApiError
          ? e.message
          : e instanceof Error
            ? e.message
            : "Passkey sign-in failed",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="email"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="pw">Password</Label>
        <Input
          id="pw"
          type="password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
        />
      </div>
      <Button type="submit" className="w-full" disabled={loading}>
        <Lock className="mr-2 h-4 w-4" /> {loading ? "Signing in…" : "Sign in"}
      </Button>
      <div className="relative py-1 text-center text-xs text-muted-foreground before:absolute before:left-0 before:right-0 before:top-1/2 before:border-t before:border-border">
        <span className="relative bg-background px-2">or</span>
      </div>
      <Button
        type="button"
        variant="outline"
        className="w-full"
        disabled={loading}
        onClick={passkeySignIn}
      >
        <Fingerprint className="mr-2 h-4 w-4" /> Sign in with a passkey
      </Button>
    </form>
  );
}

function RegisterForm({ onDone }: { onDone: () => void }) {
  const { register } = useAuth();
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await register({ email, username, password, full_name: fullName || undefined });
      onDone();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="rn">Full name (optional)</Label>
        <Input
          id="rn"
          value={fullName}
          onChange={(e) => setFullName(e.target.value)}
          autoComplete="name"
        />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-2">
          <Label htmlFor="ru">Username</Label>
          <Input
            id="ru"
            required
            minLength={3}
            maxLength={30}
            pattern="[A-Za-z0-9_]+"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="re">Email</Label>
          <Input
            id="re"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
          />
        </div>
      </div>
      <div className="space-y-2">
        <Label htmlFor="rp">Password</Label>
        <Input
          id="rp"
          type="password"
          minLength={8}
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
        />
        <p className="text-xs text-muted-foreground">
          Minimum 8 characters. Checked against known breaches (HIBP).
        </p>
      </div>
      <Button type="submit" className="w-full" disabled={loading}>
        {loading ? "Creating…" : "Create account"}
      </Button>
    </form>
  );
}

function TwoFactorForm({
  tempToken,
  onCancel,
  onSuccess,
}: {
  tempToken: string;
  onCancel: () => void;
  onSuccess: () => void;
}) {
  const { complete2fa } = useAuth();
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (code.length < 6) return;
    setLoading(true);
    try {
      await complete2fa(code, tempToken);
      toast.success("Signed in");
      onSuccess();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Invalid code");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold">Two-factor authentication</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Enter the 6-digit code from your authenticator app.
        </p>
      </div>
      <div className="flex justify-center">
        <InputOTP maxLength={6} value={code} onChange={setCode}>
          <InputOTPGroup>
            {[0, 1, 2, 3, 4, 5].map((i) => (
              <InputOTPSlot key={i} index={i} />
            ))}
          </InputOTPGroup>
        </InputOTP>
      </div>
      <div className="flex gap-2">
        <Button type="button" variant="outline" className="flex-1" onClick={onCancel}>
          Back
        </Button>
        <Button type="submit" className="flex-1" disabled={loading || code.length < 6}>
          {loading ? "Verifying…" : "Verify"}
        </Button>
      </div>
    </form>
  );
}
