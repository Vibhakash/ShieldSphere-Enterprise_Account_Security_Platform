import { createFileRoute, Outlet, useNavigate, Link, useLocation } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import {
  Activity,
  Radar,
  Bell,
  Users,
  Fingerprint,
  Ban,
  Bug,
  Bot,
  Eye,
  Terminal,
  FileSearch,
  Settings,
  Menu,
  LogOut,
  Shield,
  ChevronsLeft,
  ChevronsRight,
} from "lucide-react";
import { ThemeToggle } from "@/components/ThemeToggle";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/app")({
  component: AppLayout,
});

const NAV: { to: string; label: string; icon: any }[] = [
  { to: "/app/dashboard", label: "Dashboard", icon: Activity },
  { to: "/app/threats", label: "Threats", icon: Radar },
  { to: "/app/alerts", label: "Alerts", icon: Bell },
  { to: "/app/sessions", label: "Sessions", icon: Users },
  { to: "/app/devices", label: "Devices", icon: Fingerprint },
  { to: "/app/blocklist", label: "IP Blocklist", icon: Ban },
  { to: "/app/assessments", label: "Assessments", icon: Bug },
  { to: "/app/copilot", label: "AI Copilot", icon: Bot },
  { to: "/app/uba", label: "Behavior (UBA)", icon: Eye },
  { to: "/app/simulator", label: "Simulator", icon: Terminal },
  { to: "/app/compliance", label: "Compliance", icon: FileSearch },
  { to: "/app/settings", label: "Settings", icon: Settings },
];

function AppLayout() {
  const auth = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    if (!auth.loading && !auth.isAuthenticated) {
      navigate({ to: "/auth", search: { redirect: location.pathname } as any });
    }
  }, [auth.loading, auth.isAuthenticated, navigate, location.pathname]);

  if (auth.loading || !auth.isAuthenticated) {
    return (
      <div className="grid min-h-screen place-items-center bg-background">
        <div className="flex items-center gap-3 text-muted-foreground">
          <Shield className="h-5 w-5 animate-shield-pulse text-primary" />
          Loading your security console…
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-background">
      {/* Sidebar */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex flex-col border-r border-border bg-sidebar text-sidebar-foreground transition-all",
          collapsed ? "w-16" : "w-64",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
          "lg:translate-x-0",
        )}
      >
        <div className="flex h-16 items-center justify-between px-3">
          <Link to="/app/dashboard" className="flex min-w-0 items-center gap-2 font-bold">
            <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-primary/15 text-primary">
              <Shield className="h-5 w-5" />
            </span>
            {!collapsed && <span className="truncate">ShieldSphere</span>}
          </Link>
          <Button
            variant="ghost"
            size="icon"
            className="hidden lg:inline-flex"
            onClick={() => setCollapsed((c) => !c)}
          >
            {collapsed ? (
              <ChevronsRight className="h-4 w-4" />
            ) : (
              <ChevronsLeft className="h-4 w-4" />
            )}
          </Button>
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto p-2">
          {NAV.map((n) => (
            <Link
              key={n.to}
              to={n.to}
              onClick={() => setMobileOpen(false)}
              className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-sidebar-foreground/80 transition hover:bg-sidebar-accent hover:text-sidebar-accent-foreground data-[status=active]:bg-primary/10 data-[status=active]:text-primary data-[status=active]:font-semibold"
              activeProps={{ "data-status": "active" } as any}
            >
              <n.icon className="h-4 w-4 shrink-0" />
              {!collapsed && <span className="truncate">{n.label}</span>}
            </Link>
          ))}
        </nav>
        <div className="border-t border-border p-2">
          <button
            onClick={async () => {
              await auth.logout();
              navigate({ to: "/auth" });
            }}
            className="mt-1 flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-sidebar-foreground/80 hover:bg-destructive/10 hover:text-destructive"
          >
            <LogOut className="h-4 w-4" />
            {!collapsed && "Sign out"}
          </button>
        </div>
      </aside>

      {/* Main */}
      <div className={cn("flex min-h-screen flex-1 flex-col", collapsed ? "lg:pl-16" : "lg:pl-64")}>
        <TopBar onMenu={() => setMobileOpen((o) => !o)} />
        <main className="flex-1">
          <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
            <Outlet />
          </div>
        </main>
      </div>

      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/40 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}
    </div>
  );
}

function TopBar({ onMenu }: { onMenu: () => void }) {
  const { user } = useAuth();
  const loc = useLocation();
  const current = NAV.find((n) => loc.pathname.startsWith(n.to));
  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-border bg-background/80 px-4 backdrop-blur-xl sm:px-6">
      <Button variant="ghost" size="icon" className="lg:hidden" onClick={onMenu}>
        <Menu className="h-5 w-5" />
      </Button>
      <div className="min-w-0 flex-1">
        <div className="text-xs text-muted-foreground">ShieldSphere</div>
        <div className="truncate font-semibold">{current?.label ?? "Console"}</div>
      </div>
      <ThemeToggle />
      <div className="hidden items-center gap-2 rounded-full border border-border bg-card px-3 py-1.5 text-sm sm:flex">
        <span className="grid h-6 w-6 place-items-center rounded-full bg-primary/15 text-primary text-xs font-bold">
          {(user?.username?.[0] ?? "?").toUpperCase()}
        </span>
        <span className="max-w-[140px] truncate">{user?.username}</span>
      </div>
    </header>
  );
}
