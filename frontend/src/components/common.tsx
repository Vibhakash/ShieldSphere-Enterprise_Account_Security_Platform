import { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 grid gap-3 grid-cols-[minmax(0,1fr)_auto] items-start">
      <div className="min-w-0">
        <h1 className="truncate text-2xl font-bold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  icon,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
}) {
  return (
    <Card className="border-dashed">
      <CardContent className="flex flex-col items-center justify-center gap-2 py-14 text-center">
        {icon && <div className="mb-1 text-muted-foreground">{icon}</div>}
        <div className="font-medium">{title}</div>
        {description && <p className="max-w-sm text-sm text-muted-foreground">{description}</p>}
      </CardContent>
    </Card>
  );
}

export function ErrorState({
  title = "Something went wrong",
  description,
}: {
  title?: string;
  description?: string;
}) {
  return (
    <Card className="border-destructive/40 bg-destructive/5">
      <CardContent className="py-8 text-center">
        <div className="font-semibold text-destructive">{title}</div>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </CardContent>
    </Card>
  );
}

export function LoadingBlock({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
      <Loader2 className="h-4 w-4 animate-spin" />
      {label}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toLowerCase();
  const cls =
    s === "critical"
      ? "bg-destructive text-destructive-foreground"
      : s === "high"
        ? "bg-destructive/85 text-destructive-foreground"
        : s === "medium"
          ? "bg-warning/80 text-black"
          : s === "low"
            ? "bg-primary/15 text-primary"
            : "bg-muted text-muted-foreground";
  return (
    <span
      className={cn("inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold", cls)}
    >
      {severity ?? "unknown"}
    </span>
  );
}

export function StatusBadge({
  status,
  tone,
}: {
  status: string;
  tone?: "success" | "warn" | "danger" | "muted" | "primary";
}) {
  const map: Record<string, string> = {
    success: "bg-success/15 text-success border-success/30",
    warn: "bg-warning/15 text-warning border-warning/30",
    danger: "bg-destructive/15 text-destructive border-destructive/30",
    muted: "bg-muted text-muted-foreground border-border",
    primary: "bg-primary/15 text-primary border-primary/30",
  };
  const cls = map[tone ?? "muted"];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
        cls,
      )}
    >
      {status}
    </span>
  );
}

export { Badge };

export function statusTone(s: string): "success" | "warn" | "danger" | "muted" | "primary" {
  const v = s?.toLowerCase();
  if (["completed", "done", "success", "resolved"].includes(v)) return "success";
  if (["running", "pending", "queued"].includes(v)) return "warn";
  if (["error", "failed", "timeout", "cancelled"].includes(v)) return "danger";
  return "primary";
}

export function fmtDate(v: string | null | undefined) {
  if (!v) return "—";
  try {
    const d = new Date(v);
    return d.toLocaleString();
  } catch {
    return v;
  }
}

export function fmtRelative(v: string | null | undefined) {
  if (!v) return "—";
  const d = new Date(v).getTime();
  const now = Date.now();
  const diff = Math.max(0, now - d);
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const days = Math.floor(h / 24);
  return `${days}d ago`;
}
