import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { ThreatOut } from "@/lib/types";
import {
  PageHeader,
  LoadingBlock,
  ErrorState,
  EmptyState,
  SeverityBadge,
  fmtDate,
} from "@/components/common";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { BlockIpDialog } from "@/components/block-ip-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { CheckCircle2, Radar } from "lucide-react";

/* ────────────────────────────────────────────────────────────────────────
   RichText — renders simple markdown-like AI text in a user-friendly way.
   Supports: ## headings, **bold**, - / * bullet lists, numbered lists.
──────────────────────────────────────────────────────────────────────── */
function inlineParse(text: string): React.ReactNode[] {
  // Replace **bold** with <strong>
  const parts = text.split(/(\*\*[^*]+\*\*)/);
  return parts.map((p, i) => {
    if (p.startsWith("**") && p.endsWith("**")) {
      return (
        <strong key={i} className="font-semibold text-foreground">
          {p.slice(2, -2)}
        </strong>
      );
    }
    return <span key={i}>{p}</span>;
  });
}

function RichText({ text }: { text: string }) {
  const lines = text.split("\n");
  const elements: React.ReactNode[] = [];
  let listItems: string[] = [];
  let listType: "ul" | "ol" | null = null;

  const flushList = () => {
    if (listItems.length === 0) return;
    if (listType === "ol") {
      elements.push(
        <ol key={elements.length} className="my-2 ml-5 space-y-1 list-decimal">
          {listItems.map((li, i) => (
            <li key={i} className="text-sm text-muted-foreground leading-relaxed">
              {inlineParse(li)}
            </li>
          ))}
        </ol>,
      );
    } else {
      elements.push(
        <ul key={elements.length} className="my-2 ml-5 space-y-1 list-disc">
          {listItems.map((li, i) => (
            <li key={i} className="text-sm text-muted-foreground leading-relaxed">
              {inlineParse(li)}
            </li>
          ))}
        </ul>,
      );
    }
    listItems = [];
    listType = null;
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (!line) {
      flushList();
      continue;
    }
    // ## / ### heading
    const h3Match = line.match(/^###\s+(.+)/);
    const h2Match = line.match(/^##\s+(.+)/);
    const h1Match = line.match(/^#\s+(.+)/);
    if (h1Match || h2Match || h3Match) {
      flushList();
      const heading = (h1Match || h2Match || h3Match)![1];
      elements.push(
        <p
          key={elements.length}
          className="mt-4 mb-1 text-xs font-bold uppercase tracking-wide text-primary"
        >
          {heading}
        </p>,
      );
      continue;
    }
    // Bullet: - or *
    const bulletMatch = line.match(/^[-*]\s+(.+)/);
    if (bulletMatch) {
      if (listType !== "ul") {
        flushList();
        listType = "ul";
      }
      listItems.push(bulletMatch[1]);
      continue;
    }
    // Numbered list: 1. 2. etc.
    const numMatch = line.match(/^\d+\.\s+(.+)/);
    if (numMatch) {
      if (listType !== "ol") {
        flushList();
        listType = "ol";
      }
      listItems.push(numMatch[1]);
      continue;
    }
    // Plain paragraph
    flushList();
    // Skip lines that are just "**Security Analysis Report**" style header-only lines
    const cleanLine = line.replace(/^\*\*(.+)\*\*$/, "$1");
    if (cleanLine === line.replace(/\*\*/g, "")) {
      // has bold markers — render as a section heading
      if (line.startsWith("**") && line.endsWith("**")) {
        elements.push(
          <p
            key={elements.length}
            className="mt-3 mb-1 text-xs font-bold uppercase tracking-wide text-primary"
          >
            {cleanLine}
          </p>,
        );
        continue;
      }
    }
    elements.push(
      <p key={elements.length} className="text-sm text-muted-foreground leading-relaxed">
        {inlineParse(line)}
      </p>,
    );
  }
  flushList();
  return <div className="space-y-0.5">{elements}</div>;
}

/* Details key-value renderer */
function DetailsView({ data }: { data: Record<string, unknown> }) {
  return (
    <div className="grid grid-cols-2 gap-2">
      {Object.entries(data).map(([k, v]) => (
        <div key={k} className="rounded-md border border-border bg-muted/40 p-2">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
            {k.replace(/_/g, " ")}
          </div>
          <div className="mt-0.5 text-xs font-mono break-all">
            {typeof v === "object" ? JSON.stringify(v) : String(v ?? "—")}
          </div>
        </div>
      ))}
    </div>
  );
}

export const Route = createFileRoute("/app/threats")({ component: ThreatsPage });

function ThreatsPage() {
  const qc = useQueryClient();
  const [severity, setSeverity] = useState<string>("all");
  const [resolved, setResolved] = useState<string>("all");
  const [includeSim, setIncludeSim] = useState(true);
  const [selected, setSelected] = useState<ThreatOut | null>(null);

  const q = useQuery<{ total: number; page: number; per_page: number; items: ThreatOut[] }>({
    queryKey: ["threats", severity, resolved, includeSim],
    queryFn: () =>
      api("/threats", {
        query: {
          page: 1,
          per_page: 50,
          severity: severity === "all" ? undefined : severity,
          is_resolved: resolved === "all" ? undefined : resolved === "resolved" ? true : false,
          include_simulation: includeSim,
        },
      }),
  });

  const resolve = useMutation({
    mutationFn: (id: string) => api(`/threats/${id}/resolve`, { method: "PATCH", body: {} }),
    onSuccess: () => {
      toast.success("Threat resolved");
      qc.invalidateQueries({ queryKey: ["threats"] });
      qc.invalidateQueries({ queryKey: ["dash"] });
      setSelected(null);
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed to resolve"),
  });

  return (
    <>
      <PageHeader
        title="Threats"
        description="Backend-detected security threats. Sandbox detections are labelled so exercises stay separate from real incidents."
      />
      <Card className="mb-4">
        <CardContent className="flex flex-wrap items-center gap-3 py-4">
          <div>
            <Label className="mb-1 block text-xs">Severity</Label>
            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="mb-1 block text-xs">Status</Label>
            <Select value={resolved} onValueChange={setResolved}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="unresolved">Unresolved</SelectItem>
                <SelectItem value="resolved">Resolved</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <Switch id="sim" checked={includeSim} onCheckedChange={setIncludeSim} />
            <Label htmlFor="sim" className="text-sm">
              Include simulator-generated
            </Label>
          </div>
        </CardContent>
      </Card>

      {q.isLoading ? (
        <LoadingBlock />
      ) : q.error ? (
        <ErrorState description={(q.error as any).message} />
      ) : !q.data?.items?.length ? (
        <EmptyState title="No threats recorded yet." icon={<Radar className="h-6 w-6" />} />
      ) : (
        <Card>
          <CardContent className="overflow-x-auto p-0">
            <table className="w-full min-w-[720px] text-sm">
              <thead className="text-left text-muted-foreground">
                <tr className="border-b border-border">
                  <th className="px-4 py-3">Detected</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Title</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {q.data.items.map((t) => (
                  <tr
                    key={t.id}
                    className="border-b border-border/50 last:border-0 hover:bg-muted/40 cursor-pointer"
                    onClick={() => setSelected(t)}
                  >
                    <td className="px-4 py-3">{fmtDate(t.detected_at)}</td>
                    <td className="px-4 py-3 font-mono text-xs">{t.threat_type}</td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={t.severity} />
                    </td>
                    <td className="px-4 py-3">{t.title}</td>
                    <td className="px-4 py-3 font-mono text-xs">
                      {t.source_ip ?? "—"}
                      {t.source_country ? ` · ${t.source_country}` : ""}
                    </td>
                    <td className="px-4 py-3">
                      {t.is_resolved ? (
                        <span className="text-success">Resolved</span>
                      ) : (
                        <span className="text-warning">Open</span>
                      )}
                      {t.auto_blocked && (
                        <span className="ml-1 text-xs text-muted-foreground">(auto-blocked)</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-2">
                        {t.source_ip && !t.is_simulation && !t.auto_blocked && (
                          <BlockIpDialog
                            ipAddress={t.source_ip}
                            defaultReason={`Threat detected: ${t.title}`}
                          />
                        )}
                        {!t.is_resolved && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={(e) => {
                              e.stopPropagation();
                              resolve.mutate(t.id);
                            }}
                          >
                            <CheckCircle2 className="mr-1 h-3.5 w-3.5" /> Resolve
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      <Dialog open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <DialogContent className="max-w-2xl flex flex-col" style={{ maxHeight: "90vh" }}>
          {selected && (
            <>
              <DialogHeader className="shrink-0">
                <DialogTitle className="flex items-center gap-2">
                  <SeverityBadge severity={selected.severity} />
                  {selected.title}
                </DialogTitle>
              </DialogHeader>
              <div className="space-y-3 text-sm overflow-y-auto pr-1 flex-1 min-h-0 py-1">
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <Info label="Type" value={selected.threat_type} />
                  <Info label="Detected" value={fmtDate(selected.detected_at)} />
                  <Info label="Source IP" value={selected.source_ip ?? "—"} />
                  <Info label="Country" value={selected.source_country ?? "—"} />
                  <Info label="Risk score" value={selected.risk_score?.toString() ?? "—"} />
                  <Info label="Auto-blocked" value={selected.auto_blocked ? "yes" : "no"} />
                </div>
                {selected.description && (
                  <p className="text-muted-foreground">{selected.description}</p>
                )}
                {selected.llm_rca && (
                  <section className="rounded-lg border border-primary/20 bg-primary/5 p-3">
                    <h3 className="mb-2 flex items-center gap-1.5 text-xs font-bold uppercase tracking-wide text-primary">
                      <span className="inline-block h-1.5 w-1.5 rounded-full bg-primary" />
                      Root Cause Analysis (AI)
                    </h3>
                    <RichText text={selected.llm_rca} />
                  </section>
                )}
                {selected.llm_remediation && (
                  <section className="rounded-lg border border-accent/20 bg-accent/5 p-3">
                    <h3 className="mb-2 flex items-center gap-1.5 text-xs font-bold uppercase tracking-wide text-accent">
                      <span className="inline-block h-1.5 w-1.5 rounded-full bg-accent" />
                      Remediation Steps (AI)
                    </h3>
                    <RichText text={selected.llm_remediation} />
                  </section>
                )}
                {selected.details && typeof selected.details === "object" && (
                  <section>
                    <h3 className="mb-2 text-xs font-bold uppercase tracking-wide text-muted-foreground">
                      Additional Details
                    </h3>
                    <DetailsView data={selected.details as Record<string, unknown>} />
                  </section>
                )}
                {!selected.is_resolved && (
                  <div className="flex justify-end pt-1">
                    <Button
                      onClick={() => resolve.mutate(selected.id)}
                      disabled={resolve.isPending}
                    >
                      <CheckCircle2 className="mr-1 h-4 w-4" /> Mark as resolved
                    </Button>
                  </div>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-muted/40 p-2">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="font-mono">{value}</div>
    </div>
  );
}
