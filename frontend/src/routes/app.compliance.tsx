import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { AuditLogOut, IncidentReportOut } from "@/lib/types";
import { PageHeader, LoadingBlock, ErrorState, EmptyState, fmtDate } from "@/components/common";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Download, FileText, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";

/* ────────────────────────────────────────────────────────────────────────
   RichText — user-friendly rendering of AI markdown-style text.
   Supports: ## headings, **bold**, - bullets, numbered lists.
──────────────────────────────────────────────────────────────────────── */
function inlineParse(text: string): React.ReactNode[] {
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
        <ol key={elements.length} className="my-1.5 ml-5 space-y-1 list-decimal">
          {listItems.map((li, i) => (
            <li key={i} className="text-sm text-muted-foreground leading-relaxed">
              {inlineParse(li)}
            </li>
          ))}
        </ol>,
      );
    } else {
      elements.push(
        <ul key={elements.length} className="my-1.5 ml-5 space-y-1 list-disc">
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
    const hMatch = line.match(/^#{1,3}\s+(.+)/);
    if (hMatch) {
      flushList();
      elements.push(
        <p
          key={elements.length}
          className="mt-3 mb-0.5 text-xs font-bold uppercase tracking-wide text-primary"
        >
          {hMatch[1]}
        </p>,
      );
      continue;
    }
    const bullet = line.match(/^[-*]\s+(.+)/);
    if (bullet) {
      if (listType !== "ul") {
        flushList();
        listType = "ul";
      }
      listItems.push(bullet[1]);
      continue;
    }
    const num = line.match(/^\d+\.\s+(.+)/);
    if (num) {
      if (listType !== "ol") {
        flushList();
        listType = "ol";
      }
      listItems.push(num[1]);
      continue;
    }
    flushList();
    if (line.startsWith("**") && line.endsWith("**")) {
      elements.push(
        <p
          key={elements.length}
          className="mt-3 mb-0.5 text-xs font-bold uppercase tracking-wide text-primary"
        >
          {line.slice(2, -2)}
        </p>,
      );
      continue;
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

export const Route = createFileRoute("/app/compliance")({ component: CompliancePage });

function CompliancePage() {
  const qc = useQueryClient();
  const logs = useQuery<AuditLogOut[]>({
    queryKey: ["audit"],
    queryFn: () => api("/compliance/audit-logs", { query: { per_page: 100 } }),
  });
  const reports = useQuery<IncidentReportOut[]>({
    queryKey: ["reports"],
    queryFn: () => api("/reports"),
  });
  const [days, setDays] = useState(30);
  const [busy, setBusy] = useState(false);

  const generate = useMutation({
    mutationFn: () =>
      api<IncidentReportOut>("/reports/generate", { method: "POST", body: {}, query: { days } }),
    onSuccess: () => {
      toast.success("Report generated");
      qc.invalidateQueries({ queryKey: ["reports"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });

  async function downloadReportPdf(report: IncidentReportOut) {
    setBusy(true);
    try {
      const res = await api<Response>(`/reports/${report.id}/pdf`, { raw: true });
      if (!res.ok) {
        const contentType = res.headers.get("content-type") ?? "";
        const error = contentType.includes("application/json")
          ? (await res.json().catch(() => null))?.detail
          : await res.text().catch(() => "");
        throw new Error(error || `Could not generate the PDF (${res.status})`);
      }
      if (!res.headers.get("content-type")?.includes("application/pdf")) {
        throw new Error("The server did not return a PDF file. Please try again.");
      }
      const blob = await res.blob();
      const signature = await blob.slice(0, 4).text();
      if (signature !== "%PDF") {
        throw new Error("The downloaded file is not a valid PDF. Please try again.");
      }
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      const disposition = res.headers.get("content-disposition") ?? "";
      link.download =
        disposition.match(/filename="?([^";]+)"?/i)?.[1] ?? "shieldsphere_security_report.pdf";
      document.body.appendChild(link);
      link.click();
      // Keep the object URL alive briefly so browsers can finish writing the file.
      window.setTimeout(() => {
        URL.revokeObjectURL(url);
        link.remove();
      }, 1_000);
      toast.success("PDF report downloaded");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const deleteAuditLog = useMutation({
    mutationFn: (id: string) => api(`/compliance/audit-logs/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["audit"] });
      toast.success("Audit record deleted");
    },
    onError: (e) =>
      toast.error(e instanceof ApiError ? e.message : "Could not delete audit record"),
  });
  const clearAuditLogs = useMutation({
    mutationFn: () => api<{ deleted: number }>("/compliance/audit-logs", { method: "DELETE" }),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["audit"] });
      toast.success(`${result.deleted} audit record(s) deleted`);
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Could not clear audit log"),
  });

  async function exportGdpr() {
    setBusy(true);
    try {
      const res = await api<Response>("/compliance/gdpr-export", { raw: true });
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const disposition = res.headers.get("content-disposition") ?? "";
      const filename =
        disposition.match(/filename="?([^";]+)"?/i)?.[1] ?? "shieldsphere_gdpr_export.xlsx";
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("Export downloaded");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Compliance & reports"
        description="Audit logs, GDPR export, and AI-generated executive reports."
        actions={
          <Button size="sm" variant="outline" onClick={exportGdpr} disabled={busy}>
            <Download className="mr-1 h-4 w-4" /> GDPR Excel export
          </Button>
        }
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2">
            <CardTitle>Executive reports</CardTitle>
            <div className="flex items-center gap-2">
              <select
                className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
              >
                <option value={7}>Last 7 days</option>
                <option value={30}>Last 30 days</option>
                <option value={90}>Last 90 days</option>
              </select>
              <Button size="sm" onClick={() => generate.mutate()} disabled={generate.isPending}>
                <RefreshCw className="mr-1 h-4 w-4" /> Generate
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {reports.isLoading ? (
              <LoadingBlock />
            ) : reports.error ? (
              <ErrorState description={(reports.error as any).message} />
            ) : !reports.data?.length ? (
              <EmptyState title="No reports yet." icon={<FileText className="h-6 w-6" />} />
            ) : (
              <ul className="space-y-3">
                {reports.data.map((r) => (
                  <li key={r.id} className="rounded-md border border-border p-3 text-sm">
                    <div className="flex items-center justify-between gap-2">
                      <div className="truncate font-semibold">{r.title}</div>
                      <span className="text-xs text-muted-foreground">
                        {fmtDate(r.generated_at)}
                      </span>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
                      <span>
                        {fmtDate(r.period_start)} → {fmtDate(r.period_end)} · {r.threat_count ?? 0}{" "}
                        threats
                      </span>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => downloadReportPdf(r)}
                        disabled={busy}
                      >
                        <Download className="mr-1 h-3.5 w-3.5" /> PDF
                      </Button>
                    </div>
                    {r.executive_summary && (
                      <div className="mt-2">
                        <RichText text={r.executive_summary} />
                      </div>
                    )}
                    {r.recommendations && (
                      <details className="mt-2">
                        <summary className="cursor-pointer text-xs text-primary font-semibold">
                          Recommendations
                        </summary>
                        <div className="mt-2">
                          <RichText text={r.recommendations} />
                        </div>
                      </details>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2">
            <CardTitle>Audit log</CardTitle>
            <Button
              size="sm"
              variant="outline"
              className="text-destructive hover:text-destructive"
              disabled={!logs.data?.length || clearAuditLogs.isPending}
              onClick={() => {
                if (window.confirm("Delete all audit log records? This cannot be undone.")) {
                  clearAuditLogs.mutate();
                }
              }}
            >
              <Trash2 className="mr-1 h-4 w-4" /> Clear audit log
            </Button>
          </CardHeader>
          <CardContent>
            {logs.isLoading ? (
              <LoadingBlock />
            ) : logs.error ? (
              <ErrorState description={(logs.error as any).message} />
            ) : !logs.data?.length ? (
              <EmptyState title="No audit entries yet." />
            ) : (
              <div className="max-h-[520px] overflow-y-auto">
                <table className="w-full min-w-[520px] text-sm">
                  <thead className="sticky top-0 bg-card text-left text-muted-foreground">
                    <tr className="border-b border-border">
                      <th className="px-2 py-2">When</th>
                      <th className="px-2 py-2">Action</th>
                      <th className="px-2 py-2">Resource</th>
                      <th className="px-2 py-2">IP</th>
                      <th className="px-2 py-2">Status</th>
                      <th className="px-2 py-2">
                        <span className="sr-only">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.data.map((l) => (
                      <tr key={l.id} className="border-b border-border/50 last:border-0">
                        <td className="whitespace-nowrap px-2 py-2 text-xs text-muted-foreground">
                          {fmtDate(l.timestamp)}
                        </td>
                        <td className="px-2 py-2 font-mono text-xs">{l.action}</td>
                        <td className="px-2 py-2 font-mono text-xs">{l.resource ?? "—"}</td>
                        <td className="px-2 py-2 font-mono text-xs">{l.ip_address ?? "—"}</td>
                        <td className="px-2 py-2 text-xs">{l.status}</td>
                        <td className="px-2 py-2 text-right">
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-7 w-7 text-muted-foreground hover:text-destructive"
                            aria-label={`Delete audit record ${l.action}`}
                            disabled={deleteAuditLog.isPending}
                            onClick={() => {
                              if (
                                window.confirm("Delete this audit record? This cannot be undone.")
                              ) {
                                deleteAuditLog.mutate(l.id);
                              }
                            }}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
