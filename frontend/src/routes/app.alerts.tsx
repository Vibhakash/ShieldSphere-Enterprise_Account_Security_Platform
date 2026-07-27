import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { AlertOut } from "@/lib/types";
import {
  PageHeader,
  LoadingBlock,
  ErrorState,
  EmptyState,
  SeverityBadge,
  fmtRelative,
} from "@/components/common";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { BlockIpDialog } from "@/components/block-ip-dialog";
import { Bell, CheckCheck, MailOpen } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/app/alerts")({ component: AlertsPage });

function AlertsPage() {
  const qc = useQueryClient();
  const q = useQuery<{ total: number; unread_count: number; items: AlertOut[] }>({
    queryKey: ["alerts"],
    queryFn: () => api("/alerts"),
  });
  const readOne = useMutation({
    mutationFn: (id: string) => api(`/alerts/${id}/read`, { method: "PATCH", body: {} }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["alerts"] }),
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });
  const readAll = useMutation({
    mutationFn: () => api(`/alerts/read-all`, { method: "PATCH", body: {} }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["dash"] });
      toast.success("All alerts marked read");
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });

  return (
    <>
      <PageHeader
        title="Alerts"
        description={q.data ? `${q.data.unread_count} unread of ${q.data.total} total.` : undefined}
        actions={
          <Button
            size="sm"
            variant="outline"
            onClick={() => readAll.mutate()}
            disabled={!q.data?.unread_count}
          >
            <CheckCheck className="mr-1 h-4 w-4" /> Mark all read
          </Button>
        }
      />
      {q.isLoading ? (
        <LoadingBlock />
      ) : q.error ? (
        <ErrorState description={(q.error as any).message} />
      ) : !q.data?.items?.length ? (
        <EmptyState title="No alerts yet." icon={<Bell className="h-6 w-6" />} />
      ) : (
        <div className="space-y-2">
          {q.data.items.map((a) => (
            <Card key={a.id} className={a.is_read ? "opacity-70" : "border-primary/40"}>
              <CardContent className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-3 py-4">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={a.severity} />
                    {a.is_simulation && (
                      <span className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary">
                        Sandbox
                      </span>
                    )}
                    <div className="truncate font-semibold">{a.title}</div>
                    {!a.is_read && <span className="h-1.5 w-1.5 rounded-full bg-primary" />}
                  </div>
                  <p className="mt-1 text-sm text-muted-foreground">{a.message}</p>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {fmtRelative(a.created_at)}
                    {a.source_ip && <span className="ml-2 font-mono">Source: {a.source_ip}</span>}
                  </div>
                </div>
                <div className="flex flex-wrap justify-end gap-2">
                  {a.source_ip && !a.is_simulation && (
                    <BlockIpDialog
                      ipAddress={a.source_ip}
                      defaultReason={`Security alert: ${a.title}`}
                    />
                  )}
                  {!a.is_read && (
                    <Button size="sm" variant="ghost" onClick={() => readOne.mutate(a.id)}>
                      <MailOpen className="mr-1 h-4 w-4" /> Read
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}
