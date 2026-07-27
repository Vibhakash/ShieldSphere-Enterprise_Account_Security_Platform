import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban } from "lucide-react";
import { toast } from "sonner";

import { BlockIpDialog } from "@/components/block-ip-dialog";
import { EmptyState, ErrorState, fmtDate, LoadingBlock, PageHeader } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { api, ApiError } from "@/lib/api";
import type { IpBlocklistOut } from "@/lib/types";

export const Route = createFileRoute("/app/blocklist")({ component: BlocklistPage });

function BlocklistPage() {
  const queryClient = useQueryClient();
  const blocklist = useQuery<IpBlocklistOut[]>({
    queryKey: ["blocklist"],
    queryFn: () => api("/ip-blocklist"),
  });
  const unblock = useMutation({
    mutationFn: (id: string) => api(`/ip-blocklist/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast.success("IP unblocked");
      queryClient.invalidateQueries({ queryKey: ["blocklist"] });
      queryClient.invalidateQueries({ queryKey: ["dash"] });
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Failed to unblock IP"),
  });

  return (
    <>
      <PageHeader
        title="IP blocklist"
        description="Account blocks protect only your sign-in. Platform-wide blocks are managed by administrators and protect every account."
        actions={<BlockIpDialog triggerLabel="Block IP address" />}
      />
      {blocklist.isLoading ? (
        <LoadingBlock />
      ) : blocklist.error ? (
        <ErrorState description={(blocklist.error as Error).message} />
      ) : !blocklist.data?.length ? (
        <EmptyState
          title="No IPs are currently blocked."
          description="Use Block IP address to prevent a suspicious address from signing in to your account."
          icon={<Ban className="h-6 w-6" />}
        />
      ) : (
        <Card>
          <CardContent className="overflow-x-auto p-0">
            <table className="w-full min-w-[800px] text-sm">
              <thead className="text-left text-muted-foreground">
                <tr className="border-b border-border">
                  <th className="px-4 py-3">IP</th>
                  <th className="px-4 py-3">Reason</th>
                  <th className="px-4 py-3">Scope</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Blocked at</th>
                  <th className="px-4 py-3">Expires</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {blocklist.data.map((block) => (
                  <tr key={block.id} className="border-b border-border/50 last:border-0">
                    <td className="px-4 py-3 font-mono text-xs">{block.ip_address}</td>
                    <td className="px-4 py-3">{block.reason}</td>
                    <td className="px-4 py-3 capitalize">{block.scope}</td>
                    <td className="px-4 py-3">
                      {block.threat_type === "manual"
                        ? "Manual"
                        : block.auto_blocked
                          ? `Automatic${block.threat_type ? ` · ${block.threat_type}` : ""}`
                          : (block.threat_type ?? "Not specified")}
                    </td>
                    <td className="px-4 py-3">{fmtDate(block.blocked_at)}</td>
                    <td className="px-4 py-3">
                      {block.expires_at ? fmtDate(block.expires_at) : "Permanent"}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {block.can_unblock ? (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => unblock.mutate(block.id)}
                          disabled={unblock.isPending}
                        >
                          Unblock
                        </Button>
                      ) : (
                        <span className="text-xs text-muted-foreground">Administrator managed</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}
    </>
  );
}
