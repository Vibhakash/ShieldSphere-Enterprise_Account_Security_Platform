import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { SessionOut } from "@/lib/types";
import { PageHeader, LoadingBlock, ErrorState, EmptyState, fmtDate } from "@/components/common";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
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
import { LogOut, UsersRound } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/lib/auth";
import {
  SecurityLocationMap,
  type SecurityLocationMarker,
} from "@/components/security-location-map";

export const Route = createFileRoute("/app/sessions")({ component: SessionsPage });

function SessionsPage() {
  const qc = useQueryClient();
  const auth = useAuth();
  const navigate = useNavigate();
  const q = useQuery<SessionOut[]>({ queryKey: ["sessions"], queryFn: () => api("/sessions") });
  const mapMarkers: SecurityLocationMarker[] = (q.data ?? []).map((session, index) => ({
    id: session.id,
    latitude: session.latitude,
    longitude: session.longitude,
    location: locationLabel(session.city, session.country),
    title: `Active session ${index + 1}`,
    details: [
      { label: "IP address", value: session.ip_address ?? "Unknown" },
      { label: "Browser", value: session.user_agent ?? "Unknown" },
      { label: "Last used", value: fmtDate(session.last_used_at) },
      { label: "Expires", value: fmtDate(session.expires_at) },
    ],
  }));

  const revokeOne = useMutation({
    mutationFn: (id: string) => api(`/sessions/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast.success("Session revoked");
      qc.invalidateQueries({ queryKey: ["sessions"] });
      qc.invalidateQueries({ queryKey: ["dash"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });
  const revokeAll = useMutation({
    mutationFn: () => api(`/sessions`, { method: "DELETE" }),
    onSuccess: async () => {
      toast.success("All sessions revoked. Please sign in again.");
      await auth.logout();
      navigate({ to: "/auth" });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });

  return (
    <>
      <PageHeader
        title="Active sessions"
        description="Sessions currently signed into this account."
        actions={
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="destructive" size="sm" disabled={!q.data?.length}>
                <LogOut className="mr-1 h-4 w-4" /> Revoke all
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Revoke every session?</AlertDialogTitle>
                <AlertDialogDescription>
                  All active sessions — including this one — will be invalidated. You will be signed
                  out.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={() => revokeAll.mutate()}>Revoke all</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        }
      />
      {q.isLoading ? (
        <LoadingBlock />
      ) : q.error ? (
        <ErrorState description={(q.error as any).message} />
      ) : !q.data?.length ? (
        <EmptyState title="No active sessions found." icon={<UsersRound className="h-6 w-6" />} />
      ) : (
        <>
          <SecurityLocationMap
            title="Active session locations"
            description="Hover over a marker to see the sessions using that approximate IP location."
            markers={mapMarkers}
          />
          <div className="grid gap-3 md:grid-cols-2">
            {q.data.map((s) => (
              <Card key={s.id}>
                <CardContent className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-3 py-4">
                  <div className="min-w-0 space-y-1 text-sm">
                    <div className="truncate font-mono text-xs">{s.ip_address ?? "—"}</div>
                    <div className="break-words text-muted-foreground [overflow-wrap:anywhere]">
                      {s.user_agent ?? "Unknown agent"}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Location: {locationLabel(s.city, s.country)}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Last used {fmtDate(s.last_used_at)}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Expires {fmtDate(s.expires_at)}
                    </div>
                  </div>
                  <Button size="sm" variant="outline" onClick={() => revokeOne.mutate(s.id)}>
                    Revoke
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </>
      )}
    </>
  );
}

function locationLabel(city: string | null, country: string | null) {
  return [city, country].filter(Boolean).join(", ") || "Location unavailable";
}
