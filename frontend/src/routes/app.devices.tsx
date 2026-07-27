import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { DeviceOut } from "@/lib/types";
import { PageHeader, LoadingBlock, ErrorState, EmptyState, fmtDate } from "@/components/common";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Fingerprint, ShieldCheck, ShieldOff, Trash2 } from "lucide-react";
import { toast } from "sonner";
import {
  SecurityLocationMap,
  type SecurityLocationMarker,
} from "@/components/security-location-map";

export const Route = createFileRoute("/app/devices")({ component: DevicesPage });

function DevicesPage() {
  const qc = useQueryClient();
  const q = useQuery<DeviceOut[]>({ queryKey: ["devices"], queryFn: () => api("/devices") });
  const mapMarkers: SecurityLocationMarker[] = (q.data ?? []).map((device) => ({
    id: device.id,
    latitude: device.latitude,
    longitude: device.longitude,
    location: locationLabel(device.city, device.country),
    title: `${device.browser ?? "Unknown browser"}${device.os ? ` on ${device.os}` : ""}`,
    details: [
      { label: "Last IP", value: device.last_ip ?? "Unknown" },
      { label: "Device type", value: device.device_type ?? "Unknown" },
      { label: "Trust", value: device.is_trusted ? "Trusted" : "Not trusted" },
      { label: "First seen", value: fmtDate(device.first_seen) },
      { label: "Last seen", value: fmtDate(device.last_seen) },
    ],
  }));

  const trust = useMutation({
    mutationFn: (id: string) => api(`/devices/${id}/trust`, { method: "PATCH", body: {} }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["devices"] });
      qc.invalidateQueries({ queryKey: ["dash"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/devices/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast.success("Device removed");
      qc.invalidateQueries({ queryKey: ["devices"] });
      qc.invalidateQueries({ queryKey: ["dash"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });

  return (
    <>
      <PageHeader
        title="Recognized devices"
        description="Devices that have signed into this account."
      />
      {q.isLoading ? (
        <LoadingBlock />
      ) : q.error ? (
        <ErrorState description={(q.error as any).message} />
      ) : !q.data?.length ? (
        <EmptyState title="No recognized devices yet." icon={<Fingerprint className="h-6 w-6" />} />
      ) : (
        <>
          <SecurityLocationMap
            title="Recognized device locations"
            description="Hover over a marker to see the devices last observed at that approximate IP location."
            markers={mapMarkers}
          />
          <div className="grid gap-3 md:grid-cols-2">
            {q.data.map((d) => (
              <Card key={d.id}>
                <CardContent className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-3 py-4">
                  <div className="min-w-0 space-y-1 text-sm">
                    <div className="flex items-center gap-2 font-semibold">
                      {d.is_trusted ? (
                        <ShieldCheck className="h-4 w-4 text-success" />
                      ) : (
                        <ShieldOff className="h-4 w-4 text-muted-foreground" />
                      )}
                      <span className="truncate">
                        {d.browser ?? "Unknown browser"}
                        {d.os ? ` · ${d.os}` : ""}
                      </span>
                    </div>
                    <div className="truncate text-xs text-muted-foreground">
                      Device ID: <span className="font-mono">{d.device_id}</span>
                    </div>
                    <div className="text-xs text-muted-foreground">Last IP: {d.last_ip ?? "—"}</div>
                    <div className="text-xs text-muted-foreground">
                      Location: {locationLabel(d.city, d.country)}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      First seen {fmtDate(d.first_seen)} · Last seen {fmtDate(d.last_seen)}
                    </div>
                  </div>
                  <div className="flex flex-col gap-2">
                    <Button
                      size="sm"
                      variant={d.is_trusted ? "outline" : "default"}
                      onClick={() => trust.mutate(d.id)}
                    >
                      {d.is_trusted ? "Untrust" : "Trust"}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => remove.mutate(d.id)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
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
