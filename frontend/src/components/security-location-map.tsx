import { useMemo } from "react";
import { CircleMarker, MapContainer, TileLayer, Tooltip } from "react-leaflet";
import { MapPin, MapPinOff } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export type SecurityLocationMarker = {
  id: string;
  latitude: number | null;
  longitude: number | null;
  location: string;
  title: string;
  details: Array<{ label: string; value: string }>;
};

type MarkerGroup = {
  key: string;
  position: [number, number];
  location: string;
  entries: SecurityLocationMarker[];
};

export function SecurityLocationMap({
  title,
  description,
  markers,
}: {
  title: string;
  description: string;
  markers: SecurityLocationMarker[];
}) {
  const groups = useMemo(() => groupMarkers(markers), [markers]);
  const mappedCount = groups.reduce((total, group) => total + group.entries.length, 0);
  const unmappedCount = markers.length - mappedCount;
  const bounds = groups.map((group) => group.position);

  return (
    <Card className="mb-4 overflow-hidden">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <MapPin className="h-4 w-4 text-primary" /> {title}
        </CardTitle>
        <p className="text-sm text-muted-foreground">{description}</p>
      </CardHeader>
      <CardContent>
        {groups.length ? (
          <div className="security-map overflow-hidden rounded-lg border border-border">
            <MapContainer
              center={groups.length === 1 ? groups[0].position : [20, 0]}
              zoom={groups.length === 1 ? 6 : 2}
              bounds={groups.length > 1 ? bounds : undefined}
              boundsOptions={{ padding: [36, 36], maxZoom: 8 }}
              scrollWheelZoom={false}
              className="h-[360px] w-full"
            >
              <TileLayer
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
              />
              {groups.map((group) => (
                <CircleMarker
                  key={group.key}
                  center={group.position}
                  radius={10}
                  pathOptions={{
                    color: "#ffffff",
                    weight: 2,
                    fillColor: "#0ea5e9",
                    fillOpacity: 0.9,
                  }}
                >
                  <Tooltip sticky direction="top" offset={[0, -8]} opacity={1}>
                    <div className="min-w-64 max-w-80 space-y-3">
                      <div>
                        <div className="font-semibold">{group.location}</div>
                        <div className="text-[11px] opacity-70">
                          {group.position[0].toFixed(4)}, {group.position[1].toFixed(4)}
                        </div>
                      </div>
                      {group.entries.map((entry) => (
                        <div
                          key={entry.id}
                          className="border-t border-border pt-2 first:border-0 first:pt-0"
                        >
                          <div className="mb-1 font-medium">{entry.title}</div>
                          <dl className="space-y-0.5 text-xs">
                            {entry.details.map((detail) => (
                              <div
                                key={detail.label}
                                className="grid grid-cols-[5rem_minmax(0,1fr)] gap-2"
                              >
                                <dt className="opacity-65">{detail.label}</dt>
                                <dd className="break-words">{detail.value}</dd>
                              </div>
                            ))}
                          </dl>
                        </div>
                      ))}
                    </div>
                  </Tooltip>
                </CircleMarker>
              ))}
            </MapContainer>
          </div>
        ) : (
          <div className="flex min-h-48 flex-col items-center justify-center rounded-lg border border-dashed border-border bg-muted/30 p-6 text-center">
            <MapPinOff className="mb-2 h-6 w-6 text-muted-foreground" />
            <div className="font-medium">No public locations to map yet</div>
            <p className="mt-1 max-w-lg text-xs leading-relaxed text-muted-foreground">
              Localhost, private-network, VPN, or unresolved IP addresses may not provide geographic
              coordinates.
            </p>
          </div>
        )}
        {unmappedCount > 0 && groups.length > 0 ? (
          <p className="mt-2 text-xs text-muted-foreground">
            {unmappedCount} {unmappedCount === 1 ? "item has" : "items have"} no mappable public
            coordinates and {unmappedCount === 1 ? "is" : "are"} shown only in the list below.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function groupMarkers(markers: SecurityLocationMarker[]): MarkerGroup[] {
  const groups = new Map<string, MarkerGroup>();
  for (const marker of markers) {
    if (
      marker.latitude == null ||
      marker.longitude == null ||
      !Number.isFinite(marker.latitude) ||
      !Number.isFinite(marker.longitude)
    )
      continue;

    const key = `${marker.latitude.toFixed(5)}:${marker.longitude.toFixed(5)}`;
    const existing = groups.get(key);
    if (existing) {
      existing.entries.push(marker);
    } else {
      groups.set(key, {
        key,
        position: [marker.latitude, marker.longitude],
        location: marker.location,
        entries: [marker],
      });
    }
  }
  return Array.from(groups.values());
}
