import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import { SIMULATOR_WS_URL } from "@/lib/config";
import type {
  SimType,
  SimulationAnswerResult,
  SimulationEventOut,
  SimulationOut,
  SimulationReplayOut,
} from "@/lib/types";
import {
  PageHeader,
  LoadingBlock,
  ErrorState,
  EmptyState,
  StatusBadge,
  statusTone,
  fmtDate,
} from "@/components/common";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Terminal, Trash2 } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/app/simulator")({ component: SimulatorPage });

type SimTypeOption = { type: SimType; label: string; description: string };

const PARAMETER_HELP: Record<SimType, string> = {
  brute_force:
    "Required: attacker_ip (valid IP address), attempts (positive integer). Optional: username.",
  sqli: "Required: target_url and payloads (a non-empty array of strings). The probe runs only against the isolated sandbox target.",
  xss: "Required: target_url and payloads (a non-empty array of strings). The probe runs only against the isolated sandbox target.",
  port_scan: "Required: target. Optional: ports. The scan runs only in the isolated sandbox.",
  vuln_scan:
    "No parameters are required. Optional target_url is recorded with the run; inspection remains inside the sandbox.",
  phishing:
    "Required: urls (strings or { url, description }) and legitimate_domains (array of domains).",
  packet_capture: "Required: duration_seconds from 1 to 60.",
  social_engineering: "Optional: user_role. The backend generates and persists the scenario.",
};

function SimulatorPage() {
  const qc = useQueryClient();
  const runs = useQuery<SimulationOut[]>({
    queryKey: ["sim-runs"],
    queryFn: () => api("/simulator/runs"),
    refetchInterval: 5000,
  });
  const types = useQuery<SimTypeOption[]>({
    queryKey: ["sim-types"],
    queryFn: () => api("/simulator/types"),
  });
  const [type, setType] = useState<SimType>("brute_force");
  const [paramsText, setParamsText] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const deleteRun = useMutation({
    mutationFn: (id: string) => api(`/simulator/runs/${id}`, { method: "DELETE" }),
    onSuccess: (_result, id) => {
      if (selectedId === id) setSelectedId(null);
      qc.invalidateQueries({ queryKey: ["sim-runs"] });
      qc.removeQueries({ queryKey: ["sim-run", id] });
      qc.removeQueries({ queryKey: ["sim-replay", id] });
      toast.success("Simulation run deleted");
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Could not delete run"),
  });
  const clearRuns = useMutation({
    mutationFn: () => api<{ deleted: number }>("/simulator/runs", { method: "DELETE" }),
    onSuccess: ({ deleted }) => {
      setSelectedId(null);
      qc.invalidateQueries({ queryKey: ["sim-runs"] });
      toast.success(`${deleted} completed simulator run(s) cleared`);
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 405) {
        toast.error("This backend is outdated. Restart or redeploy the backend, then try again.");
        return;
      }
      toast.error(e instanceof ApiError ? e.message : "Could not clear simulator runs");
    },
  });

  const submit = useMutation({
    mutationFn: async () => {
      let params: any = null;
      if (paramsText.trim()) {
        try {
          params = JSON.parse(paramsText);
        } catch {
          throw new Error("Params must be valid JSON");
        }
      }
      return api<SimulationOut>("/simulator/run", {
        body: { sim_type: type, target_url: null, params },
      });
    },
    onSuccess: (d) => {
      toast.success("Simulation queued");
      setSelectedId(d.id);
      qc.invalidateQueries({ queryKey: ["sim-runs"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : (e as Error).message),
  });

  return (
    <>
      <PageHeader
        title="Attack simulator"
        description="Simulations run in an isolated Docker sandbox — never against real public targets."
      />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <Card>
          <CardHeader>
            <CardTitle>New simulation</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label>Type</Label>
              {types.isLoading ? (
                <LoadingBlock />
              ) : types.error ? (
                <ErrorState description={(types.error as any).message} />
              ) : (
                <Select
                  value={type}
                  onValueChange={(value) => {
                    setType(value as SimType);
                    setParamsText("");
                  }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {types.data?.map((item) => (
                      <SelectItem key={item.type} value={item.type}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
            <div className="space-y-1">
              <Label>Params (JSON)</Label>
              <Textarea
                rows={6}
                className="font-mono text-xs"
                value={paramsText}
                onChange={(e) => setParamsText(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">{PARAMETER_HELP[type]}</p>
            </div>
            <Button
              onClick={() => submit.mutate()}
              disabled={submit.isPending || types.isLoading || !!types.error}
            >
              <Terminal className="mr-1 h-4 w-4" /> Run in sandbox
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2">
            <CardTitle>Recent runs</CardTitle>
            <Button
              size="sm"
              variant="outline"
              className="text-destructive hover:text-destructive"
              disabled={
                !runs.data?.some((run) => !["queued", "running"].includes(run.status)) ||
                clearRuns.isPending
              }
              onClick={() => {
                if (
                  window.confirm(
                    "Clear all completed or failed simulator runs and their replay events? Active runs will be kept.",
                  )
                ) {
                  clearRuns.mutate();
                }
              }}
            >
              <Trash2 className="mr-1 h-4 w-4" /> Clear all simulations
            </Button>
          </CardHeader>
          <CardContent>
            {runs.isLoading ? (
              <LoadingBlock />
            ) : runs.error ? (
              <ErrorState description={(runs.error as any).message} />
            ) : !runs.data?.length ? (
              <EmptyState title="No runs yet." />
            ) : (
              <ul className="space-y-2 text-sm">
                {runs.data.map((r) => (
                  <li
                    key={r.id}
                    className={`cursor-pointer rounded-md border p-2 ${selectedId === r.id ? "border-primary bg-primary/5" : "border-border"}`}
                    onClick={() => setSelectedId(r.id)}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs">{r.sim_type}</span>
                      <StatusBadge status={r.status} tone={statusTone(r.status)} />
                      <span className="ml-auto text-xs text-muted-foreground">
                        {fmtDate(r.created_at)}
                      </span>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7 text-muted-foreground hover:text-destructive"
                        aria-label={`Delete ${r.sim_type} simulation run`}
                        title={
                          ["queued", "running"].includes(r.status)
                            ? "A queued or running simulation cannot be deleted"
                            : "Delete this simulation run"
                        }
                        disabled={deleteRun.isPending || ["queued", "running"].includes(r.status)}
                        onClick={(event) => {
                          event.stopPropagation();
                          if (window.confirm("Delete this simulation run and its replay events?")) {
                            deleteRun.mutate(r.id);
                          }
                        }}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                    {r.error_message && (
                      <div className="mt-1 text-xs text-destructive">{r.error_message}</div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      {selectedId && <RunDetail key={selectedId} id={selectedId} />}
    </>
  );
}

function RunDetail({ id }: { id: string }) {
  const qc = useQueryClient();
  const [events, setEvents] = useState<
    {
      type: string;
      payload?: string;
      severity?: string | null;
      timestamp?: string;
      details?: any;
    }[]
  >([]);
  const wsRef = useRef<WebSocket | null>(null);

  const run = useQuery<SimulationOut>({
    queryKey: ["sim-run", id],
    queryFn: () => api(`/simulator/runs/${id}`),
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return s && !["completed", "failed", "cancelled"].includes(s) ? 2000 : false;
    },
  });

  const isTerminal = useMemo(() => {
    const s = run.data?.status;
    return !!s && ["completed", "failed", "cancelled"].includes(s);
  }, [run.data?.status]);

  // A completed sandbox run persists a labelled threat and alert. Refresh the
  // shared page queries immediately so Dashboard, Threats, and Alerts show the
  // new detection as soon as the user visits them.
  useEffect(() => {
    if (run.data?.status !== "completed") return;
    qc.invalidateQueries({ queryKey: ["dash"] });
    qc.invalidateQueries({ queryKey: ["threats"] });
    qc.invalidateQueries({ queryKey: ["alerts"] });
    qc.invalidateQueries({ queryKey: ["sim-runs"] });
  }, [qc, run.data?.status]);

  const replay = useQuery<SimulationReplayOut>({
    queryKey: ["sim-replay", id],
    queryFn: () => api(`/simulator/runs/${id}/replay`),
    refetchInterval: isTerminal ? false : 2500,
  });

  // Restore persisted events on mount & on terminal
  useEffect(() => {
    api<SimulationEventOut[]>(`/simulator/runs/${id}/events`)
      .then((list) =>
        setEvents(
          list.map((e) => ({
            type: e.event_type,
            payload: e.payload ?? undefined,
            severity: e.severity,
            timestamp: e.timestamp,
            details: e.details,
          })),
        ),
      )
      .catch(() => {});
  }, [id, isTerminal]);

  // WS
  useEffect(() => {
    if (isTerminal) return;
    const url = `${SIMULATOR_WS_URL}/${id}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;
    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data?.type === "ping") return;
        setEvents((prev) => [...prev, data]);
        if (data?.type === "detection_recorded" || data?.type === "threat_triggered") {
          qc.invalidateQueries({ queryKey: ["dash"] });
          qc.invalidateQueries({ queryKey: ["threats"] });
          qc.invalidateQueries({ queryKey: ["alerts"] });
        }
        if (data?.type === "complete") qc.invalidateQueries({ queryKey: ["sim-run", id] });
      } catch {
        /* ignore */
      }
    };
    ws.onerror = () => {
      /* rely on polling and persisted events */
    };
    return () => {
      try {
        ws.close();
      } catch {
        /* socket already closed */
      }
    };
  }, [id, isTerminal, qc]);

  const phishingPrompts = useMemo(
    () =>
      events
        .filter((e) => e.type === "phishing_prompt")
        .map((e) => e.details)
        .filter(Boolean) as any[],
    [events],
  );
  const socialScenario = useMemo(
    () => events.find((e) => e.type === "scenario_generated")?.details as any,
    [events],
  );
  const showAnswers =
    isTerminal && run.data?.status === "completed" && (phishingPrompts.length || socialScenario);

  return (
    <Card className="mt-4">
      <CardHeader className="flex flex-row items-center justify-between gap-2">
        <div>
          <CardTitle className="truncate">{run.data?.sim_type ?? "Simulation"}</CardTitle>
          <div className="mt-1 flex items-center gap-2">
            {run.data?.status && (
              <StatusBadge status={run.data.status} tone={statusTone(run.data.status)} />
            )}
            {run.data?.target_url && (
              <span className="truncate font-mono text-xs">{run.data.target_url}</span>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {run.data?.summary && <p className="text-sm">{run.data.summary}</p>}
        {run.data?.error_message && (
          <p className="text-sm text-destructive">{run.data.error_message}</p>
        )}

        <div className="max-h-[360px] overflow-y-auto rounded-md border border-border bg-muted/30 font-mono text-xs">
          {!events.length ? (
            <div className="p-4 text-center text-muted-foreground">Waiting for events…</div>
          ) : (
            events.map((e, i) => (
              <div key={i} className="border-b border-border/50 px-3 py-1.5 last:border-0">
                <span className="text-primary">{e.type}</span>
                {e.severity && <span className="ml-2 text-warning">[{e.severity}]</span>}
                {e.payload && <span className="ml-2 break-words">{e.payload}</span>}
                {e.details && !e.payload && (
                  <span className="ml-2 break-words text-muted-foreground">
                    {humanDetails(e.details)}
                  </span>
                )}
              </div>
            ))
          )}
        </div>

        <ReplayPanel replay={replay.data} loading={replay.isLoading} />

        {showAnswers ? (
          <AnswerForm id={id} phishingPrompts={phishingPrompts} scenario={socialScenario} />
        ) : null}
      </CardContent>
    </Card>
  );
}

function humanDetails(details: Record<string, unknown>) {
  return Object.entries(details)
    .map(
      ([key, value]) =>
        `${key.replace(/_/g, " ")}: ${Array.isArray(value) ? value.join(", ") : String(value)}`,
    )
    .join(" · ");
}

function ReplayPanel({ replay, loading }: { replay?: SimulationReplayOut; loading: boolean }) {
  if (loading) return <LoadingBlock label="Building attack-to-defense replay..." />;
  if (!replay) return null;
  const metrics = [
    ["Attack events", replay.attack_events],
    ["Threats detected", replay.threats_detected],
    ["Alerts generated", replay.alerts_generated],
    ["Source IPs blocked", replay.source_ips_blocked],
  ];
  return (
    <section className="space-y-4 rounded-lg border border-primary/25 bg-primary/5 p-4">
      <div>
        <h3 className="font-semibold">Attack-to-defense replay</h3>
        <p className="mt-1 text-sm text-muted-foreground">{replay.outcome}</p>
      </div>
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        {metrics.map(([label, value]) => (
          <div key={label} className="rounded-md border border-border bg-background/70 p-3">
            <div className="text-2xl font-bold">{value}</div>
            <div className="text-xs text-muted-foreground">{label}</div>
          </div>
        ))}
      </div>
      <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
        <span>
          Time to detect:{" "}
          <strong className="text-foreground">
            {replay.time_to_detect_ms == null
              ? "Not triggered"
              : formatDuration(replay.time_to_detect_ms)}
          </strong>
        </span>
        <span>
          Total duration:{" "}
          <strong className="text-foreground">
            {replay.duration_ms == null ? "Running" : formatDuration(replay.duration_ms)}
          </strong>
        </span>
      </div>
      <ol className="max-h-[520px] space-y-0 overflow-y-auto pl-2">
        {replay.timeline.map((stage, index) => (
          <li
            key={`${stage.timestamp}-${index}`}
            className="relative border-l border-border pb-4 pl-5 last:pb-0"
          >
            <span
              className={`absolute -left-1.5 top-1 h-3 w-3 rounded-full border-2 border-background ${phaseColor(stage.phase)}`}
            />
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide">
                {stage.phase}
              </span>
              <span className="font-medium">{stage.title}</span>
              {stage.severity && (
                <StatusBadge
                  status={stage.severity}
                  tone={
                    stage.severity === "critical" || stage.severity === "high"
                      ? "danger"
                      : stage.severity === "warning"
                        ? "warn"
                        : "muted"
                  }
                />
              )}
            </div>
            <p className="mt-1 text-sm text-muted-foreground">{stage.description}</p>
            {stage.timestamp && (
              <time className="mt-1 block text-[11px] text-muted-foreground">
                {fmtDate(stage.timestamp)}
              </time>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}

function formatDuration(value: number) {
  return value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(1)} s`;
}

function phaseColor(phase: string) {
  if (phase === "attack") return "bg-destructive";
  if (phase === "detect") return "bg-warning";
  if (phase === "contain") return "bg-success";
  if (phase === "analyze") return "bg-accent";
  return "bg-primary";
}

function AnswerForm({
  id,
  phishingPrompts,
  scenario,
}: {
  id: string;
  phishingPrompts: any[];
  scenario: any;
}) {
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [result, setResult] = useState<SimulationAnswerResult | null>(null);

  const submit = useMutation({
    mutationFn: () =>
      api<SimulationAnswerResult>(`/simulator/runs/${id}/answers`, { body: { answers } }),
    onSuccess: (d) => {
      setResult(d);
      toast.success(`Score: ${d.correct} / ${d.total}`);
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.message : "Failed"),
  });

  return (
    <div className="space-y-3 rounded-md border border-primary/30 bg-primary/5 p-4">
      <div className="font-semibold">Your response</div>
      {phishingPrompts.length > 0 &&
        phishingPrompts.map((p: any) => (
          <div key={p.challenge_id} className="space-y-1">
            <div className="text-sm">
              <span className="font-mono text-xs">{p.url}</span>{" "}
              <span className="text-muted-foreground">
                (domain: {p.domain}, reachable: {String(p.reachable)})
              </span>
            </div>
            <Select
              value={answers[p.challenge_id] ?? ""}
              onValueChange={(v) => setAnswers((a) => ({ ...a, [p.challenge_id]: v }))}
            >
              <SelectTrigger>
                <SelectValue placeholder="Classify" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="phishing">Phishing</SelectItem>
                <SelectItem value="legitimate">Legitimate</SelectItem>
              </SelectContent>
            </Select>
          </div>
        ))}
      {scenario && Array.isArray(scenario.options) && (
        <div className="space-y-1">
          <div className="text-sm">
            {scenario.scenario ?? scenario.prompt ?? "Choose the best response"}
          </div>
          <Select
            value={answers.choice ?? ""}
            onValueChange={(v) => setAnswers((a) => ({ ...a, choice: v }))}
          >
            <SelectTrigger>
              <SelectValue placeholder="Choose" />
            </SelectTrigger>
            <SelectContent>
              {scenario.options.map((o: any) => (
                <SelectItem
                  key={o.id ?? o.value ?? o.label}
                  value={String(o.id ?? o.value ?? o.label)}
                >
                  {o.label ?? o.text ?? String(o.id)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}
      <Button
        onClick={() => submit.mutate()}
        disabled={submit.isPending || !Object.keys(answers).length}
      >
        Submit answers
      </Button>
      {result && (
        <div className="text-sm">
          Score: <span className="font-mono font-semibold">{result.score}</span> ({result.correct}/
          {result.total} correct)
        </div>
      )}
    </div>
  );
}
