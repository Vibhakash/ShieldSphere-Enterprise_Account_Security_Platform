import { API_BASE_URL } from "./config";

const ACCESS_KEY = "ss_access_token";
const REFRESH_KEY = "ss_refresh_token";

export const tokenStore = {
  get access() {
    return null;
  },
  get refresh() {
    return null;
  },
  set(_access: string, _refresh: string) {
    if (typeof window === "undefined") return;
    // Authentication is persisted only in secure HTTP-only cookies. Remove
    // tokens left by versions that previously used localStorage.
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
  clear() {
    if (typeof window === "undefined") return;
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
};

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, detail: unknown, message: string) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

function detailToMessage(detail: unknown, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d: any) => (typeof d === "string" ? d : d?.msg || JSON.stringify(d)))
      .join(", ");
  }
  if (detail && typeof detail === "object" && (detail as any).message) {
    return String((detail as any).message);
  }
  return fallback;
}

async function refreshTokens(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
      credentials: "include",
    });
    if (!res.ok) return false;
    return true;
  } catch {
    return false;
  }
}

export interface ApiOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
  query?: Record<string, string | number | boolean | null | undefined>;
  auth?: boolean; // default true
  raw?: boolean; // return the raw Response
  retry?: boolean; // internal
}

export async function api<T = any>(path: string, opts: ApiOptions = {}): Promise<T> {
  const { body, query, auth = true, raw = false, retry = true, headers, method, ...rest } = opts;
  let url = path.startsWith("http") ? path : `${API_BASE_URL}${path}`;
  if (query) {
    const qs = new URLSearchParams();
    Object.entries(query).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.append(k, String(v));
    });
    const q = qs.toString();
    if (q) url += (url.includes("?") ? "&" : "?") + q;
  }
  const h: Record<string, string> = {
    Accept: "application/json",
    ...(headers as Record<string, string> | undefined),
  };
  if (body !== undefined) h["Content-Type"] = "application/json";
  if (auth) {
    const t = tokenStore.access;
    if (t) h["Authorization"] = `Bearer ${t}`;
  }
  const res = await fetch(url, {
    ...rest,
    method: method ?? (body === undefined ? "GET" : "POST"),
    headers: h,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: rest.credentials ?? "include",
  });

  if (res.status === 401 && auth && retry) {
    const ok = await refreshTokens();
    if (ok) {
      return api<T>(path, { ...opts, retry: false });
    }
    tokenStore.clear();
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("shieldsphere:unauthorized"));
    }
  }

  if (raw) return res as unknown as T;

  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("application/json")
    ? await res.json().catch(() => null)
    : await res.text();

  if (!res.ok) {
    const detail = (data as any)?.detail ?? data;
    throw new ApiError(
      res.status,
      detail,
      detailToMessage(detail, `Request failed (${res.status})`),
    );
  }
  return data as T;
}

// Server-Sent Events stream for POST bodies (copilot chat).
export async function apiStream(
  path: string,
  body: unknown,
  onChunk: (text: string) => void,
  signal?: AbortSignal,
  retry = true,
): Promise<void> {
  const url = `${API_BASE_URL}${path}`;
  const t = tokenStore.access;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "text/event-stream",
      ...(t ? { Authorization: `Bearer ${t}` } : {}),
    },
    body: JSON.stringify(body),
    signal,
    credentials: "include",
  });
  if (res.status === 401 && retry && (await refreshTokens())) {
    return apiStream(path, body, onChunk, signal, false);
  }
  if (!res.ok || !res.body) {
    const text = await res.text().catch(() => "");
    throw new ApiError(res.status, text, text || `Stream failed (${res.status})`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      const eventLine = line.endsWith("\r") ? line.slice(0, -1) : line;
      if (!eventLine.startsWith("data:")) continue;
      const data = eventLine.slice(5);
      const payload = data.startsWith(" ") ? data.slice(1) : data;
      if (payload === "[DONE]") return;
      if (!payload) continue;
      try {
        const decoded = JSON.parse(payload);
        onChunk(typeof decoded === "string" ? decoded : String(decoded));
      } catch {
        // Compatibility with servers that still send unencoded text chunks.
        onChunk(payload);
      }
    }
  }
}
