export const API_ORIGIN =
  (typeof import.meta !== "undefined" && (import.meta as any).env?.VITE_API_ORIGIN) ||
  "http://127.0.0.1:8000";
export const API_BASE_URL =
  (typeof import.meta !== "undefined" && (import.meta as any).env?.VITE_API_BASE_URL) ||
  `${API_ORIGIN}/api/v1`;
export const SIMULATOR_WS_URL =
  (typeof import.meta !== "undefined" && (import.meta as any).env?.VITE_SIMULATOR_WS_URL) ||
  API_ORIGIN.replace(/^http/, "ws") + "/api/v1/simulator/ws";
