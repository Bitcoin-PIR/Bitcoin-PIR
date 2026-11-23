import { invoke } from "@tauri-apps/api/core";

export interface DatabaseConfig {
  name: string;
  type: string;
  path: string;
  proof_dir: string | null;
  proof_v2_dir: string | null;
  base_height: number;
  height: number;
}

export interface ServerConfig {
  database: DatabaseConfig[];
}

export interface NodeSettings {
  schema_version: number;
  data_dir: string;
  active_catalog: string | null;
  server_binary: string | null;
  bind_address: string;
  port: number;
  role: "primary" | "secondary";
  serve_queries: boolean;
  serve_hints: boolean;
  extra_args: string[];
  close_to_tray: boolean;
}

export interface ConfigSnapshot {
  settings: NodeSettings;
  raw_settings: string;
  catalog: ServerConfig | null;
  available_catalog: ServerConfig | null;
  raw_catalog: string;
  argv: string[];
}

export type ProcessStatus = "stopped" | "starting" | "running" | "stopping" | "failed";

export interface ProcessSnapshot {
  status: ProcessStatus;
  pid: number | null;
  exit_code: number | null;
  last_error: string | null;
  endpoint: string;
  active_catalog: string | null;
}

export interface HealthReport {
  endpoint: string;
  checked_at_unix: number;
  info: unknown;
}

interface DesktopError {
  code: string;
  message: string;
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    const desktopError = error as DesktopError;
    throw new Error(desktopError?.message ?? String(error));
  }
}

export const getConfig = () => call<ConfigSnapshot>("get_config");
export const importBundle = (path: string) => call<ConfigSnapshot>("import_bundle", { path });
export const saveSettings = (settings: NodeSettings) => call<ConfigSnapshot>("save_settings", { settings });
export const saveRawSettings = (raw: string) => call<ConfigSnapshot>("save_raw_settings", { raw });
export const saveCatalog = (catalog: ServerConfig) => call<ConfigSnapshot>("save_catalog", { catalog });
export const saveRawCatalog = (raw: string) => call<ConfigSnapshot>("save_raw_catalog", { raw });
export const getProcessState = () => call<ProcessSnapshot>("get_process_state");
export const startServer = () => call<ProcessSnapshot>("start_server");
export const stopServer = () => call<ProcessSnapshot>("stop_server");
export const restartServer = () => call<ProcessSnapshot>("restart_server");
export const readLogs = () => call<string[]>("read_logs");
export const probeEndpoint = (endpoint: string) => call<HealthReport>("probe_endpoint", { endpoint: endpoint || null });
