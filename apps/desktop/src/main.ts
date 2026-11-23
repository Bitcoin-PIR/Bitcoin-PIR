import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import {
  getConfig,
  getProcessState,
  importBundle,
  probeEndpoint,
  readLogs,
  restartServer,
  saveCatalog,
  saveRawCatalog,
  saveRawSettings,
  saveSettings,
  startServer,
  stopServer,
  type ConfigSnapshot,
  type DatabaseConfig,
  type ProcessSnapshot,
} from "./ipc";
import { databaseKey, makeDatabaseDraft, moveDatabase, selectedDatabases } from "./pages/serve";

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing UI element #${id}`);
  return element as T;
}

const pageMetadata: Record<string, [string, string]> = {
  overview: ["Overview", "Your node at a glance"],
  serve: ["Serve", "Choose databases and map directly to unified_server"],
  diagnostics: ["Diagnostics", "Process output and startup verification"],
  settings: ["Settings", "Paths and desktop behavior"],
  advanced: ["Advanced", "Edit the actual TOML configuration"],
};

let config: ConfigSnapshot | null = null;
let processSnapshot: ProcessSnapshot | null = null;
let draft: DatabaseConfig[] = [];
let selected = new Set<string>();
let logLines: string[] = [];
let healthDirty = false;

function notify(message: string, error = false): void {
  const notice = byId("notice");
  notice.textContent = message;
  notice.classList.toggle("error", error);
  notice.classList.remove("hidden");
}

function clearNotice(): void {
  byId("notice").classList.add("hidden");
}

async function perform(action: () => Promise<void>, success: string): Promise<void> {
  clearNotice();
  try {
    await action();
    notify(success);
  } catch (error) {
    notify(error instanceof Error ? error.message : String(error), true);
  }
}

function applyConfig(snapshot: ConfigSnapshot): void {
  config = snapshot;
  const next = makeDatabaseDraft(snapshot.available_catalog, snapshot.catalog);
  draft = next.draft;
  selected = next.selected;
  healthDirty = false;
  renderConfig();
}

function localEndpoint(settings: ConfigSnapshot["settings"]): string {
  let host = settings.bind_address;
  if (["0.0.0.0", "::", "[::]"].includes(host)) host = "127.0.0.1";
  else if (host.includes(":")) host = `[${host.replaceAll("[", "").replaceAll("]", "")}]`;
  return `ws://${host}:${settings.port}`;
}

function renderConfig(): void {
  if (!config) return;
  const { settings } = config;
  byId<HTMLInputElement>("serve-role").value = settings.role;
  byId<HTMLInputElement>("serve-bind").value = settings.bind_address;
  byId<HTMLInputElement>("serve-port").value = String(settings.port);
  byId<HTMLInputElement>("serve-queries").checked = settings.serve_queries;
  byId<HTMLInputElement>("serve-hints").checked = settings.serve_hints;
  byId<HTMLTextAreaElement>("extra-args").value = settings.extra_args.join("\n");
  byId<HTMLInputElement>("settings-data-dir").value = settings.data_dir;
  byId<HTMLInputElement>("settings-server-binary").value = settings.server_binary ?? "";
  byId<HTMLInputElement>("settings-close-tray").checked = settings.close_to_tray;
  byId<HTMLTextAreaElement>("raw-settings").value = config.raw_settings;
  byId<HTMLTextAreaElement>("raw-catalog").value = config.raw_catalog;
  byId("settings-active-catalog").textContent = settings.active_catalog ?? "No active catalog";
  byId("settings-active-catalog").title = settings.active_catalog ?? "";
  byId("overview-generation").textContent = settings.active_catalog ?? "None";
  byId("overview-generation").title = settings.active_catalog ?? "";
  const count = config.catalog?.database.length ?? 0;
  byId("overview-databases").textContent = count
    ? `${count} database${count === 1 ? "" : "s"} configured`
    : "Import a bundle to begin";
  byId("argv-preview").textContent = config.argv.length
    ? config.argv.map((argument) => JSON.stringify(argument)).join(" \\\n  ")
    : "No arguments yet.";
  if (!healthDirty) byId<HTMLInputElement>("health-endpoint").value = localEndpoint(settings);
  renderDatabases();
  renderProcess();
}

function renderProcess(): void {
  const status = processSnapshot?.status ?? "stopped";
  const label = status === "starting" ? "Verifying / starting" : status;
  const pill = byId("status-pill");
  pill.className = `status-pill ${status}`;
  pill.textContent = label;
  byId("overview-status").textContent = label;
  const exitCode = processSnapshot?.exit_code;
  byId("overview-pid").textContent = processSnapshot?.pid
    ? `PID ${processSnapshot.pid}${exitCode !== null ? ` · exit ${exitCode}` : ""}`
    : exitCode !== null && exitCode !== undefined
      ? `Last exit code ${exitCode}`
      : "No child process";
  byId("overview-endpoint").textContent = processSnapshot?.endpoint ?? (config ? localEndpoint(config.settings) : "—");
  byId("process-error").textContent = processSnapshot?.last_error ?? "";
  byId("process-error").classList.toggle("hidden", !processSnapshot?.last_error);
  byId<HTMLButtonElement>("start-node").disabled = !config?.settings.active_catalog || ["starting", "running", "stopping"].includes(status);
  byId<HTMLButtonElement>("stop-node").disabled = ["stopped", "failed", "stopping"].includes(status);
  byId<HTMLButtonElement>("restart-node").disabled = !config?.settings.active_catalog || ["starting", "stopping"].includes(status);
  if (!healthDirty && processSnapshot) byId<HTMLInputElement>("health-endpoint").value = processSnapshot.endpoint;
}

function renderDatabases(): void {
  const list = byId("database-list");
  list.replaceChildren();
  if (!draft.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "Import a database bundle from Overview to configure the catalog.";
    list.append(empty);
    return;
  }
  const selectedOrder = new Map(
    draft.filter((database) => selected.has(databaseKey(database))).map((database, index) => [databaseKey(database), index]),
  );
  draft.forEach((database, index) => {
    const key = databaseKey(database);
    const row = document.createElement("div");
    row.className = `database-row${selected.has(key) ? "" : " unselected"}`;

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = selected.has(key);
    checkbox.setAttribute("aria-label", `Serve ${database.name}`);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) selected.add(key);
      else selected.delete(key);
      renderDatabases();
    });

    const dbId = document.createElement("span");
    dbId.className = "db-id mono";
    dbId.textContent = selectedOrder.has(key) ? `#${selectedOrder.get(key)}` : "—";

    const name = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = database.name;
    const type = document.createElement("small");
    type.textContent = database.type;
    name.append(strong, type);

    const path = document.createElement("div");
    path.className = "database-path mono";
    path.textContent = database.path;
    path.title = database.path;

    const height = document.createElement("span");
    height.className = "db-height mono";
    height.textContent = database.base_height ? `${database.base_height}→${database.height}` : `@${database.height}`;

    const actions = document.createElement("div");
    actions.className = "database-actions";
    const up = document.createElement("button");
    up.textContent = "Up";
    up.disabled = index === 0;
    up.addEventListener("click", () => {
      draft = moveDatabase(draft, index, -1);
      renderDatabases();
    });
    const down = document.createElement("button");
    down.textContent = "Down";
    down.disabled = index === draft.length - 1;
    down.addEventListener("click", () => {
      draft = moveDatabase(draft, index, 1);
      renderDatabases();
    });
    actions.append(up, down);
    row.append(checkbox, dbId, name, path, height, actions);
    list.append(row);
  });
}

function settingsFromServeForm(): ConfigSnapshot["settings"] {
  if (!config) throw new Error("Configuration is not loaded");
  return {
    ...config.settings,
    role: byId<HTMLSelectElement>("serve-role").value as "primary" | "secondary",
    bind_address: byId<HTMLInputElement>("serve-bind").value,
    port: Number(byId<HTMLInputElement>("serve-port").value),
    serve_queries: byId<HTMLInputElement>("serve-queries").checked,
    serve_hints: byId<HTMLInputElement>("serve-hints").checked,
    extra_args: byId<HTMLTextAreaElement>("extra-args").value.split("\n").filter((line) => line.length > 0),
  };
}

async function refreshProcess(): Promise<void> {
  try {
    processSnapshot = await getProcessState();
    renderProcess();
  } catch (error) {
    notify(error instanceof Error ? error.message : String(error), true);
  }
}

for (const button of document.querySelectorAll<HTMLButtonElement>(".nav-item")) {
  button.addEventListener("click", () => {
    const page = button.dataset.page ?? "overview";
    document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item === button));
    document.querySelectorAll(".page").forEach((section) => section.classList.remove("active"));
    byId(`page-${page}`).classList.add("active");
    const [title, subtitle] = pageMetadata[page];
    byId("page-title").textContent = title;
    byId("page-subtitle").textContent = subtitle;
  });
}

byId("start-node").addEventListener("click", () => perform(async () => {
  processSnapshot = await startServer();
  renderProcess();
}, "Node start requested. Manifest verification may take several minutes."));
byId("stop-node").addEventListener("click", () => perform(async () => {
  processSnapshot = await stopServer();
  renderProcess();
}, "Node stopped."));
byId("restart-node").addEventListener("click", () => perform(async () => {
  processSnapshot = await restartServer();
  renderProcess();
}, "Node restart requested with the saved configuration."));

byId("browse-bundle").addEventListener("click", () => perform(async () => {
  const path = await open({ directory: true, multiple: false, title: "Select a database bundle" });
  if (typeof path === "string") byId<HTMLInputElement>("bundle-path").value = path;
}, "Bundle selection updated."));
byId("import-bundle").addEventListener("click", () => perform(async () => {
  const path = byId<HTMLInputElement>("bundle-path").value;
  applyConfig(await importBundle(path));
}, "Bundle imported. Review Serve, then start the node."));

byId("save-serve").addEventListener("click", () => perform(async () => {
  await saveSettings(settingsFromServeForm());
  applyConfig(await saveCatalog(selectedDatabases(draft, selected)));
}, "Node configuration saved. Restart to apply it."));
byId("save-settings").addEventListener("click", () => perform(async () => {
  if (!config) return;
  applyConfig(await saveSettings({
    ...config.settings,
    data_dir: byId<HTMLInputElement>("settings-data-dir").value,
    server_binary: byId<HTMLInputElement>("settings-server-binary").value || null,
    close_to_tray: byId<HTMLInputElement>("settings-close-tray").checked,
  }));
}, "Settings saved."));
byId("save-raw-settings").addEventListener("click", () => perform(async () => {
  applyConfig(await saveRawSettings(byId<HTMLTextAreaElement>("raw-settings").value));
}, "node.toml saved."));
byId("save-raw-catalog").addEventListener("click", () => perform(async () => {
  applyConfig(await saveRawCatalog(byId<HTMLTextAreaElement>("raw-catalog").value));
}, "databases.toml saved."));

byId("probe-health").addEventListener("click", () => perform(async () => {
  const output = byId("health-result");
  output.textContent = "Probing…";
  const report = await probeEndpoint(byId<HTMLInputElement>("health-endpoint").value);
  output.textContent = JSON.stringify(report, null, 2);
}, "Protocol probe completed."));
byId("health-endpoint").addEventListener("input", () => { healthDirty = true; });
byId("refresh-logs").addEventListener("click", () => perform(async () => {
  logLines = await readLogs();
  byId("logs-output").textContent = logLines.join("\n") || "No logs yet.";
}, "Logs refreshed."));

await listen<ProcessSnapshot>("server-status", (event) => {
  processSnapshot = event.payload;
  renderProcess();
});
await listen<string>("server-log", (event) => {
  logLines.push(event.payload);
  if (logLines.length > 1000) logLines.shift();
  const output = byId("logs-output");
  output.textContent = logLines.join("\n");
  output.scrollTop = output.scrollHeight;
});

await perform(async () => {
  const [nextConfig, nextProcess, nextLogs] = await Promise.all([getConfig(), getProcessState(), readLogs()]);
  applyConfig(nextConfig);
  processSnapshot = nextProcess;
  logLines = nextLogs;
  byId("logs-output").textContent = logLines.join("\n") || "No logs yet.";
  renderProcess();
}, "Node configuration loaded.");
window.setInterval(refreshProcess, 2_000);
