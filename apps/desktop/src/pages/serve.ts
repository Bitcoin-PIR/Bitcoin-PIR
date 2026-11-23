import type { DatabaseConfig, ServerConfig } from "../ipc";

export function databaseKey(database: DatabaseConfig): string {
  return `${database.name}\0${database.path}`;
}

export function makeDatabaseDraft(
  available: ServerConfig | null,
  active: ServerConfig | null,
): { draft: DatabaseConfig[]; selected: Set<string> } {
  const all = available?.database ?? [];
  const current = active?.database ?? [];
  const currentKeys = new Set(current.map(databaseKey));
  const currentByKey = new Map(current.map((database) => [databaseKey(database), database]));
  const activeRows = current
    .map((database) => all.find((candidate) => databaseKey(candidate) === databaseKey(database)) ?? database);
  const remaining = all.filter((database) => !currentKeys.has(databaseKey(database)));
  return {
    draft: [...activeRows, ...remaining],
    selected: new Set([...currentByKey.keys()]),
  };
}

export function moveDatabase(draft: DatabaseConfig[], index: number, offset: number): DatabaseConfig[] {
  const destination = index + offset;
  if (index < 0 || index >= draft.length || destination < 0 || destination >= draft.length) {
    return draft;
  }
  const next = [...draft];
  [next[index], next[destination]] = [next[destination], next[index]];
  return next;
}

export function selectedDatabases(draft: DatabaseConfig[], selected: Set<string>): ServerConfig {
  return { database: draft.filter((database) => selected.has(databaseKey(database))) };
}
