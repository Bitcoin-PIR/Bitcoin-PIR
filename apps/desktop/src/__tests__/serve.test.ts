import { describe, expect, it } from "vitest";
import type { DatabaseConfig } from "../ipc";
import { makeDatabaseDraft, moveDatabase, selectedDatabases } from "../pages/serve";

function database(name: string, height = 100): DatabaseConfig {
  return {
    name,
    type: name === "main" ? "full" : "delta",
    path: `/data with spaces/${name}`,
    proof_dir: null,
    proof_v2_dir: null,
    base_height: name === "main" ? 0 : 90,
    height,
  };
}

describe("database catalog editing", () => {
  it("keeps active databases first and preserves their order", () => {
    const main = database("main");
    const delta = database("delta");
    const older = database("older", 90);
    const { draft, selected } = makeDatabaseDraft(
      { database: [main, delta, older] },
      { database: [delta, main] },
    );
    expect(draft.map((entry) => entry.name)).toEqual(["delta", "main", "older"]);
    expect([...selectedDatabases(draft, selected).database.map((entry) => entry.name)]).toEqual(["delta", "main"]);
  });

  it("reorders without losing the selected set", () => {
    const main = database("main");
    const delta = database("delta");
    const { selected } = makeDatabaseDraft({ database: [main, delta] }, { database: [main, delta] });
    const reordered = moveDatabase([main, delta], 1, -1);
    expect(selectedDatabases(reordered, selected).database.map((entry) => entry.name)).toEqual(["delta", "main"]);
    expect(moveDatabase(reordered, 0, -1)).toEqual(reordered);
  });
});
