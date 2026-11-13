import { copyToClipboard } from "../clipboard.ts";
import { planCopy, renderCopyKeys, resolveNote, type CopyPlan } from "../notes.ts";
import { openCache } from "./list.ts";

/**
 * Execute a copy plan: on a settings note with no key, nothing leaves the
 * cache — the keys name the values and the two-argument form; a matched key
 * copies just that value; a note without settings still copies its body.
 */
export async function runCopyPlan(query: string, plan: CopyPlan): Promise<void> {
  if (plan.kind === "keys") {
    console.log(renderCopyKeys(query, plan.keys));
    return;
  }
  if (plan.kind === "value") {
    console.log(await copyToClipboard(plan.value, plan.key));
    return;
  }
  console.log(await copyToClipboard(plan.body));
}

export async function copyCommand(query: string, key?: string): Promise<void> {
  const db = await openCache();
  try {
    const row = resolveNote(db, query, { all: false });
    await runCopyPlan(query, planCopy(row, key));
  } finally {
    db.close();
  }
}
