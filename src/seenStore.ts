import * as fs from "fs";
import * as path from "path";
import { get as blobGet, put as blobPut } from "@vercel/blob";

export interface BlobStateOptions {
  token: string;
  pathname: string;
}

interface StateData {
  proofTx?: string[];
  responses?: Record<string, string>;
}

/**
 * Seen-set for proof_tx references ("The proof reference has not already been
 * used for another task" — /build Security checklist; PROOF_REUSED trap).
 *
 * Three layers, in order of authority:
 *   1. In-memory Set/Map for the life of the process.
 *   2. A JSON file on local disk (best-effort across restarts on a persistent
 *      host; on serverless it lives in /tmp and may vanish on cold start).
 *   3. A private Vercel Blob document, when BLOB_READ_WRITE_TOKEN is set:
 *      hydrate() merges the shared state in before each task and flush()
 *      writes the merged state back after recording. This is the layer that
 *      makes the seen-set survive Vercel's per-instance /tmp — without it, a
 *      PROOF_REUSED trap whose first use landed on a different instance is
 *      answered as if never seen (the leading suspect for R04's one
 *      incorrect decision, 2026-11-16).
 * Also keeps a task_id -> serialized response cache so a redelivered task is
 * answered idempotently instead of being misread as proof reuse.
 * Blob failures are logged and swallowed: state is best-effort, the task
 * answer must never depend on it.
 */
export class SeenStore {
  private seenProofTx = new Set<string>();
  private responseByTaskId = new Map<string, string>();
  private filePath: string;
  private blob: BlobStateOptions | null;
  private blobDirty = false;

  constructor(filePath: string, blob: BlobStateOptions | null = null) {
    this.filePath = filePath;
    this.blob = blob;
    this.load();
  }

  private load(): void {
    try {
      const raw = fs.readFileSync(this.filePath, "utf8");
      this.merge(JSON.parse(raw) as StateData);
    } catch {
      /* missing/corrupt file -> start empty (fail-open for storage, fail-closed for policy) */
    }
  }

  private snapshot(): StateData {
    return {
      proofTx: [...this.seenProofTx],
      responses: Object.fromEntries(this.responseByTaskId),
    };
  }

  private merge(data: StateData): void {
    for (const tx of data.proofTx ?? []) this.seenProofTx.add(normalizeTx(tx));
    for (const [k, v] of Object.entries(data.responses ?? {})) {
      if (!this.responseByTaskId.has(k)) this.responseByTaskId.set(k, v);
    }
  }

  private persist(): void {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(this.snapshot()));
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      console.error("[seen-store] persist failed:", (err as Error).message);
    }
  }

  /** Merge the shared Blob state into memory. No-op without Blob config. */
  async hydrate(): Promise<void> {
    if (!this.blob) return;
    try {
      const res = await blobGet(this.blob.pathname, {
        access: "private",
        token: this.blob.token,
        useCache: false,
      });
      if (!res || res.statusCode !== 200 || !res.stream) return;
      const reader = res.stream.getReader();
      const chunks: Uint8Array[] = [];
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) chunks.push(value);
      }
      const text = Buffer.concat(chunks).toString("utf8");
      if (text) this.merge(JSON.parse(text) as StateData);
    } catch (err) {
      console.error("[seen-store] blob hydrate failed:", (err as Error).message);
    }
  }

  /** Write the merged state back to Blob when it changed. No-op otherwise. */
  async flush(): Promise<void> {
    if (!this.blob || !this.blobDirty) return;
    try {
      await blobPut(this.blob.pathname, JSON.stringify(this.snapshot()), {
        access: "private",
        token: this.blob.token,
        addRandomSuffix: false,
        allowOverwrite: true,
        cacheControlMaxAge: 0,
        contentType: "application/json",
      });
      this.blobDirty = false;
    } catch (err) {
      console.error("[seen-store] blob flush failed:", (err as Error).message);
    }
  }

  hasProofTx(proofTx: string): boolean {
    return this.seenProofTx.has(normalizeTx(proofTx));
  }

  recordProofTx(proofTx: string): void {
    const key = normalizeTx(proofTx);
    if (!key) return;
    if (!this.seenProofTx.has(key)) {
      this.seenProofTx.add(key);
      this.blobDirty = true;
      this.persist();
    }
  }

  getResponse(taskId: string): string | null {
    return this.responseByTaskId.get(taskId) ?? null;
  }

  recordResponse(taskId: string, serializedResponse: string): void {
    if (!this.responseByTaskId.has(taskId)) {
      this.responseByTaskId.set(taskId, serializedResponse);
      this.blobDirty = true;
      this.persist();
    }
  }

  get size(): number {
    return this.seenProofTx.size;
  }
}

export function normalizeTx(tx: string): string {
  return (tx ?? "").trim().toLowerCase();
}
