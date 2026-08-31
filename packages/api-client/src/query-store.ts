export interface AuthorizationContext {
  readonly principal: string;
  readonly session: string;
  readonly securityDomain: string;
}

export type QueryStatus = "idle" | "loading" | "success" | "error";

export interface QuerySnapshot<TData> {
  readonly status: QueryStatus;
  readonly data?: TData;
  readonly error?: Error;
  readonly updatedAt?: number;
}

export class QueryPresentationError extends Error {
  readonly correlationId?: string;

  constructor(correlationId?: string) {
    super("The request could not be completed.");
    this.name = "QueryPresentationError";
    this.correlationId = correlationId;
  }
}

export class QueryCancellationError extends Error {
  constructor() {
    super("The request was cancelled.");
    this.name = "QueryCancellationError";
  }
}

interface OptimisticMutation<TData> {
  readonly snapshot: QuerySnapshot<TData>;
  readonly previousMutation?: OptimisticMutation<TData>;
  appliedGeneration: number;
  rolledBack: boolean;
}

interface QueryEntry<TData> {
  snapshot: QuerySnapshot<TData>;
  baseSnapshot: QuerySnapshot<TData>;
  listeners: Set<() => void>;
  controller?: AbortController;
  inflight?: Promise<TData>;
  contextRevision: number;
  stateGeneration: number;
  optimisticMutation?: OptimisticMutation<TData>;
}

const IDLE_SNAPSHOT: QuerySnapshot<never> = { status: "idle" };
const SAFE_CORRELATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

function presentationError(error: unknown): QueryPresentationError {
  try {
    if (
      typeof error === "object" &&
      error !== null &&
      "correlationId" in error &&
      typeof error.correlationId === "string" &&
      SAFE_CORRELATION_ID_PATTERN.test(error.correlationId)
    ) {
      return new QueryPresentationError(error.correlationId);
    }
  } catch {
    // Untrusted error properties never cross the presentation boundary.
  }
  return new QueryPresentationError();
}

function isCancellation(error: unknown, signal: AbortSignal): boolean {
  if (signal.aborted) return true;
  try {
    return (
      typeof error === "object" &&
      error !== null &&
      "name" in error &&
      error.name === "AbortError"
    );
  } catch {
    return false;
  }
}

function sameContext(
  left: AuthorizationContext | undefined,
  right: AuthorizationContext,
): boolean {
  return (
    left?.principal === right.principal &&
    left.session === right.session &&
    left.securityDomain === right.securityDomain
  );
}

export class QueryStore {
  private readonly entries = new Map<string, QueryEntry<unknown>>();
  private context?: AuthorizationContext;
  private contextRevision = 0;

  setAuthorizationContext(context: AuthorizationContext): void {
    if (sameContext(this.context, context)) return;
    this.context = context;
    this.contextRevision += 1;
    this.clear();
  }

  clearAuthorizationContext(): void {
    this.context = undefined;
    this.contextRevision += 1;
    this.clear();
  }

  clear(): void {
    for (const entry of this.entries.values()) {
      entry.controller?.abort();
      entry.inflight = undefined;
      entry.controller = undefined;
      entry.contextRevision = this.contextRevision;
      this.replaceSnapshot(entry, IDLE_SNAPSHOT);
      this.notify(entry);
    }
  }

  invalidate(key: string): void {
    const entry = this.entries.get(key);
    entry?.controller?.abort();
    if (!entry) return;
    entry.inflight = undefined;
    entry.controller = undefined;
    this.replaceSnapshot(entry, IDLE_SNAPSHOT);
    this.notify(entry);
  }

  getSnapshot<TData>(key: string): QuerySnapshot<TData> {
    return (this.entries.get(key)?.snapshot ?? IDLE_SNAPSHOT) as QuerySnapshot<TData>;
  }

  subscribe(key: string, listener: () => void): () => void {
    const entry = this.ensureEntry(key);
    entry.listeners.add(listener);
    return () => entry.listeners.delete(listener);
  }

  async load<TData>(
    key: string,
    loader: (signal: AbortSignal) => Promise<TData>,
  ): Promise<TData> {
    if (!this.context) {
      throw new Error("authorization context must be set before loading data");
    }
    const entry = this.ensureEntry<TData>(key);
    if (entry.inflight) return entry.inflight;
    const controller = new AbortController();
    const revision = this.contextRevision;
    entry.controller = controller;
    entry.contextRevision = revision;
    this.replaceSnapshot(entry, {
      status: "loading",
      data: entry.snapshot.data,
    });
    this.notify(entry);

    let loaderResult: Promise<TData>;
    try {
      loaderResult = Promise.resolve(loader(controller.signal));
    } catch (error: unknown) {
      loaderResult = Promise.reject(error);
    }

    let inflight: Promise<TData>;
    inflight = loaderResult.then(
      (data) => {
        const isCurrentRequest = entry.inflight === inflight;
        if (revision !== this.contextRevision || controller.signal.aborted) {
          if (isCurrentRequest) {
            entry.inflight = undefined;
            entry.controller = undefined;
          }
          throw new QueryCancellationError();
        }
        if (isCurrentRequest) {
          entry.inflight = undefined;
          entry.controller = undefined;
        }
        if (isCurrentRequest) {
          this.updateBaseSnapshot(entry, {
            status: "success",
            data,
            updatedAt: Date.now(),
          });
        }
        return data;
      },
      (error: unknown) => {
        const isCurrentRequest = entry.inflight === inflight;
        if (isCurrentRequest) {
          entry.inflight = undefined;
          entry.controller = undefined;
        }
        const sanitizedError = isCancellation(error, controller.signal)
          ? new QueryCancellationError()
          : presentationError(error);
        if (
          isCurrentRequest &&
          revision === this.contextRevision &&
          !(sanitizedError instanceof QueryCancellationError)
        ) {
          this.updateBaseSnapshot(entry, {
            status: "error",
            error: sanitizedError,
          });
        }
        throw sanitizedError;
      },
    );
    entry.inflight = inflight;
    return inflight;
  }

  prefetch<TData>(
    key: string,
    loader: (signal: AbortSignal) => Promise<TData>,
  ): Promise<TData> {
    const snapshot = this.getSnapshot<TData>(key);
    if (snapshot.status === "success" && snapshot.data !== undefined) {
      return Promise.resolve(snapshot.data);
    }
    return this.load(key, loader);
  }

  optimisticallySet<TData>(key: string, data: TData): () => void {
    if (!this.context) {
      throw new Error("authorization context must be set before presenting data");
    }
    const entry = this.ensureEntry<TData>(key);
    const revision = this.contextRevision;
    const snapshot: QuerySnapshot<TData> = {
      status: "success",
      data,
      updatedAt: Date.now(),
    };
    const mutation: OptimisticMutation<TData> = {
      snapshot,
      ...(entry.optimisticMutation
        ? { previousMutation: entry.optimisticMutation }
        : {}),
      appliedGeneration: entry.stateGeneration + 1,
      rolledBack: false,
    };
    entry.stateGeneration = mutation.appliedGeneration;
    entry.optimisticMutation = mutation;
    entry.snapshot = snapshot;
    this.notify(entry);
    return () => {
      if (revision !== this.contextRevision || mutation.rolledBack) return;
      mutation.rolledBack = true;
      if (
        entry.optimisticMutation !== mutation ||
        entry.stateGeneration !== mutation.appliedGeneration
      ) {
        return;
      }

      let previousMutation = mutation.previousMutation;
      while (previousMutation?.rolledBack) {
        previousMutation = previousMutation.previousMutation;
      }

      entry.stateGeneration += 1;
      entry.optimisticMutation = previousMutation;
      if (previousMutation) {
        previousMutation.appliedGeneration = entry.stateGeneration;
        entry.snapshot = previousMutation.snapshot;
      } else {
        entry.snapshot = entry.baseSnapshot;
      }
      this.notify(entry);
    };
  }

  private ensureEntry<TData = unknown>(key: string): QueryEntry<TData> {
    const existing = this.entries.get(key);
    if (existing) return existing as QueryEntry<TData>;
    const entry: QueryEntry<TData> = {
      snapshot: IDLE_SNAPSHOT,
      baseSnapshot: IDLE_SNAPSHOT,
      listeners: new Set(),
      contextRevision: this.contextRevision,
      stateGeneration: 0,
    };
    this.entries.set(key, entry as QueryEntry<unknown>);
    return entry;
  }

  private notify(entry: QueryEntry<unknown>): void {
    for (const listener of entry.listeners) listener();
  }

  private replaceSnapshot<TData>(
    entry: QueryEntry<TData>,
    snapshot: QuerySnapshot<TData>,
  ): number {
    entry.stateGeneration += 1;
    entry.baseSnapshot = snapshot;
    entry.snapshot = snapshot;
    entry.optimisticMutation = undefined;
    return entry.stateGeneration;
  }

  private updateBaseSnapshot<TData>(
    entry: QueryEntry<TData>,
    snapshot: QuerySnapshot<TData>,
  ): void {
    entry.baseSnapshot = snapshot;
    if (entry.optimisticMutation) return;
    entry.stateGeneration += 1;
    entry.snapshot = snapshot;
    this.notify(entry);
  }
}
