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

interface QueryEntry<TData> {
  snapshot: QuerySnapshot<TData>;
  listeners: Set<() => void>;
  controller?: AbortController;
  inflight?: Promise<TData>;
  contextRevision: number;
}

const IDLE_SNAPSHOT: QuerySnapshot<never> = { status: "idle" };

function presentationError(error: unknown): QueryPresentationError {
  if (
    typeof error === "object" &&
    error !== null &&
    "correlationId" in error &&
    typeof error.correlationId === "string"
  ) {
    return new QueryPresentationError(error.correlationId);
  }
  return new QueryPresentationError();
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
      entry.snapshot = IDLE_SNAPSHOT;
      entry.inflight = undefined;
      entry.controller = undefined;
      entry.contextRevision = this.contextRevision;
      this.notify(entry);
    }
  }

  invalidate(key: string): void {
    const entry = this.entries.get(key);
    entry?.controller?.abort();
    if (!entry) return;
    entry.snapshot = IDLE_SNAPSHOT;
    entry.inflight = undefined;
    entry.controller = undefined;
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
    entry.snapshot = { status: "loading", data: entry.snapshot.data };
    this.notify(entry);

    let inflight: Promise<TData>;
    inflight = loader(controller.signal).then(
      (data) => {
        if (revision !== this.contextRevision || controller.signal.aborted) {
          throw new DOMException("The authorized context changed.", "AbortError");
        }
        entry.snapshot = {
          status: "success",
          data,
          updatedAt: Date.now(),
        };
        if (entry.inflight === inflight) {
          entry.inflight = undefined;
          entry.controller = undefined;
        }
        this.notify(entry);
        return data;
      },
      (error: unknown) => {
        const isCurrentRequest = entry.inflight === inflight;
        if (isCurrentRequest) {
          entry.inflight = undefined;
          entry.controller = undefined;
        }
        if (isCurrentRequest && revision === this.contextRevision) {
          entry.snapshot = {
            status: "error",
            error: presentationError(error),
          };
          this.notify(entry);
        }
        throw error;
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
    const previous = entry.snapshot;
    const revision = this.contextRevision;
    entry.snapshot = { status: "success", data, updatedAt: Date.now() };
    this.notify(entry);
    return () => {
      if (revision !== this.contextRevision) return;
      entry.snapshot = previous;
      this.notify(entry);
    };
  }

  private ensureEntry<TData = unknown>(key: string): QueryEntry<TData> {
    const existing = this.entries.get(key);
    if (existing) return existing as QueryEntry<TData>;
    const entry: QueryEntry<TData> = {
      snapshot: IDLE_SNAPSHOT,
      listeners: new Set(),
      contextRevision: this.contextRevision,
    };
    this.entries.set(key, entry as QueryEntry<unknown>);
    return entry;
  }

  private notify(entry: QueryEntry<unknown>): void {
    for (const listener of entry.listeners) listener();
  }
}
