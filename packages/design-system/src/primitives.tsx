import {
  default as React,
  forwardRef,
  useId,
  type ButtonHTMLAttributes,
  type HTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
} from "react";

function joinClassNames(
  ...classNames: Array<string | false | null | undefined>
): string {
  return classNames.filter(Boolean).join(" ");
}

const FORBIDDEN_FORWARDED_DOM_PROPERTIES = new Set([
  "action",
  "background",
  "backgroundimage",
  "codebase",
  "csstext",
  "dangerouslysetinnerhtml",
  "data",
  "formaction",
  "href",
  "innerhtml",
  "outerhtml",
  "ping",
  "poster",
  "src",
  "srcdoc",
  "srcset",
  "style",
]);

function governedDomProperties<TProperties extends object>(
  properties: TProperties,
): TProperties {
  for (const name of Reflect.ownKeys(properties)) {
    if (
      typeof name !== "string" ||
      FORBIDDEN_FORWARDED_DOM_PROPERTIES.has(name.toLowerCase())
    ) {
      throw new Error("resource-loading DOM properties are not supported");
    }
  }
  return properties;
}

export type ButtonVariant = "primary" | "secondary" | "quiet" | "danger";

export interface ButtonProps
  extends Omit<
    ButtonHTMLAttributes<HTMLButtonElement>,
    "dangerouslySetInnerHTML" | "formAction" | "style"
  > {
  readonly variant?: ButtonVariant;
  readonly pending?: boolean;
  readonly pendingLabel?: string;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    className,
    variant = "secondary",
    pending = false,
    pendingLabel = "Working",
    disabled,
    children,
    type = "button",
    ...properties
  },
  reference,
) {
  return (
    <button
      {...governedDomProperties(properties)}
      ref={reference}
      className={joinClassNames("stead-button", `stead-button--${variant}`, className)}
      type={type}
      disabled={disabled || pending}
      aria-busy={pending || undefined}
    >
      {pending ? <span className="stead-spinner" aria-hidden="true" /> : null}
      <span>{pending ? pendingLabel : children}</span>
    </button>
  );
});

export interface TextFieldProps
  extends Omit<
    InputHTMLAttributes<HTMLInputElement>,
    "dangerouslySetInnerHTML" | "formAction" | "src" | "style"
  > {
  readonly label: string;
  readonly description?: string;
  readonly error?: string;
}

export const TextField = forwardRef<HTMLInputElement, TextFieldProps>(
  function TextField(
    { className, id, label, description, error, ...properties },
    reference,
  ) {
    const generatedId = useId();
    const inputId = id ?? generatedId;
    const descriptionId = description ? `${inputId}-description` : undefined;
    const errorId = error ? `${inputId}-error` : undefined;
    const describedBy = [descriptionId, errorId].filter(Boolean).join(" ") || undefined;
    return (
      <div className="stead-field">
        <label className="stead-field__label" htmlFor={inputId}>
          {label}
        </label>
        {description ? (
          <span className="stead-field__description" id={descriptionId}>
            {description}
          </span>
        ) : null}
        <input
          {...governedDomProperties(properties)}
          ref={reference}
          id={inputId}
          className={joinClassNames("stead-field__control", className)}
          aria-describedby={describedBy}
          aria-invalid={error ? true : undefined}
        />
        {error ? (
          <span className="stead-field__error" id={errorId} role="alert">
            {error}
          </span>
        ) : null}
      </div>
    );
  },
);

export interface SurfaceProps
  extends Omit<HTMLAttributes<HTMLElement>, "dangerouslySetInnerHTML" | "style"> {
  readonly children: ReactNode;
  readonly elevated?: boolean;
}

export function Surface({
  children,
  className,
  elevated = false,
  ...properties
}: SurfaceProps) {
  return (
    <section
      {...governedDomProperties(properties)}
      className={joinClassNames(
        "stead-surface",
        elevated && "stead-surface--elevated",
        className,
      )}
    >
      {children}
    </section>
  );
}

export interface EmptyStateProps {
  readonly title: string;
  readonly description: string;
  readonly action?: ReactNode;
}

export function EmptyState({ title, description, action }: EmptyStateProps) {
  return (
    <div className="stead-state" data-state="empty">
      <span className="stead-state__glyph" aria-hidden="true">
        ◌
      </span>
      <h2>{title}</h2>
      <p>{description}</p>
      {action ? <div className="stead-state__action">{action}</div> : null}
    </div>
  );
}

export interface LoadingStateProps {
  readonly label?: string;
  readonly lines?: number;
}

export function LoadingState({
  label = "Loading authorized content",
  lines = 3,
}: LoadingStateProps) {
  return (
    <div className="stead-state stead-state--loading" data-state="loading" aria-busy="true">
      <span className="stead-visually-hidden" role="status">
        {label}
      </span>
      <div aria-hidden="true" className="stead-skeleton" data-lines={lines}>
        {Array.from({ length: lines }, (_, index) => (
          <span key={index} />
        ))}
      </div>
    </div>
  );
}

export interface ErrorStateProps {
  readonly title?: string;
  readonly correlationId?: string;
  readonly onRetry?: () => void;
}

const SAFE_CORRELATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

function safeCorrelationId(value: unknown): string | undefined {
  return typeof value === "string" && SAFE_CORRELATION_ID_PATTERN.test(value)
    ? value
    : undefined;
}

export function ErrorState({
  title = "This view is unavailable",
  correlationId,
  onRetry,
}: ErrorStateProps) {
  const visibleCorrelationId = safeCorrelationId(correlationId);
  return (
    <div className="stead-state" data-state="error" role="alert">
      <span className="stead-state__glyph stead-state__glyph--error" aria-hidden="true">
        !
      </span>
      <h2>{title}</h2>
      <p>Try again. If the problem continues, share the correlation ID with an administrator.</p>
      {visibleCorrelationId ? <code>{visibleCorrelationId}</code> : null}
      {onRetry ? (
        <div className="stead-state__action">
          <Button onClick={onRetry}>Try again</Button>
        </div>
      ) : null}
    </div>
  );
}

export interface SecurityMarkingProps {
  readonly label: string;
  readonly markings: readonly { readonly kind: string; readonly text: string }[];
}

export function SecurityMarking({ label, markings }: SecurityMarkingProps) {
  return (
    <aside className="stead-security-marking" aria-label={label}>
      <span className="stead-security-marking__label">{label}</span>
      {markings.map((marking, index) => (
        <span key={`${marking.kind}-${index}`} data-marking-kind={marking.kind}>
          {marking.text}
        </span>
      ))}
    </aside>
  );
}
