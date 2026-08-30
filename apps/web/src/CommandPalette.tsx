import {
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { Button, TextField } from "../../../packages/design-system/src/index";

import {
  beginPerformanceSpan,
  endPerformanceSpan,
} from "./performance";
import { primaryNavigation } from "./routes";

export interface CommandPaletteProps {
  readonly navigate: (href: string) => void;
}

export function CommandPalette({ navigate }: CommandPaletteProps) {
  const dialogReference = useRef<HTMLDialogElement>(null);
  const inputReference = useRef<HTMLInputElement>(null);
  const triggerReference = useRef<HTMLButtonElement>(null);
  const returnFocusReference = useRef<HTMLElement | null>(null);
  const titleId = useId();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  const openPalette = () => {
    if (dialogReference.current?.open) return;

    returnFocusReference.current =
      document.activeElement instanceof HTMLElement &&
      document.activeElement !== document.body
        ? document.activeElement
        : triggerReference.current;
    beginPerformanceSpan("command-open-acknowledgement");
    setOpen(true);
  };

  const closePalette = () => {
    dialogReference.current?.close();
  };

  const handleDialogClose = () => {
    setOpen(false);
    setQuery("");
    const returnFocus = returnFocusReference.current ?? triggerReference.current;
    window.requestAnimationFrame(() => returnFocus?.focus());
  };

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        openPalette();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  useLayoutEffect(() => {
    const dialog = dialogReference.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
    if (open) {
      inputReference.current?.focus();
      endPerformanceSpan("command-open-acknowledgement");
    }
  }, [open]);

  const results = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase();
    if (!normalized) return primaryNavigation;
    return primaryNavigation.filter((item) =>
      item.label.toLocaleLowerCase().includes(normalized),
    );
  }, [query]);

  useLayoutEffect(() => {
    if (open) endPerformanceSpan("command-local-results");
  }, [open, results]);

  return (
    <>
      <Button
        ref={triggerReference}
        className="command-trigger"
        variant="quiet"
        onClick={openPalette}
        aria-haspopup="dialog"
        aria-expanded={open}
      >
        <span aria-hidden="true">⌕</span>
        <span>Search or jump</span>
        <kbd>{navigator.platform.includes("Mac") ? "⌘ K" : "Ctrl K"}</kbd>
      </Button>
      <dialog
        className="command-dialog"
        ref={dialogReference}
        aria-labelledby={titleId}
        onClose={handleDialogClose}
      >
        <div className="command-dialog__header">
          <h2 id={titleId}>Search or jump</h2>
          <Button variant="quiet" onClick={closePalette} aria-label="Close command palette">
            Esc
          </Button>
        </div>
        <TextField
          ref={inputReference}
          autoFocus
          label="Search commands"
          placeholder="Type a destination"
          value={query}
          onChange={(event) => {
            beginPerformanceSpan("command-local-results");
            setQuery(event.currentTarget.value);
          }}
        />
        <div className="command-results" aria-label="Command results">
          {results.length ? (
            results.map((item) => (
              <button
                key={item.id}
                className="command-result"
                type="button"
                onClick={() => {
                  navigate(item.href);
                  closePalette();
                }}
              >
                <span>{item.label}</span>
                <span aria-hidden="true">↵</span>
              </button>
            ))
          ) : (
            <p className="command-results__empty" role="status">
              No local destinations match. Authorized search connects through the Platform API.
            </p>
          )}
        </div>
      </dialog>
    </>
  );
}
