"use client";

import { KeyRound, Plus, X } from "lucide-react";

import { FieldError } from "@/components/common/field-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { AUTH_MODE_LABELS, type AuthMode } from "@/types/scan";

export interface CookieRow {
  name: string;
  value: string;
}

export interface AuthenticationDraft {
  mode: AuthMode;
  token: string;
  cookies: CookieRow[];
}

export const EMPTY_AUTHENTICATION: AuthenticationDraft = {
  mode: "NONE",
  token: "",
  cookies: [{ name: "", value: "" }],
};

const MODES: AuthMode[] = ["NONE", "BEARER_TOKEN", "COOKIE"];

interface AuthenticationFieldsProps {
  value: AuthenticationDraft;
  onChange: (value: AuthenticationDraft) => void;
  disabled?: boolean;
  error?: string;
}

/**
 * Credentials for the **target application** — not for this scanner.
 *
 * Everything typed here stays in React state for exactly as long as the create
 * request takes: it is sent once in the request body and the parent clears it
 * on both success and failure. Nothing is written to `localStorage`,
 * `sessionStorage`, a cookie, a query string or a log, and nothing is ever read
 * back — the API has no field that can return a credential.
 *
 * Every secret input is `type="password"` with autocomplete off, so the value
 * is not shoulder-readable and no browser offers to save it.
 */
export function AuthenticationFields({
  value,
  onChange,
  disabled = false,
  error,
}: AuthenticationFieldsProps) {
  const setMode = (mode: AuthMode) => {
    // Switching mode discards the material for the mode being left, so a
    // credential cannot linger in state for a mode that is no longer selected.
    onChange({ ...EMPTY_AUTHENTICATION, mode });
  };

  const setCookie = (index: number, patch: Partial<CookieRow>) => {
    const cookies = value.cookies.map((row, i) => (i === index ? { ...row, ...patch } : row));
    onChange({ ...value, cookies });
  };

  const addCookie = () => onChange({ ...value, cookies: [...value.cookies, { name: "", value: "" }] });

  const removeCookie = (index: number) =>
    onChange({ ...value, cookies: value.cookies.filter((_, i) => i !== index) });

  return (
    <div className="space-y-3 rounded-lg border border-border p-3">
      <div className="flex items-center gap-2">
        <KeyRound className="size-4 text-muted-foreground" aria-hidden />
        <span className="text-sm font-medium">Authentication</span>
        <span className="text-xs text-muted-foreground">
          for the target site, if it needs a login
        </span>
      </div>

      <div role="radiogroup" aria-label="Authentication mode" className="flex flex-wrap gap-2">
        {MODES.map((mode) => (
          <button
            key={mode}
            type="button"
            role="radio"
            aria-checked={value.mode === mode}
            disabled={disabled}
            onClick={() => setMode(mode)}
            className={cn(
              "rounded-md border px-3 py-1.5 text-sm transition-colors",
              "disabled:cursor-not-allowed disabled:opacity-50",
              value.mode === mode
                ? "border-primary bg-primary/10 text-foreground"
                : "border-border text-muted-foreground hover:text-foreground",
            )}
          >
            {AUTH_MODE_LABELS[mode]}
          </button>
        ))}
      </div>

      {value.mode === "BEARER_TOKEN" ? (
        <div className="space-y-1.5">
          <Label htmlFor="auth-token">Bearer token</Label>
          <Input
            id="auth-token"
            type="password"
            autoComplete="off"
            spellCheck={false}
            disabled={disabled}
            value={value.token}
            onChange={(event) => onChange({ ...value, token: event.target.value })}
            placeholder="Paste the token only"
          />
          <p className="text-xs text-muted-foreground">
            Sent as <span className="font-mono">Authorization: Bearer …</span>. Do not include the
            word Bearer — the scanner adds it.
          </p>
        </div>
      ) : null}

      {value.mode === "COOKIE" ? (
        <div className="space-y-2">
          <Label>Cookies</Label>
          {value.cookies.map((cookie, index) => (
            <div key={index} className="flex gap-2">
              <Input
                aria-label={`Cookie ${index + 1} name`}
                value={cookie.name}
                disabled={disabled}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => setCookie(index, { name: event.target.value })}
                placeholder="session"
                className="font-mono sm:max-w-52"
              />
              <Input
                aria-label={`Cookie ${index + 1} value`}
                type="password"
                autoComplete="off"
                spellCheck={false}
                disabled={disabled}
                value={cookie.value}
                onChange={(event) => setCookie(index, { value: event.target.value })}
                placeholder="value"
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={`Remove cookie ${index + 1}`}
                disabled={disabled || value.cookies.length === 1}
                onClick={() => removeCookie(index)}
              >
                <X className="size-4 text-muted-foreground" aria-hidden />
              </Button>
            </div>
          ))}
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={disabled}
            onClick={addCookie}
          >
            <Plus className="size-4" aria-hidden />
            Add cookie
          </Button>
        </div>
      ) : null}

      <FieldError message={error} />

      {value.mode === "NONE" ? (
        <p className="text-xs text-muted-foreground">
          The scan runs as an anonymous visitor and sees only what a signed-out user sees.
        </p>
      ) : (
        <p className="text-xs text-muted-foreground">
          Only use credentials for a site you are authorised to test. They are sent to the origin
          being scanned and nowhere else, are never stored, and are cleared from this form as soon
          as the scan starts.
        </p>
      )}
    </div>
  );
}

/** The request payload for a draft, or `undefined` when no credential is set. */
export function toAuthenticationPayload(draft: AuthenticationDraft) {
  if (draft.mode === "NONE") return undefined;

  if (draft.mode === "BEARER_TOKEN") {
    return { mode: draft.mode, token: draft.token };
  }

  return {
    mode: draft.mode,
    // Blank rows are the form's own scaffolding, not something the user meant
    // to send. A cookie with a name but no value is still sent: an empty value
    // is legal, and silently dropping it would change what the user asked for.
    cookies: draft.cookies.filter((cookie) => cookie.name.trim() !== ""),
  };
}

/** Client-side check, so an obvious mistake does not cost a round trip. */
export function validateAuthenticationDraft(draft: AuthenticationDraft): string | undefined {
  if (draft.mode === "BEARER_TOKEN") {
    if (draft.token.trim() === "") return "Enter the bearer token, or choose None.";
    if (/[\r\n]/.test(draft.token.trim())) return "A token cannot contain line breaks.";
    return undefined;
  }

  if (draft.mode === "COOKIE") {
    const named = draft.cookies.filter((cookie) => cookie.name.trim() !== "");
    if (named.length === 0) return "Add at least one cookie, or choose None.";
    if (named.some((cookie) => /[\r\n]/.test(cookie.name) || /[\r\n]/.test(cookie.value))) {
      return "A cookie cannot contain line breaks.";
    }
    return undefined;
  }

  return undefined;
}
