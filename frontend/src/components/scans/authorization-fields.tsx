"use client";

import { Plus, ShieldCheck, X } from "lucide-react";

import { FieldError } from "@/components/common/field-error";
import {
  AuthenticationFields,
  EMPTY_AUTHENTICATION,
  toAuthenticationPayload,
  validateAuthenticationDraft,
  type AuthenticationDraft,
} from "@/components/scans/authentication-fields";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ACCESS_EXPECTATIONS, type AccessExpectation } from "@/types/scan";

export interface IdentityDraft {
  id: string;
  label: string;
  role: string;
  privilegeRank: number;
  authentication: AuthenticationDraft;
}

export interface RuleDraft {
  contextId: string;
  resource: string;
  expected: AccessExpectation;
}

export interface OwnershipDraft {
  resource: string;
  owner: string;
}

export interface AuthorizationDraft {
  enabled: boolean;
  includeAnonymous: boolean;
  identities: IdentityDraft[];
  rules: RuleDraft[];
  ownership: OwnershipDraft[];
}

export const ANONYMOUS_CONTEXT_ID = "anonymous";

export const EMPTY_AUTHORIZATION: AuthorizationDraft = {
  enabled: false,
  includeAnonymous: true,
  identities: [],
  rules: [],
  ownership: [],
};

function newIdentity(): IdentityDraft {
  return {
    id: "",
    label: "",
    role: "",
    privilegeRank: 0,
    authentication: EMPTY_AUTHENTICATION,
  };
}

interface AuthorizationFieldsProps {
  value: AuthorizationDraft;
  onChange: (value: AuthorizationDraft) => void;
  disabled?: boolean;
  error?: string;
}

/**
 * Identities and expected access for authorization testing.
 *
 * Every credential typed here follows the same path as the single-identity
 * case: React state until the request is sent, cleared by the parent on every
 * outcome, never written to browser storage and never read back from the API.
 *
 * The policy half is deliberately optional and deliberately not pre-filled. A
 * scan with identities but no rules still runs — it observes access and reports
 * every comparison as unknown, which is the honest result when nobody has said
 * what should happen.
 */
export function AuthorizationFields({
  value,
  onChange,
  disabled = false,
  error,
}: AuthorizationFieldsProps) {
  const contextIds = [
    ...(value.includeAnonymous ? [ANONYMOUS_CONTEXT_ID] : []),
    ...value.identities.map((identity) => identity.id).filter(Boolean),
  ];

  const setIdentity = (index: number, patch: Partial<IdentityDraft>) =>
    onChange({
      ...value,
      identities: value.identities.map((identity, i) =>
        i === index ? { ...identity, ...patch } : identity,
      ),
    });

  const removeIdentity = (index: number) => {
    const removed = value.identities[index]?.id;
    onChange({
      ...value,
      identities: value.identities.filter((_, i) => i !== index),
      // Rules pointing at a removed identity would be rejected by the API, so
      // they go with it rather than becoming a confusing validation error.
      rules: value.rules.filter((rule) => rule.contextId !== removed),
      ownership: value.ownership.filter((entry) => entry.owner !== removed),
    });
  };

  return (
    <div className="space-y-4 rounded-lg border border-border p-3">
      <label className="flex items-start gap-3">
        <input
          type="checkbox"
          className="mt-1 size-4 accent-primary"
          checked={value.enabled}
          disabled={disabled}
          onChange={(event) =>
            onChange({ ...EMPTY_AUTHORIZATION, enabled: event.target.checked })
          }
        />
        <span>
          <span className="flex items-center gap-2 text-sm font-medium">
            <ShieldCheck className="size-4 text-muted-foreground" aria-hidden />
            Authorization testing
          </span>
          <span className="mt-0.5 block text-xs text-muted-foreground">
            Compare what different identities can reach. Requires at least two — the anonymous
            visitor counts as one.
          </span>
        </span>
      </label>

      {value.enabled ? (
        <>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4 accent-primary"
              checked={value.includeAnonymous}
              disabled={disabled}
              onChange={(event) =>
                onChange({ ...value, includeAnonymous: event.target.checked })
              }
            />
            Include an anonymous identity
          </label>

          {/* --- identities --- */}
          <div className="space-y-3">
            {value.identities.map((identity, index) => (
              <div key={index} className="space-y-2 rounded-md border border-border p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium">Identity {index + 1}</span>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    aria-label={`Remove identity ${index + 1}`}
                    disabled={disabled}
                    onClick={() => removeIdentity(index)}
                  >
                    <X className="size-4 text-muted-foreground" aria-hidden />
                  </Button>
                </div>

                <div className="grid gap-2 sm:grid-cols-3">
                  <div className="space-y-1">
                    <Label htmlFor={`authz-id-${index}`}>Id</Label>
                    <Input
                      id={`authz-id-${index}`}
                      value={identity.id}
                      disabled={disabled}
                      autoComplete="off"
                      placeholder="alice"
                      className="font-mono"
                      onChange={(event) => setIdentity(index, { id: event.target.value })}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor={`authz-label-${index}`}>Name</Label>
                    <Input
                      id={`authz-label-${index}`}
                      value={identity.label}
                      disabled={disabled}
                      autoComplete="off"
                      placeholder="Alice (customer)"
                      onChange={(event) => setIdentity(index, { label: event.target.value })}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor={`authz-role-${index}`}>Role (optional)</Label>
                    <Input
                      id={`authz-role-${index}`}
                      value={identity.role}
                      disabled={disabled}
                      autoComplete="off"
                      placeholder="USER"
                      onChange={(event) => setIdentity(index, { role: event.target.value })}
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <Label htmlFor={`authz-rank-${index}`}>Privilege rank</Label>
                  <Input
                    id={`authz-rank-${index}`}
                    type="number"
                    min={0}
                    max={100}
                    value={identity.privilegeRank}
                    disabled={disabled}
                    className="sm:max-w-32"
                    onChange={(event) =>
                      setIdentity(index, {
                        privilegeRank: Number(event.target.value) || 0,
                      })
                    }
                  />
                  <p className="text-xs text-muted-foreground">
                    Higher means more privileged. Used only to tell a vertical comparison from a
                    horizontal one — never to decide what should be allowed.
                  </p>
                </div>

                <AuthenticationFields
                  value={identity.authentication}
                  disabled={disabled}
                  onChange={(authentication) => setIdentity(index, { authentication })}
                />
              </div>
            ))}

            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={disabled || value.identities.length >= 7}
              onClick={() =>
                onChange({
                  ...value,
                  identities: [...value.identities, newIdentity()],
                })
              }
            >
              <Plus className="size-4" aria-hidden />
              Add identity
            </Button>
          </div>

          {/* --- expected access --- */}
          <div className="space-y-2">
            <Label>Expected access (optional)</Label>
            <p className="text-xs text-muted-foreground">
              Only what you declare here can be reported as a problem. A resource nobody has
              written a rule for is reported as unknown, never as a finding — the scanner cannot
              read your application&apos;s rules out of its traffic.
            </p>
            {value.rules.map((rule, index) => (
              <div key={index} className="flex flex-wrap gap-2">
                <Select
                  value={rule.contextId}
                  onValueChange={(next) =>
                    onChange({
                      ...value,
                      rules: value.rules.map((r, i) =>
                        i === index ? { ...r, contextId: next ?? "" } : r,
                      ),
                    })
                  }
                >
                  <SelectTrigger className="w-40" aria-label={`Rule ${index + 1} identity`}>
                    <SelectValue placeholder="Identity" />
                  </SelectTrigger>
                  <SelectContent>
                    {contextIds.map((id) => (
                      <SelectItem key={id} value={id}>
                        {id}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  aria-label={`Rule ${index + 1} resource`}
                  value={rule.resource}
                  disabled={disabled}
                  placeholder="/admin/*"
                  className="font-mono sm:max-w-64"
                  onChange={(event) =>
                    onChange({
                      ...value,
                      rules: value.rules.map((r, i) =>
                        i === index ? { ...r, resource: event.target.value } : r,
                      ),
                    })
                  }
                />
                <Select
                  value={rule.expected}
                  onValueChange={(next) =>
                    onChange({
                      ...value,
                      rules: value.rules.map((r, i) =>
                        i === index
                          ? { ...r, expected: (next as AccessExpectation) ?? "UNKNOWN" }
                          : r,
                      ),
                    })
                  }
                >
                  <SelectTrigger className="w-36" aria-label={`Rule ${index + 1} expectation`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ACCESS_EXPECTATIONS.map((expectation) => (
                      <SelectItem key={expectation} value={expectation}>
                        {expectation.charAt(0) + expectation.slice(1).toLowerCase()}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={`Remove rule ${index + 1}`}
                  disabled={disabled}
                  onClick={() =>
                    onChange({ ...value, rules: value.rules.filter((_, i) => i !== index) })
                  }
                >
                  <X className="size-4 text-muted-foreground" aria-hidden />
                </Button>
              </div>
            ))}
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={disabled || contextIds.length === 0}
              onClick={() =>
                onChange({
                  ...value,
                  rules: [
                    ...value.rules,
                    { contextId: contextIds[0] ?? "", resource: "", expected: "DENIED" },
                  ],
                })
              }
            >
              <Plus className="size-4" aria-hidden />
              Add rule
            </Button>
          </div>

          {/* --- ownership --- */}
          <div className="space-y-2">
            <Label>Resource ownership (optional)</Label>
            <p className="text-xs text-muted-foreground">
              Naming an object&apos;s owner is what makes object-level testing possible: every
              other identity at the same level is then expected to be denied it.
            </p>
            {value.ownership.map((entry, index) => (
              <div key={index} className="flex flex-wrap gap-2">
                <Input
                  aria-label={`Ownership ${index + 1} resource`}
                  value={entry.resource}
                  disabled={disabled}
                  placeholder="/api/orders/101"
                  className="font-mono sm:max-w-64"
                  onChange={(event) =>
                    onChange({
                      ...value,
                      ownership: value.ownership.map((o, i) =>
                        i === index ? { ...o, resource: event.target.value } : o,
                      ),
                    })
                  }
                />
                <Select
                  value={entry.owner}
                  onValueChange={(next) =>
                    onChange({
                      ...value,
                      ownership: value.ownership.map((o, i) =>
                        i === index ? { ...o, owner: next ?? "" } : o,
                      ),
                    })
                  }
                >
                  <SelectTrigger className="w-40" aria-label={`Ownership ${index + 1} owner`}>
                    <SelectValue placeholder="Owner" />
                  </SelectTrigger>
                  <SelectContent>
                    {contextIds.map((id) => (
                      <SelectItem key={id} value={id}>
                        {id}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={`Remove ownership ${index + 1}`}
                  disabled={disabled}
                  onClick={() =>
                    onChange({
                      ...value,
                      ownership: value.ownership.filter((_, i) => i !== index),
                    })
                  }
                >
                  <X className="size-4 text-muted-foreground" aria-hidden />
                </Button>
              </div>
            ))}
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={disabled || contextIds.length === 0}
              onClick={() =>
                onChange({
                  ...value,
                  ownership: [...value.ownership, { resource: "", owner: contextIds[0] ?? "" }],
                })
              }
            >
              <Plus className="size-4" aria-hidden />
              Add ownership
            </Button>
          </div>

          <FieldError message={error} />

          <p className="text-xs text-muted-foreground">
            Only supply identities for an application you are authorised to test. The scanner
            sends read-only GET requests, never creates or guesses an account, and clears these
            credentials from the form as soon as the scan starts.
          </p>
        </>
      ) : null}
    </div>
  );
}

/** The request payload for a draft, or `undefined` when testing is off. */
export function toAuthorizationPayload(draft: AuthorizationDraft) {
  if (!draft.enabled) return undefined;

  return {
    enabled: true,
    include_anonymous: draft.includeAnonymous,
    contexts: draft.identities.map((identity) => ({
      id: identity.id.trim(),
      label: identity.label.trim() || identity.id.trim(),
      role: identity.role.trim() || undefined,
      privilege_rank: identity.privilegeRank,
      authentication: toAuthenticationPayload(identity.authentication) ?? {
        mode: "NONE" as const,
      },
    })),
    rules: draft.rules
      .filter((rule) => rule.contextId && rule.resource.trim())
      .map((rule) => ({
        context_id: rule.contextId,
        resource: rule.resource.trim(),
        expected: rule.expected,
      })),
    ownership: draft.ownership
      .filter((entry) => entry.owner && entry.resource.trim())
      .map((entry) => ({ resource: entry.resource.trim(), owner: entry.owner })),
  };
}

/** Client-side check, so an obvious mistake does not cost a round trip. */
export function validateAuthorizationDraft(draft: AuthorizationDraft): string | undefined {
  if (!draft.enabled) return undefined;

  const available = draft.identities.length + (draft.includeAnonymous ? 1 : 0);
  if (available < 2) {
    return "Authorization testing needs two identities to compare. Add one, or keep the anonymous identity.";
  }

  const ids = draft.identities.map((identity) => identity.id.trim());
  if (ids.some((id) => id === "")) return "Every identity needs an id.";
  if (ids.some((id) => id === ANONYMOUS_CONTEXT_ID)) {
    return "That id is reserved for the built-in anonymous identity.";
  }
  if (new Set(ids).size !== ids.length) return "Each identity needs a distinct id.";

  for (const identity of draft.identities) {
    if (identity.authentication.mode === "NONE") {
      return `Identity ${identity.id.trim()} needs credentials. The unauthenticated case is the anonymous identity.`;
    }
    const message = validateAuthenticationDraft(identity.authentication);
    if (message) return `Identity ${identity.id.trim()}: ${message}`;
  }

  return undefined;
}
