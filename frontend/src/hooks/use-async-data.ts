"use client";

import { useCallback, useEffect, useState } from "react";

import { errorMessage } from "@/lib/errors";

export interface AsyncData<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  /** Re-run the fetcher, e.g. after creating or deleting a record. */
  reload: () => void;
  /** Replace the cached value without a round trip. */
  setData: (value: T) => void;
}

/**
 * Runs `fetcher` on mount and whenever its identity changes, exposing loading
 * and error state for the UI.
 *
 * `fetcher` must be memoised with `useCallback`; its dependencies are what
 * decide when a refetch happens. Results from a superseded request are
 * discarded, so a slow response can never overwrite a newer one.
 */
export function useAsyncData<T>(fetcher: () => Promise<T>): AsyncData<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    let active = true;

    fetcher()
      .then((result) => {
        if (!active) return;
        setData(result);
        setError(null);
      })
      .catch((caught: unknown) => {
        if (!active) return;
        setError(errorMessage(caught));
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [fetcher, reloadToken]);

  const reload = useCallback(() => {
    setLoading(true);
    setReloadToken((token) => token + 1);
  }, []);

  return { data, loading, error, reload, setData };
}
