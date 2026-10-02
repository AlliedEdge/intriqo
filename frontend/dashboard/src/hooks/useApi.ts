import { useCallback, useEffect, useRef, useState } from 'react'

export interface QueryState<T> {
  data: T | null
  loading: boolean
  error: Error | null
  updatedAt: Date | null
  refresh: () => void
}

/** Abort superseded REST reads; refresh is explicit rather than a hidden polling loop. */
export function useApi<T>(loader: (signal: AbortSignal) => Promise<T>, key: string): QueryState<T> {
  const loaderRef = useRef(loader)
  loaderRef.current = loader
  const [revision, setRevision] = useState(0)
  const [state, setState] = useState<Omit<QueryState<T>, 'refresh'>>({
    data: null, loading: true, error: null, updatedAt: null,
  })
  const previousKey = useRef(key)

  useEffect(() => {
    const controller = new AbortController()
    const changed = previousKey.current !== key
    previousKey.current = key
    setState((current) => ({ ...current, data: changed ? null : current.data, loading: true, error: null }))
    loaderRef.current(controller.signal).then(
      (data) => { if (!controller.signal.aborted) setState({ data, loading: false, error: null, updatedAt: new Date() }) },
      (error: unknown) => {
        if (!controller.signal.aborted) setState((current) => ({ ...current, loading: false, error: error instanceof Error ? error : new Error('Request failed') }))
      },
    )
    return () => controller.abort()
  }, [key, revision])

  const refresh = useCallback(() => setRevision((value) => value + 1), [])
  return { ...state, refresh }
}
