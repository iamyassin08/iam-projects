import { useCallback, useEffect, useState } from 'react'

// Load several API calls together; returns [data, reload, error].
export function useLoad(loaders, deps = []) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const reload = useCallback(async () => {
    try {
      const keys = Object.keys(loaders)
      const vals = await Promise.all(keys.map((k) => loaders[k]()))
      setData(Object.fromEntries(keys.map((k, i) => [k, vals[i]])))
      setError('')
    } catch (e) {
      setError(e.message)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(() => { reload() }, [reload])
  return [data, reload, error]
}

// Simple toast state: { msg, kind } that clears itself.
export function useToast() {
  const [toast, setToast] = useState(null)
  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 4000)
    return () => clearTimeout(t)
  }, [toast])
  return [toast, (msg, kind = 'ok') => setToast({ msg, kind })]
}
