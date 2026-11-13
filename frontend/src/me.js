import { useEffect, useState } from 'react'
import { api } from './api.js'

// One shared /api/me result for the whole app. Anything that changes the
// signed-in user (profile save, sign out) calls refreshMe() so the top bar,
// sidebar and pages update together.
let cache = null
let inflight = null
const subs = new Set()

export function refreshMe() {
  inflight = api.me().then((m) => { cache = m; subs.forEach((f) => f(m)); applyPrefs(m); return m }).catch(() => {
    cache = { authenticated: false, providers: [] }
    subs.forEach((f) => f(cache))
    return cache
  }).finally(() => { inflight = null })
  return inflight
}

export function useMe() {
  const [me, setMe] = useState(cache)
  useEffect(() => {
    subs.add(setMe)
    if (!cache && !inflight) refreshMe()
    return () => subs.delete(setMe)
  }, [])
  return me
}

// Preferences that change how the app behaves for this person.
let landed = false
export function applyPrefs(me) {
  const prefs = me?.profile?.prefs || {}
  document.documentElement.classList.toggle('reduce-motion', !!prefs.reduceMotion)
  if (!landed) {
    landed = true
    const hash = window.location.hash.replace('#', '')
    if (!hash && prefs.landing && prefs.landing !== 'home') window.location.hash = prefs.landing
  }
}

export const displayName = (me) => me?.profile?.displayName || me?.user?.n || me?.user?.u || ''
export const avatarOf = (me) => me?.profile?.avatar || ''
