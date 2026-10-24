const BASE = '/api'
const KEY = 'bayora_session'

export const session = {
  get: () => { try { return JSON.parse(sessionStorage.getItem(KEY)) } catch { return null } },
  set: (s) => sessionStorage.setItem(KEY, JSON.stringify(s)),
  clear: () => sessionStorage.removeItem(KEY),
}

export async function api(path, { method = 'GET', body } = {}) {
  const s = session.get()
  const res = await fetch(BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(s ? { Authorization: `Bearer ${s.access_token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  })
  if (res.status === 401 && path !== '/auth/login') { session.clear(); window.location.reload() }
  if (res.status === 204) return null
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (${res.status})`)
  return data
}
