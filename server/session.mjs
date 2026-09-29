// Session tokens shared by desk, bench and table.
//
// One signed HS256 JWT, 30 days, secret in SESSION_SECRET. desk and bench
// carry it as a bearer token; table carries it in an HttpOnly cookie
// (cookie helpers below). The payload is whatever the caller passes; the
// caller decides what is safe to trust without re-checking.

import {SignJWT, jwtVerify} from 'jose'

export const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60

function key(secret = process.env.SESSION_SECRET) {
  if (!secret || secret.length < 16) {
    throw new Error('SESSION_SECRET not configured (set a ≥16-char random string in the Functions env)')
  }
  return new TextEncoder().encode(secret)
}

export async function signSession(claims, {secret, ttl = '30d'} = {}) {
  return await new SignJWT({...claims})
    .setProtectedHeader({alg: 'HS256'})
    .setIssuedAt()
    .setExpirationTime(ttl)
    .sign(key(secret))
}

export async function readSession(token, {secret} = {}) {
  if (!token || typeof token !== 'string') throw new Error('no session token')
  const {payload} = await jwtVerify(token, key(secret), {algorithms: ['HS256']})
  return payload
}

// ---- cookie transport (table) ----

export function sessionCookie(name, token, {secure = true} = {}) {
  return [
    `${name}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${SESSION_TTL_SECONDS}`,
    secure ? 'Secure' : ''
  ].filter(Boolean).join('; ')
}

export function clearCookie(name, {secure = true} = {}) {
  return [`${name}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0', secure ? 'Secure' : ''].filter(Boolean).join('; ')
}

export function cookieValue(req, name) {
  const raw = req.headers.get('cookie') || ''
  for (const part of raw.split(';')) {
    const i = part.indexOf('=')
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim()
  }
  return null
}
