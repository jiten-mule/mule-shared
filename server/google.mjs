// Verify a Google ID token (JWT) against Google's published JWKs.
// Caches the JWKs in module memory for the Function's warm lifetime.
//
// Returns the verified token claims on success, or throws on failure.

import crypto from 'node:crypto'

const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs'
const ISS = ['https://accounts.google.com', 'accounts.google.com']
let jwksCache = null

async function fetchJwks() {
  if (jwksCache && jwksCache.expiresAt > Date.now()) return jwksCache.keys
  const r = await fetch(JWKS_URL)
  if (!r.ok) throw new Error(`JWKS fetch failed (${r.status})`)
  const {keys} = await r.json()
  jwksCache = {keys, expiresAt: Date.now() + 60 * 60 * 1000} // 1h cache
  return keys
}

function b64urlToBuffer(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  return Buffer.from(s, 'base64')
}

function jwkToPem(jwk) {
  // Convert JWK (RSA) → PEM via Node crypto's createPublicKey.
  return crypto.createPublicKey({key: jwk, format: 'jwk'}).export({type: 'spki', format: 'pem'})
}

export async function verifyGoogleIdToken(token, expectedAudience) {
  if (!token || token.split('.').length !== 3) throw new Error('malformed token')
  const [headerB64, payloadB64, sigB64] = token.split('.')
  const header = JSON.parse(b64urlToBuffer(headerB64).toString())
  const payload = JSON.parse(b64urlToBuffer(payloadB64).toString())

  if (!ISS.includes(payload.iss)) throw new Error(`bad issuer: ${payload.iss}`)
  if (expectedAudience && payload.aud !== expectedAudience) {
    throw new Error(`bad audience: ${payload.aud}`)
  }
  if (typeof payload.exp !== 'number' || payload.exp * 1000 < Date.now() - 60_000) {
    throw new Error('token expired')
  }

  const keys = await fetchJwks()
  const jwk = keys.find((k) => k.kid === header.kid)
  if (!jwk) throw new Error('signing key not found')

  const pem = jwkToPem(jwk)
  const verifier = crypto.createVerify('RSA-SHA256')
  verifier.update(`${headerB64}.${payloadB64}`)
  const sig = b64urlToBuffer(sigB64)
  if (!verifier.verify(pem, sig)) throw new Error('signature invalid')

  return payload
}
