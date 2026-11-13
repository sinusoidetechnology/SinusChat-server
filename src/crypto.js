// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

'use strict'

const crypto = require('crypto')

const { AUTH_PROOF_SECRET, TURN_SECRET, UPLOAD_TOKEN_SECRET } = require('./config')

const sha256 = (data) => crypto.createHash('sha256').update(data).digest()
const sha256Hex = (data) => crypto.createHash('sha256').update(data).digest('hex')

const randomHex = (bytes) => crypto.randomBytes(bytes).toString('hex')
const randomBase64Url = (bytes) => crypto.randomBytes(bytes).toString('base64url')
const randomUuid = () => crypto.randomUUID()

// HMAC wspólny z auth.php: kody z e-maila i dowody logowania.
function proofHmacHex(data) {
  return crypto.createHmac('sha256', AUTH_PROOF_SECRET).update(data).digest('hex')
}

// HMAC wspólny z upload.php: tokeny wysyłki, przekaźnik, kasowanie i nazwy zdjęć.
function uploadHmacHex(data) {
  return crypto.createHmac('sha256', UPLOAD_TOKEN_SECRET).update(data).digest('hex')
}

function turnCredential(username) {
  return crypto.createHmac('sha1', TURN_SECRET).update(username).digest('base64')
}

function sameHex(a, b) {
  const x = Buffer.from(String(a), 'utf8')
  const y = Buffer.from(String(b), 'utf8')
  return x.length === y.length && crypto.timingSafeEqual(x, y)
}

function secretEquals(a, b) {
  return crypto.timingSafeEqual(sha256(a), sha256(b))
}

function hashAccessKey(akB64) {
  return sha256Hex(Buffer.from(akB64, 'base64'))
}

function accessKeyMatches(uaHash, akB64) {
  if (!uaHash || typeof akB64 !== 'string' || !akB64 || akB64.length > 64) return false
  return sameHex(hashAccessKey(akB64), uaHash)
}

function keyFingerprint(keyB64) {
  return sha256Hex(Buffer.from(keyB64, 'base64')).slice(0, 16)
}

function leadingZeroBits(buf) {
  let n = 0
  for (const byte of buf) {
    if (byte === 0) { n += 8; continue }
    for (let b = 7; b >= 0; b--) { if (byte & (1 << b)) return n; n++ }
  }
  return n
}

function ed25519Verify(pubB64, message, sigB64) {
  try {
    const raw = Buffer.from(String(pubB64), 'base64')
    const sig = Buffer.from(String(sigB64), 'base64')
    if (raw.length !== 32 || sig.length !== 64) return false
    const key = crypto.createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]),
      format: 'der', type: 'spki'
    })
    return crypto.verify(null, Buffer.from(message, 'utf8'), key, sig)
  } catch (_) { return false }
}

function signRs256(data, privateKey) {
  return crypto.sign('RSA-SHA256', Buffer.from(data), privateKey).toString('base64url')
}

module.exports = {
  sha256, sha256Hex, randomHex, randomBase64Url, randomUuid, proofHmacHex, uploadHmacHex,
  turnCredential, sameHex, secretEquals, hashAccessKey, accessKeyMatches, keyFingerprint,
  leadingZeroBits, ed25519Verify, signRs256
}
