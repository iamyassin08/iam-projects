// RFC 6238 TOTP in the browser (WebCrypto HMAC-SHA1), used by the demo
// virtual authenticator. Same algorithm Google / Microsoft Authenticator use.
function base32ToBytes(s) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0, val = 0
  const out = []
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const i = alpha.indexOf(c)
    if (i < 0) continue
    val = (val << 5) | i
    bits += 5
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8 }
  }
  return new Uint8Array(out)
}

export async function totp(secret, at = Date.now()) {
  const counter = Math.floor(at / 1000 / 30)
  const msg = new ArrayBuffer(8)
  new DataView(msg).setUint32(4, counter)
  new DataView(msg).setUint32(0, Math.floor(counter / 2 ** 32))
  const key = await crypto.subtle.importKey('raw', base32ToBytes(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg))
  const off = h[h.length - 1] & 15
  const code = (((h[off] & 127) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]) % 1e6
  return String(code).padStart(6, '0')
}

export const secondsLeft = () => 30 - (Math.floor(Date.now() / 1000) % 30)
