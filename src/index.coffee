import jsSHA from 'jssha'
import Base from 'base-2n'

Base64 = Base(6, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
Base32 = Base(5, "abcdefghijklmnopqrstuvwxyz234567")

totp = (now, secret)->
  sha = new jsSHA "SHA-1", "B64"
  sha.setHMACKey Base32.toHex(secret), "HEX"
  sha.update Base64.byNumber 8, now // 30000
  hex = sha.getHMAC "HEX"
  offset = 2 * parseInt hex[-1..], 16
  key = 0x7fffffff & parseInt hex[offset..][0..7], 16
  "000000#{key}"[-6..]

old = 0
tick = ({ seed, diff, otk })->
  now = new Date - diff
  time = 30 - (now // 1000) % 30
  if old < time
    otk = totp now, seed
  old = time
  { time, otk }

export default { to_otk, tick }
