// Generated by CoffeeScript 2.0.2
var Base32, Base64, at, old_seed, old_time, tick;

import jsSHA from 'jssha';

import Base from 'base-2n';

Base64 = Base(6, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

Base32 = Base(5, "abcdefghijklmnopqrstuvwxyz234567");

at = function (now, secret) {
  var hex, key, offset, sha;
  if (!secret) {
    return "";
  }
  sha = new jsSHA("SHA-1", "B64");
  sha.setHMACKey(Base32.toHex(secret), "HEX");
  sha.update(Base64.byNumber(8, Math.floor(now / 30000)));
  hex = sha.getHMAC("HEX");
  offset = 2 * parseInt(hex.slice(-1), 16);
  key = 0x7fffffff & parseInt(hex.slice(offset).slice(0, 8), 16);
  return `000000${key}`.slice(-6);
};

old_time = 0;

old_seed = "";

tick = function ({ seed, diff, totp }) {
  var now, time;
  now = new Date() - diff;
  time = 30 - Math.floor(now / 1000) % 30;
  if (old_time < time || old_seed !== seed) {
    totp = at(now, seed);
  }
  old_seed = seed;
  old_time = time;
  return { time, totp };
};

export default { at, tick };
//# sourceMappingURL=index.js.map
