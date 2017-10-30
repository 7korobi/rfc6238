// Generated by CoffeeScript 2.0.1
var Base32, Base64, tick, to_otk;

import jsSHA from 'jssha';

import Base from 'base-2n';

Base64 = Base(6, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

Base32 = Base(5, "abcdefghijklmnopqrstuvwxyz234567");

to_otk = function (now, secret) {
  var hex, key, offset, sha;
  sha = new jsSHA("SHA-1", "B64");
  sha.setHMACKey(Base32.toHex(secret), "HEX");
  sha.update(Base64.byNumber(8, Math.floor(now / 30000)));
  hex = sha.getHMAC("HEX");
  offset = 2 * parseInt(hex.slice(-1), 16);
  key = 0x7fffffff & parseInt(hex.slice(offset).slice(0, 8), 16);
  return `000000${key}`.slice(-6);
};

tick = function (msec, seed, cb) {
  var old, ticker;
  old = 0;
  ticker = function () {
    var now, otk, time;
    now = new Date() - diff;
    time = 30 - Math.floor(now / 1000) % 30;
    if (old < time) {
      otk = to_otk(now, seed);
    }
    old = time;
    return cb({ time, otk });
  };
  ticker();
  return setInterval(f, msec);
};

export default { to_otk, tick };
//# sourceMappingURL=index.js.map
