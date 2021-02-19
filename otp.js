const base32 = require("base32.js");
const crypto = require("crypto");

// Private interface

/**
 * Return a 6 digit OTP from the passed message and secret.
 * @param {Buffer} msgBuf the message as a Buffer
 * @param {secret} secret the secret in Base32 format
 */
function otpFromBuffer(msgBuf, secret) {
  // create a hmac-sha1 digest of the msg and secret. base32 decode the secret to its hex value and create Buffer() object from it.
  let hmac = crypto.createHmac(
    "sha1",
    Buffer.from(base32.decode(secret.replace(/\s/g, ""))) // strip out any whitespace in case it has been formatted in 4 char groups
  );

  hmac.update(msgBuf);

  let bufDigest = Buffer.from(hmac.digest("hex"), "hex");

  // get the last bit - this will be out offset
  let offset = bufDigest[bufDigest.length - 1] & 0xf;

  // get 4 bytes from the offset position
  // use bitwise AND mask, << shift and OR to create a 31 bit integer from each hex byte
  let code =
    ((bufDigest[offset] & 0x7f) << 24) |
    ((bufDigest[offset + 1] & 0xff) << 16) |
    ((bufDigest[offset + 2] & 0xff) << 8) |
    (bufDigest[offset + 3] & 0xff);

  // return the last 6 chars. mod 10^6 is great and all but this saves having
  // to handle padding if the code starts with any 0s
  return ("" + code).substr(-6);
}

let otp = {};

/**
 * Helper function to generate a 20 byte long random secret
 * The resultant base32 string will be 32 chars long and can be resembled as 8 groups of 4
 *
 * @returns {object} containing the secret bytes in hex form and base32 encoded
 */
otp.generateSecret = function () {
  let buffer = crypto.randomBytes(20);
  let hex = buffer.toString("hex");
  let b32 = base32.encode(buffer);

  return {
    hex: hex,
    base32: b32,
  };
};

/**
 * Returns a 6 digit TOTP for the current time
 *
 * @param {string} secret the base32 secret to use in HMAC-SHA1
 */
otp.totp = function (secret) {
  let msgBuf = this.epochIteration();
  let otp = otpFromBuffer(msgBuf, secret);
  return otp;
};

/**
 * Verify a given OTP code. For convenience, we will try to match against the time window either side of the current.
 * As per RFC6238 this will allow for delays in the network, time sync or indeed the user themselves.
 * @param {string} secret the base32 secret
 * @param {string} code the 6 digit OTP code provided by the authenticatee
 */
otp.verify = function (secret, code) {
  let currentIteration = this.epochIteration();
  let previousIteration = this.epochIteration(-1);
  let nextIteration = this.epochIteration(1);

  if (otpFromBuffer(currentIteration, secret) === code) {
    return true;
  }

  if (otpFromBuffer(previousIteration, secret) === code) {
    return true;
  }

  if (otpFromBuffer(nextIteration, secret) === code) {
    return true;
  }

  return false;
};

/**
 * Return a Buffer representing the padded 16 character hex value for the epoch iteration.
 * Increments by 1 for every STEP since the Unix Epoch.
 * e.g. 000000000333f7d0
 *
 * @param {int} iterOffset optional offset the iteration by this value, default 0 (current). -1 would get the previous, 1 would get the next. Useful for
 *  creating several OTP's based on a window.
 * @param {int} step optional time step, default 30 seconds
 * @param {int} time optional Unix time value, default is the current Unix time stamp.
 */
otp.epochIteration = function (iterOffset, step, time) {
  step = step || 30;
  iterOffset = iterOffset === undefined || iterOffset === "" ? 0 : iterOffset;
  let unixTime = time || new Date().getTime() / 1000;
  const iter = Math.floor(unixTime / step) + iterOffset;
  const hexIter = iter.toString(16);
  let padded = ("0000000000000000" + hexIter).slice(-16);
  return Buffer.from(padded, "hex");
};

module.exports = otp;
