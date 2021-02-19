# TOTP

Very simple timebase OTP library as used by Speed Welshpool in internal projects.

Based on RFC6238 and uses base32.js to handle secrets.

This implementation will interop with others online, e.g. this one from [Dan Hersam](https://totp.danhersam.com/).

# Usage

    const otp = require('./otp');

    // generate a 6 digit OTP from a given base32 secret
    const code = otp.totp(secret);
    // 123456

    // verify a OTP - returns true or false
    const result = otp.verify(secret, 123456);

    // generate a random secret
    otp.generateSecret();
