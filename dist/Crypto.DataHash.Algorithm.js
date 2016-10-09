/*
 * A JavaScript implementation of 
 * ******************************************************************************* * 
 * 'RSA Data Security, Inc. MD5 Message Digest Algorithm, as defined in RFC 1321', *
 * 'Secure Hash Algorithm, SHA-1,   as defined in FIPS 180-1',                     *
 * 'Secure Hash Algorithm, SHA-256, as defined in FIPS 180-2',                     *
 * 'Secure Hash Algorithm, SHA-512, as defined in FIPS 180-2',                     *
 * ******************************************************************************* * 
 * Version 1.0 Copyright (c) Sudheer Kaku 2016, distributed under the BSD License
 * contributors: Paul, Greg, Andrew, Ydnar, Lostinet
 */

var Crypto = Crypto || {};

/* hexCase: 0(false) - lowercase; 1(true) - UPPERCASE  */
/* b64Padding character. "=" for strict RFC compliance, Default to '' */
Crypto.Algorithm = Crypto.Algorithm || {
    VERSION: '1.0',

    HEX_MD5: function (input, hexCase) {
        var _H = this.Helpers;
        return _H.RSTR2HEX(_H.STR2RSTR(input, '0'), hexCase ? hexCase : false);
    },
    HEX_SHA1: function (input, hexCase) {
        var _H = this.Helpers;
        return _H.RSTR2HEX(_H.STR2RSTR(input, '1'), hexCase ? hexCase : false);
    },
    HEX_SHA256: function (input, hexCase) {
        var _H = this.Helpers;
        return _H.RSTR2HEX(_H.STR2RSTR(input, '2'), hexCase ? hexCase : false);
    },
    HEX_SHA512: function (input, hexCase) {
        var _H = this.Helpers;
        return _H.RSTR2HEX(_H.STR2RSTR(input, '3'), hexCase ? hexCase : false);
    },
    HEX_HMAC_MD5: function (key, data, hexCase) {
        var _H = this.Helpers;
        return _H.RSTR2HEX(_H.STR2RSTRwKey(key, data, '0'), hexCase ? hexCase : false);
    },
    HEX_HMAC_SHA1: function (key, data, hexCase) {
        var _H = this.Helpers;
        return _H.RSTR2HEX(_H.STR2RSTRwKey(key, data, '1'), hexCase ? hexCase : false);
    },
    HEX_HMAC_SHA256: function (key, data, hexCase) {
        var _H = this.Helpers;
        return _H.RSTR2HEX(_H.STR2RSTRwKey(key, data, '2'), hexCase ? hexCase : false);
    },
    HEX_HMAC_SHA512: function (key, data, hexCase) {
        var _H = this.Helpers;
        return _H.RSTR2HEX(_H.STR2RSTRwKey(key, data, '3'), hexCase ? hexCase : false);
    },

    B64_MD5: function (input, b64Padding) {
        var _H = this.Helpers;
        return _H.RSTR2B64(_H.STR2RSTR(input, '0'), b64Padding ? b64Padding : '');
    },
    B64_SHA1: function (input, b64Padding) {
        var _H = this.Helpers;
        return _H.RSTR2B64(_H.STR2RSTR(input, '1'), b64Padding ? b64Padding : '');
    },
    B64_SHA256: function (input, b64Padding) {
        var _H = this.Helpers;
        return _H.RSTR2B64(_H.STR2RSTR(input, '2'), b64Padding ? b64Padding : '');
    },
    B64_SHA512: function (input, b64Padding) {
        var _H = this.Helpers;
        return _H.RSTR2B64(_H.STR2RSTR(input, '3'), b64Padding ? b64Padding : '');
    },
    B64_HMAC_MD5: function (key, data, b64Padding) {
        var _H = this.Helpers;
        return _H.RSTR2B64(_H.STR2RSTRwKey(key, data, '0'), b64Padding ? b64Padding : '');
    },
    B64_HMAC_SHA1: function (key, data, b64Padding) {
        var _H = this.Helpers;
        return _H.RSTR2B64(_H.STR2RSTRwKey(key, data, '1'), b64Padding ? b64Padding : '');
    },
    B64_HMAC_SHA256: function (key, data, b64Padding) {
        var _H = this.Helpers;
        return _H.RSTR2B64(_H.STR2RSTRwKey(key, data, '2'), b64Padding ? b64Padding : '');
    },
    B64_HMAC_SHA512: function (key, data, b64Padding) {
        var _H = this.Helpers;
        return _H.RSTR2B64(_H.STR2RSTRwKey(key, data, '3'), b64Padding ? b64Padding : '');
    },

    ANY_MD5: function (input, encoding) {
        var _H = this.Helpers;
        return _H.RSTR2ANY(_H.STR2RSTR(input, '0'), encoding ? encoding : '');
    },
    ANY_SHA1: function (input, encoding) {
        var _H = this.Helpers;
        return _H.RSTR2ANY(_H.STR2RSTR(input, '1'), encoding ? encoding : '');
    },
    ANY_SHA256: function (input, encoding) {
        var _H = this.Helpers;
        return _H.RSTR2ANY(_H.STR2RSTR(input, '2'), encoding ? encoding : '');
    },
    ANY_SHA512: function (input, encoding) {
        var _H = this.Helpers;
        return _H.RSTR2ANY(_H.STR2RSTR(input, '3'), encoding ? encoding : '');
    },
    ANY_HMAC_MD5: function (key, data, encoding) {
        var _H = this.Helpers;
        return _H.RSTR2ANY(_H.STR2RSTRwKey(key, data, '0'), encoding ? encoding : '');
    },
    ANY_HMAC_SHA1: function (key, data, encoding) {
        var _H = this.Helpers;
        return _H.RSTR2ANY(_H.STR2RSTRwKey(key, data, '1'), encoding ? encoding : '');
    },
    ANY_HMAC_SHA256: function (key, data, encoding) {
        var _H = this.Helpers;
        return _H.RSTR2ANY(_H.STR2RSTRwKey(key, data, '2'), encoding ? encoding : '');
    },
    ANY_HMAC_SHA512: function (key, data, encoding) {
        var _H = this.Helpers;
        return _H.RSTR2ANY(_H.STR2RSTRwKey(key, data, '3'), encoding ? encoding : '');
    },
};

Crypto.Algorithm.Helpers = Crypto.Algorithm.Helpers || {

    /* Encode a string as UTF-8. For efficiency, this assumes the input is valid UTF-16. */
    /* str2rstr_utf8 */
    EncodeUTF8: function (input) {
        var x, y, i = -1, output = '';

        while (++i < input.length) {
            /* Decode utf-16 surrogate pairs */
            x = input.charCodeAt(i);
            y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
            if (0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF) {
                x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
                i++;
            }

            /* Encode output as utf-8 */
            if (x <= 0x7F)
                output += String.fromCharCode(x);
            else if (x <= 0x7FF)
                output += String.fromCharCode(0xC0 | ((x >>> 6) & 0x1F), 0x80 | (x & 0x3F));
            else if (x <= 0xFFFF)
                output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F), 0x80 | ((x >>> 6) & 0x3F), 0x80 | (x & 0x3F));
            else if (x <= 0x1FFFFF)
                output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07), 0x80 | ((x >>> 12) & 0x3F), 0x80 | ((x >>> 6) & 0x3F), 0x80 | (x & 0x3F));
        }
        return output;
    },

    /* Decode a UTF-8 string to readable format. */
    /* utf8Decode */
    DecodeUTF8: function (input) {
        var i, l, ac, c1, c2, c3, arr = [];
        i = ac = c1 = c2 = c3 = 0;

        while (i < input.length) {
            c1 = input.charCodeAt(i);
            ac += 1;
            if (c1 < 128) {
                arr[ac] = String.fromCharCode(c1);
                i += 1;
            } else if (c1 > 191 && c1 < 224) {
                c2 = input.charCodeAt(i + 1);
                arr[ac] = String.fromCharCode(((c1 & 31) << 6) | (c2 & 63));
                i += 2;
            } else {
                c2 = input.charCodeAt(i + 1);
                c3 = input.charCodeAt(i + 2);
                arr[ac] = String.fromCharCode(((c1 & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
                i += 3;
            }
        }

        return arr.join('');
    },

    /* Encode a string as UTF-16 Little Endian. */
    /* str2rstr_utf16le */
    EncodeUTF16LE: function (input) {
        var output = "";
        for (var i = 0; i < input.length; i++)
            output += String.fromCharCode(input.charCodeAt(i) & 0xFF, (input.charCodeAt(i) >>> 8) & 0xFF);

        return output;
    },

    /* Encode a string as UTF-16 Big Endian. */
    /* str2rstr_utf16be */
    EncodeUTF16BE: function (input) {
        var output = "";
        for (var i = 0; i < input.length; i++)
            output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF, input.charCodeAt(i) & 0xFF);

        return output;
    },

    /* Decode a Little Endian UTF-16 string to readable format. */
    /* binl2rstr */
    DecodeUTF16LE: function (input) {
        var output = "";
        for (var i = 0; i < input.length * 32; i += 8)
            output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);

        return output;
    },

    /* Decode a Big Endian UTF-16 string to readable format. */
    /* binb2rstr */
    DecodeUTF16BE: function (input) {
        var output = "";
        for (var i = 0; i < input.length * 32; i += 8)
            output += String.fromCharCode((input[i >> 5] >>> (24 - i % 32)) & 0xFF);

        return output;
    },

    /* Add integers, wrapping at 2^32. This uses 16-bit operations internally to work around bugs in some JS interpreters. */
    Safe_Add: function (x, y) {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF),
            msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    },

    /* Bitwise rotate a 32-bit number to the left. */
    Bit_Rol: function (num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    },

    /* Convert a raw string to an array of little-endian words, Characters >255 have their high-byte silently ignored. */
    /* rstr2binl */
    RSTR2LE: function (input) {
        var output = Array(input.length >> 2);
        for (var i = 0; i < output.length; i++)
            output[i] = 0;
        for (var i = 0; i < input.length * 8; i += 8)
            output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
        return output;
    },

    /* Convert a raw string to an array of big-endian words, Characters >255 have their high-byte silently ignored. */
    /* rstr2binb */
    RSTR2BE: function (input) {
        var output = Array(input.length >> 2);
        for (var i = 0; i < output.length; i++)
            output[i] = 0;
        for (var i = 0; i < input.length * 8; i += 8)
            output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
        return output;
    },

    /* Convert a raw string to a hex string. */
    /* rstr2hex */
    RSTR2HEX: function (input, hexcase) {
        var hex_tab = hexcase ? '0123456789ABCDEF' : '0123456789abcdef',
            output = '', x;

        for (var i = 0; i < input.length; i++) {
            x = input.charCodeAt(i);
            output += hex_tab.charAt((x >>> 4) & 0x0F) + hex_tab.charAt(x & 0x0F);
        }
        return output;
    },

    /* Convert a raw string to a base-64 string */
    /* rstr2b64 */
    RSTR2B64: function (input, b64pad) {
        var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var output = "";
        var len = input.length;
        for (var i = 0; i < len; i += 3) {
            var triplet = (input.charCodeAt(i) << 16) | (i + 1 < len ? input.charCodeAt(i + 1) << 8 : 0) | (i + 2 < len ? input.charCodeAt(i + 2) : 0);
            for (var j = 0; j < 4; j++) {
                if (i * 8 + j * 6 > input.length * 8) output += b64pad;
                else output += tab.charAt((triplet >>> 6 * (3 - j)) & 0x3F);
            }
        }
        return output;
    },

    /* Convert a raw string to an arbitrary string encoding. */
    /* rstr2any */
    RSTR2ANY: function (input, encoding) {
        var divisor = encoding.length,
            i, j, q, x, quotient;

        /* Convert to an array of 16-bit big-endian values, forming the dividend */
        var dividend = Array(Math.ceil(input.length / 2));
        for (i = 0; i < dividend.length; i++) {
            dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
        }

        /*
         * Repeatedly perform a long division. The binary array forms the dividend,
         * the length of the encoding is the divisor. Once computed, the quotient
         * forms the dividend for the next step. All remainders are stored for later
         * use.
         */
        var full_length = Math.ceil(input.length * 8 / (Math.log(encoding.length) / Math.log(2)));
        var remainders = Array(full_length);
        for (j = 0; j < full_length; j++) {
            quotient = Array();
            x = 0;
            for (i = 0; i < dividend.length; i++) {
                x = (x << 16) + dividend[i];
                q = Math.floor(x / divisor);
                x -= q * divisor;
                if (quotient.length > 0 || q > 0)
                    quotient[quotient.length] = q;
            }
            remainders[j] = x;
            dividend = quotient;
        }

        /* Convert the remainders to the output string */
        var output = '';
        for (i = remainders.length - 1; i >= 0; i--)
            output += encoding.charAt(remainders[i]);

        return output;
    },

    /* MD5 / SHA1 / SHA256 / SHA512 - Convert2RawString */
    /* MD5 - 0, SHA1 - 1, SHA256 - 2, SHA512 - 3 */
    STR2RSTR: function (input, hashType) {
        var encodedValue = this.EncodeUTF8(input);
        var endianValue = (hashType === '0') ? this.RSTR2LE(encodedValue) : this.RSTR2BE(encodedValue);
        var hashedValue = null;
        switch (hashType) {
            case '0':
                hashedValue = this.MD5.LEArray2MD5(endianValue, encodedValue.length * 8);
                break;
            case '1':
                hashedValue = this.SHA1.BEArray2SHA1(endianValue, encodedValue.length * 8);
                break;
            case '2':
                hashedValue = this.SHA256.BEArray2SHA256(endianValue, encodedValue.length * 8);
                break;
            case '3':
                hashedValue = this.SHA512.BEArray2SHA512(endianValue, encodedValue.length * 8);
                break;
        }
        if (hashedValue === null)
            throw 'Something went wrong while converting endian to hashed value.';

        var rawString = (hashType === '0') ? this.DecodeUTF16LE(hashedValue) : this.DecodeUTF16BE(hashedValue);
        return rawString;
    },

    /* HMAC - Convert2RawStringWithKey */
    /* MD5 - 0, SHA1 - 1, SHA256 - 2, SHA512 - 3 */
    STR2RSTRwKey: function (key, data, hashType) {
        var encodedKey = this.EncodeUTF8(key),
            encodedData = this.EncodeUTF8(data);

        var endianKeyValue = hashType > 0 ? this.RSTR2BE(encodedKey) : this.RSTR2LE(encodedKey),
            endianDataValue = hashType > 0 ? this.RSTR2BE(encodedData) : this.RSTR2LE(encodedData);

        var len = (hashType === '3') ? 32 : 16;
        if (endianKeyValue.length > len) {
            switch (hashType) {
                case '0':
                    endianKeyValue = this.MD5.LEArray2MD5(endianKeyValue, encodedKey.length * 8);
                    break;
                case '1':
                    endianKeyValue = this.SHA1.BEArray2SHA1(endianKeyValue, encodedKey.length * 8);
                    break;
                case '2':
                    endianKeyValue = this.SHA256.BEArray2SHA256(endianKeyValue, encodedKey.length * 8);
                    break;
                case '3':
                    endianKeyValue = this.SHA512.BEArray2SHA512(endianKeyValue, encodedKey.length * 8);
                    break;
            }
        }

        var iPad = Array(len),
            oPad = Array(len);

        for (var i = 0; i < len; i++) {
            iPad[i] = endianKeyValue[i] ^ 0x36363636;
            oPad[i] = endianKeyValue[i] ^ 0x5C5C5C5C;
        }
        var rawString = null;
        switch (hashType) {
            case '0':
                var hash = this.MD5.LEArray2MD5(iPad.concat(endianDataValue), 512 + encodedData.length * 8);
                rawString = this.DecodeUTF16LE(this.MD5.LEArray2MD5(oPad.concat(hash), 512 + 128));
                break;
            case '1':
                var hash = this.SHA1.BEArray2SHA1(iPad.concat(endianDataValue), 512 + encodedData.length * 8);
                rawString = this.DecodeUTF16BE(this.SHA1.BEArray2SHA1(oPad.concat(hash), 512 + 160));
                break;
            case '2':
                var hash = this.SHA256.BEArray2SHA256(iPad.concat(endianDataValue), 512 + encodedData.length * 8);
                rawString = this.DecodeUTF16BE(this.SHA256.BEArray2SHA256(oPad.concat(hash), 512 + 256));
                break;
            case '3':
                var hash = this.SHA512.BEArray2SHA512(iPad.concat(endianDataValue), 1024 + encodedData.length * 8);
                rawString = this.DecodeUTF16BE(this.SHA512.BEArray2SHA512(oPad.concat(hash), 1024 + 512));
                break;
        }
        if (rawString === null)
            throw 'Something went wrong while converting endian value to raw string.';

        return rawString;
    }
};

Crypto.Algorithm.Helpers.MD5 = Crypto.Algorithm.Helpers.MD5 || {

    /* These functions implement the four basic operations the algorithm uses. */
    MD5_CMN: function (q, a, b, x, s, t) {
        var helpers = Crypto.Algorithm.Helpers;
        return helpers.Safe_Add(helpers.Bit_Rol(helpers.Safe_Add(helpers.Safe_Add(a, q), helpers.Safe_Add(x, t)), s), b);
    },
    MD5_FF: function (a, b, c, d, x, s, t) {
        return this.MD5_CMN((b & c) | ((~b) & d), a, b, x, s, t);
    },
    MD5_GG: function (a, b, c, d, x, s, t) {
        return this.MD5_CMN((b & d) | (c & (~d)), a, b, x, s, t);
    },
    MD5_HH: function (a, b, c, d, x, s, t) {
        return this.MD5_CMN(b ^ c ^ d, a, b, x, s, t);
    },
    MD5_II: function (a, b, c, d, x, s, t) {
        return this.MD5_CMN(c ^ (b | (~d)), a, b, x, s, t);
    },

    /* Calculate the MD5 of an array of little-endian words, and a bit length. */
    /* binl_md5 */
    LEArray2MD5: function (x, len) {

        /* append padding */
        x[len >> 5] |= 0x80 << ((len) % 32);
        x[(((len + 64) >>> 9) << 4) + 14] = len;

        var helpers = Crypto.Algorithm.Helpers;
        var a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;

        for (var i = 0; i < x.length; i += 16) {
            var olda = a, oldb = b, oldc = c, oldd = d;

            a = this.MD5_FF(a, b, c, d, x[i + 0], 7, -680876936);
            d = this.MD5_FF(d, a, b, c, x[i + 1], 12, -389564586);
            c = this.MD5_FF(c, d, a, b, x[i + 2], 17, 606105819);
            b = this.MD5_FF(b, c, d, a, x[i + 3], 22, -1044525330);
            a = this.MD5_FF(a, b, c, d, x[i + 4], 7, -176418897);
            d = this.MD5_FF(d, a, b, c, x[i + 5], 12, 1200080426);
            c = this.MD5_FF(c, d, a, b, x[i + 6], 17, -1473231341);
            b = this.MD5_FF(b, c, d, a, x[i + 7], 22, -45705983);
            a = this.MD5_FF(a, b, c, d, x[i + 8], 7, 1770035416);
            d = this.MD5_FF(d, a, b, c, x[i + 9], 12, -1958414417);
            c = this.MD5_FF(c, d, a, b, x[i + 10], 17, -42063);
            b = this.MD5_FF(b, c, d, a, x[i + 11], 22, -1990404162);
            a = this.MD5_FF(a, b, c, d, x[i + 12], 7, 1804603682);
            d = this.MD5_FF(d, a, b, c, x[i + 13], 12, -40341101);
            c = this.MD5_FF(c, d, a, b, x[i + 14], 17, -1502002290);
            b = this.MD5_FF(b, c, d, a, x[i + 15], 22, 1236535329);

            a = this.MD5_GG(a, b, c, d, x[i + 1], 5, -165796510);
            d = this.MD5_GG(d, a, b, c, x[i + 6], 9, -1069501632);
            c = this.MD5_GG(c, d, a, b, x[i + 11], 14, 643717713);
            b = this.MD5_GG(b, c, d, a, x[i + 0], 20, -373897302);
            a = this.MD5_GG(a, b, c, d, x[i + 5], 5, -701558691);
            d = this.MD5_GG(d, a, b, c, x[i + 10], 9, 38016083);
            c = this.MD5_GG(c, d, a, b, x[i + 15], 14, -660478335);
            b = this.MD5_GG(b, c, d, a, x[i + 4], 20, -405537848);
            a = this.MD5_GG(a, b, c, d, x[i + 9], 5, 568446438);
            d = this.MD5_GG(d, a, b, c, x[i + 14], 9, -1019803690);
            c = this.MD5_GG(c, d, a, b, x[i + 3], 14, -187363961);
            b = this.MD5_GG(b, c, d, a, x[i + 8], 20, 1163531501);
            a = this.MD5_GG(a, b, c, d, x[i + 13], 5, -1444681467);
            d = this.MD5_GG(d, a, b, c, x[i + 2], 9, -51403784);
            c = this.MD5_GG(c, d, a, b, x[i + 7], 14, 1735328473);
            b = this.MD5_GG(b, c, d, a, x[i + 12], 20, -1926607734);

            a = this.MD5_HH(a, b, c, d, x[i + 5], 4, -378558);
            d = this.MD5_HH(d, a, b, c, x[i + 8], 11, -2022574463);
            c = this.MD5_HH(c, d, a, b, x[i + 11], 16, 1839030562);
            b = this.MD5_HH(b, c, d, a, x[i + 14], 23, -35309556);
            a = this.MD5_HH(a, b, c, d, x[i + 1], 4, -1530992060);
            d = this.MD5_HH(d, a, b, c, x[i + 4], 11, 1272893353);
            c = this.MD5_HH(c, d, a, b, x[i + 7], 16, -155497632);
            b = this.MD5_HH(b, c, d, a, x[i + 10], 23, -1094730640);
            a = this.MD5_HH(a, b, c, d, x[i + 13], 4, 681279174);
            d = this.MD5_HH(d, a, b, c, x[i + 0], 11, -358537222);
            c = this.MD5_HH(c, d, a, b, x[i + 3], 16, -722521979);
            b = this.MD5_HH(b, c, d, a, x[i + 6], 23, 76029189);
            a = this.MD5_HH(a, b, c, d, x[i + 9], 4, -640364487);
            d = this.MD5_HH(d, a, b, c, x[i + 12], 11, -421815835);
            c = this.MD5_HH(c, d, a, b, x[i + 15], 16, 530742520);
            b = this.MD5_HH(b, c, d, a, x[i + 2], 23, -995338651);

            a = this.MD5_II(a, b, c, d, x[i + 0], 6, -198630844);
            d = this.MD5_II(d, a, b, c, x[i + 7], 10, 1126891415);
            c = this.MD5_II(c, d, a, b, x[i + 14], 15, -1416354905);
            b = this.MD5_II(b, c, d, a, x[i + 5], 21, -57434055);
            a = this.MD5_II(a, b, c, d, x[i + 12], 6, 1700485571);
            d = this.MD5_II(d, a, b, c, x[i + 3], 10, -1894986606);
            c = this.MD5_II(c, d, a, b, x[i + 10], 15, -1051523);
            b = this.MD5_II(b, c, d, a, x[i + 1], 21, -2054922799);
            a = this.MD5_II(a, b, c, d, x[i + 8], 6, 1873313359);
            d = this.MD5_II(d, a, b, c, x[i + 15], 10, -30611744);
            c = this.MD5_II(c, d, a, b, x[i + 6], 15, -1560198380);
            b = this.MD5_II(b, c, d, a, x[i + 13], 21, 1309151649);
            a = this.MD5_II(a, b, c, d, x[i + 4], 6, -145523070);
            d = this.MD5_II(d, a, b, c, x[i + 11], 10, -1120210379);
            c = this.MD5_II(c, d, a, b, x[i + 2], 15, 718787259);
            b = this.MD5_II(b, c, d, a, x[i + 9], 21, -343485551);

            a = helpers.Safe_Add(a, olda);
            b = helpers.Safe_Add(b, oldb);
            c = helpers.Safe_Add(c, oldc);
            d = helpers.Safe_Add(d, oldd);
        }
        return Array(a, b, c, d);
    },
};

Crypto.Algorithm.Helpers.SHA1 = Crypto.Algorithm.Helpers.SHA1 || {

    /* Perform the appropriate triplet combination function for the current iteration */
    SHA1_FT: function (t, b, c, d) {
        if (t < 20) return (b & c) | ((~b) & d);
        if (t < 40) return b ^ c ^ d;
        if (t < 60) return (b & c) | (b & d) | (c & d);
        return b ^ c ^ d;
    },

    /* Determine the appropriate additive constant for the current iteration */
    SHA1_KT: function (t) {
        return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 :
               (t < 60) ? -1894007588 : -899497514;
    },

    /* binb_sha1 */
    BEArray2SHA1: function (x, len) {

        /* append padding */
        x[len >> 5] |= 0x80 << (24 - len % 32);
        x[((len + 64 >> 9) << 4) + 15] = len;

        var helpers = Crypto.Algorithm.Helpers;
        var w = Array(80),
            a = 1732584193,
            b = -271733879,
            c = -1732584194,
            d = 271733878,
            e = -1009589776;

        for (var i = 0; i < x.length; i += 16) {
            var olda = a,
                oldb = b,
                oldc = c,
                oldd = d,
                olde = e;

            for (var j = 0; j < 80; j++) {
                if (j < 16) w[j] = x[i + j];
                else w[j] = helpers.Bit_Rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                var t = helpers.Safe_Add(helpers.Safe_Add(helpers.Bit_Rol(a, 5), this.SHA1_FT(j, b, c, d)), helpers.Safe_Add(helpers.Safe_Add(e, w[j]), this.SHA1_KT(j)));
                e = d;
                d = c;
                c = helpers.Bit_Rol(b, 30);
                b = a;
                a = t;
            }

            a = helpers.Safe_Add(a, olda);
            b = helpers.Safe_Add(b, oldb);
            c = helpers.Safe_Add(c, oldc);
            d = helpers.Safe_Add(d, oldd);
            e = helpers.Safe_Add(e, olde);
        }
        return Array(a, b, c, d, e);
    },
};

Crypto.Algorithm.Helpers.SHA256 = Crypto.Algorithm.Helpers.SHA256 || {

    SHA256_K: new Array
    (
        1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993,
        -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987,
        1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522,
        264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
        -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585,
        113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
        1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885,
        -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344,
        430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
        1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872,
        -1866530822, -1538233109, -1090935817, -965641998
    ),

    SHA256_S: function (X, n) { return (X >>> n) | (X << (32 - n)); },

    SHA256_R: function (X, n) { return (X >>> n); },

    SHA256_CH: function (x, y, z) { return ((x & y) ^ ((~x) & z)); },

    SHA256_MAJ: function (x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); },

    SHA256_Sigma0256: function (x) { return (this.SHA256_S(x, 2) ^ this.SHA256_S(x, 13) ^ this.SHA256_S(x, 22)); },

    SHA256_Sigma1256: function (x) { return (this.SHA256_S(x, 6) ^ this.SHA256_S(x, 11) ^ this.SHA256_S(x, 25)); },

    SHA256_Gamma0256: function (x) { return (this.SHA256_S(x, 7) ^ this.SHA256_S(x, 18) ^ this.SHA256_R(x, 3)); },

    SHA256_Gamma1256: function (x) { return (this.SHA256_S(x, 17) ^ this.SHA256_S(x, 19) ^ this.SHA256_R(x, 10)); },

    /* binb_sha256 */
    BEArray2SHA256: function (x, len) {
        var helpers = Crypto.Algorithm.Helpers;

        var HASH = new Array(1779033703, -1150833019, 1013904242, -1521486534, 1359893119, -1694144372, 528734635, 1541459225),
            W = new Array(64),
            a, b, c, d, e, f, g, h,
            i, j, T1, T2;

        /* append padding */
        x[len >> 5] |= 0x80 << (24 - len % 32);
        x[((len + 64 >> 9) << 4) + 15] = len;

        for (i = 0; i < x.length; i += 16) {
            a = HASH[0];
            b = HASH[1];
            c = HASH[2];
            d = HASH[3];
            e = HASH[4];
            f = HASH[5];
            g = HASH[6];
            h = HASH[7];

            for (j = 0; j < 64; j++) {
                if (j < 16) W[j] = x[j + i];
                else W[j] = helpers.Safe_Add(helpers.Safe_Add(helpers.Safe_Add(this.SHA256_Gamma1256(W[j - 2]), W[j - 7]), this.SHA256_Gamma0256(W[j - 15])), W[j - 16]);

                T1 = helpers.Safe_Add(helpers.Safe_Add(helpers.Safe_Add(helpers.Safe_Add(h, this.SHA256_Sigma1256(e)), this.SHA256_CH(e, f, g)), this.SHA256_K[j]), W[j]);
                T2 = helpers.Safe_Add(this.SHA256_Sigma0256(a), this.SHA256_MAJ(a, b, c));
                h = g;
                g = f;
                f = e;
                e = helpers.Safe_Add(d, T1);
                d = c;
                c = b;
                b = a;
                a = helpers.Safe_Add(T1, T2);
            }

            HASH[0] = helpers.Safe_Add(a, HASH[0]);
            HASH[1] = helpers.Safe_Add(b, HASH[1]);
            HASH[2] = helpers.Safe_Add(c, HASH[2]);
            HASH[3] = helpers.Safe_Add(d, HASH[3]);
            HASH[4] = helpers.Safe_Add(e, HASH[4]);
            HASH[5] = helpers.Safe_Add(f, HASH[5]);
            HASH[6] = helpers.Safe_Add(g, HASH[6]);
            HASH[7] = helpers.Safe_Add(h, HASH[7]);
        }
        return HASH;
    },
};

Crypto.Algorithm.Helpers.SHA512 = Crypto.Algorithm.Helpers.SHA512 || {

    SHA512_K: null,

    /* A constructor for 64-bit numbers */
    INT64: function (h, l) {
        this.h = h;
        this.l = l;
    },

    /* Copies src into dst, assuming both are 64-bit numbers */
    INT64Cpy: function (dst, src) {
        dst.h = src.h;
        dst.l = src.l;
    },

    /* Right-rotates a 64-bit number by shift Won't handle cases of shift>=32, The function revrrot() is for that. */
    INT64RRot: function (dst, x, shift) {
        dst.l = (x.l >>> shift) | (x.h << (32 - shift));
        dst.h = (x.h >>> shift) | (x.l << (32 - shift));
    },

    /* Reverses the dwords of the source and then rotates right by shift. This is equivalent to rotation by 32+shift */
    INT64RevRRot: function (dst, x, shift) {
        dst.l = (x.h >>> shift) | (x.l << (32 - shift));
        dst.h = (x.l >>> shift) | (x.h << (32 - shift));
    },

    /* Bitwise-shifts right a 64-bit number by shift, Won't handle shift>=32, but it's never needed in SHA512 */
    INT64BSft: function (dst, x, shift) {
        dst.l = (x.l >>> shift) | (x.h << (32 - shift));
        dst.h = (x.h >>> shift);
    },

    /* Adds two 64-bit numbers Like the original implementation, does not rely on 32-bit operations */
    INT64Add: function (dst, x, y) {
        var w0 = (x.l & 0xffff) + (y.l & 0xffff);
        var w1 = (x.l >>> 16) + (y.l >>> 16) + (w0 >>> 16);
        var w2 = (x.h & 0xffff) + (y.h & 0xffff) + (w1 >>> 16);
        var w3 = (x.h >>> 16) + (y.h >>> 16) + (w2 >>> 16);
        dst.l = (w0 & 0xffff) | (w1 << 16);
        dst.h = (w2 & 0xffff) | (w3 << 16);
    },

    /* Same, except with 4 addends. Works faster than adding them one by one */
    INT64Add4: function (dst, a, b, c, d) {
        var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff);
        var w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (w0 >>> 16);
        var w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (w1 >>> 16);
        var w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (w2 >>> 16);
        dst.l = (w0 & 0xffff) | (w1 << 16);
        dst.h = (w2 & 0xffff) | (w3 << 16);
    },

    /* Same, except with 5 addends */
    INT64Add5: function (dst, a, b, c, d, e) {
        var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff) + (e.l & 0xffff);
        var w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (e.l >>> 16) + (w0 >>> 16);
        var w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (e.h & 0xffff) + (w1 >>> 16);
        var w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (e.h >>> 16) + (w2 >>> 16);
        dst.l = (w0 & 0xffff) | (w1 << 16);
        dst.h = (w2 & 0xffff) | (w3 << 16);
    },

    /* binb_sha512 */
    BEArray2SHA512: function (x, len) {
        if (this.SHA512_K == undefined) {
            /* SHA512 constants */
            this.SHA512_K = new Array
            (
                new this.INT64(0x428a2f98, -685199838), new this.INT64(0x71374491, 0x23ef65cd),
                new this.INT64(-1245643825, -330482897), new this.INT64(-373957723, -2121671748),
                new this.INT64(0x3956c25b, -213338824), new this.INT64(0x59f111f1, -1241133031),
                new this.INT64(-1841331548, -1357295717), new this.INT64(-1424204075, -630357736),
                new this.INT64(-670586216, -1560083902), new this.INT64(0x12835b01, 0x45706fbe),
                new this.INT64(0x243185be, 0x4ee4b28c), new this.INT64(0x550c7dc3, -704662302),
                new this.INT64(0x72be5d74, -226784913), new this.INT64(-2132889090, 0x3b1696b1),
                new this.INT64(-1680079193, 0x25c71235), new this.INT64(-1046744716, -815192428),
                new this.INT64(-459576895, -1628353838), new this.INT64(-272742522, 0x384f25e3),
                new this.INT64(0xfc19dc6, -1953704523), new this.INT64(0x240ca1cc, 0x77ac9c65),
                new this.INT64(0x2de92c6f, 0x592b0275), new this.INT64(0x4a7484aa, 0x6ea6e483),
                new this.INT64(0x5cb0a9dc, -1119749164), new this.INT64(0x76f988da, -2096016459),
                new this.INT64(-1740746414, -295247957), new this.INT64(-1473132947, 0x2db43210),
                new this.INT64(-1341970488, -1728372417), new this.INT64(-1084653625, -1091629340),
                new this.INT64(-958395405, 0x3da88fc2), new this.INT64(-710438585, -1828018395),
                new this.INT64(0x6ca6351, -536640913), new this.INT64(0x14292967, 0xa0e6e70),
                new this.INT64(0x27b70a85, 0x46d22ffc), new this.INT64(0x2e1b2138, 0x5c26c926),
                new this.INT64(0x4d2c6dfc, 0x5ac42aed), new this.INT64(0x53380d13, -1651133473),
                new this.INT64(0x650a7354, -1951439906), new this.INT64(0x766a0abb, 0x3c77b2a8),
                new this.INT64(-2117940946, 0x47edaee6), new this.INT64(-1838011259, 0x1482353b),
                new this.INT64(-1564481375, 0x4cf10364), new this.INT64(-1474664885, -1136513023),
                new this.INT64(-1035236496, -789014639), new this.INT64(-949202525, 0x654be30),
                new this.INT64(-778901479, -688958952), new this.INT64(-694614492, 0x5565a910),
                new this.INT64(-200395387, 0x5771202a), new this.INT64(0x106aa070, 0x32bbd1b8),
                new this.INT64(0x19a4c116, -1194143544), new this.INT64(0x1e376c08, 0x5141ab53),
                new this.INT64(0x2748774c, -544281703), new this.INT64(0x34b0bcb5, -509917016),
                new this.INT64(0x391c0cb3, -976659869), new this.INT64(0x4ed8aa4a, -482243893),
                new this.INT64(0x5b9cca4f, 0x7763e373), new this.INT64(0x682e6ff3, -692930397),
                new this.INT64(0x748f82ee, 0x5defb2fc), new this.INT64(0x78a5636f, 0x43172f60),
                new this.INT64(-2067236844, -1578062990), new this.INT64(-1933114872, 0x1a6439ec),
                new this.INT64(-1866530822, 0x23631e28), new this.INT64(-1538233109, -561857047),
                new this.INT64(-1090935817, -1295615723), new this.INT64(-965641998, -479046869),
                new this.INT64(-903397682, -366583396), new this.INT64(-779700025, 0x21c0c207),
                new this.INT64(-354779690, -840897762), new this.INT64(-176337025, -294727304),
                new this.INT64(0x6f067aa, 0x72176fba), new this.INT64(0xa637dc5, -1563912026),
                new this.INT64(0x113f9804, -1090974290), new this.INT64(0x1b710b35, 0x131c471b),
                new this.INT64(0x28db77f5, 0x23047d84), new this.INT64(0x32caab7b, 0x40c72493),
                new this.INT64(0x3c9ebe0a, 0x15c9bebc), new this.INT64(0x431d67c4, -1676669620),
                new this.INT64(0x4cc5d4be, -885112138), new this.INT64(0x597f299c, -60457430),
                new this.INT64(0x5fcb6fab, 0x3ad6faec), new this.INT64(0x6c44198c, 0x4a475817)
            );
        }

        /* Initial hash values */
        var H = new Array
        (
          new this.INT64(0x6a09e667, -205731576),
          new this.INT64(-1150833019, -2067093701),
          new this.INT64(0x3c6ef372, -23791573),
          new this.INT64(-1521486534, 0x5f1d36f1),
          new this.INT64(0x510e527f, -1377402159),
          new this.INT64(-1694144372, 0x2b3e6c1f),
          new this.INT64(0x1f83d9ab, -79577749),
          new this.INT64(0x5be0cd19, 0x137e2179)
        );

        var T1 = new this.INT64(0, 0),
            T2 = new this.INT64(0, 0),
            a = new this.INT64(0, 0),
            b = new this.INT64(0, 0),
            c = new this.INT64(0, 0),
            d = new this.INT64(0, 0),
            e = new this.INT64(0, 0),
            f = new this.INT64(0, 0),
            g = new this.INT64(0, 0),
            h = new this.INT64(0, 0),
            /* Temporary variables not specified by the document */
            s0 = new this.INT64(0, 0),
            s1 = new this.INT64(0, 0),
            Ch = new this.INT64(0, 0),
            Maj = new this.INT64(0, 0),
            r1 = new this.INT64(0, 0),
            r2 = new this.INT64(0, 0),
            r3 = new this.INT64(0, 0);
        var j, i;
        var W = new Array(80);
        for (i = 0; i < 80; i++)
            W[i] = new this.INT64(0, 0);

        /* append padding to the source string. The format is described in the FIPS. */
        x[len >> 5] |= 0x80 << (24 - (len & 0x1f));
        x[((len + 128 >> 10) << 5) + 31] = len;

        /* 32 dwords is the block size */
        for (i = 0; i < x.length; i += 32)
        {
            this.INT64Cpy(a, H[0]);
            this.INT64Cpy(b, H[1]);
            this.INT64Cpy(c, H[2]);
            this.INT64Cpy(d, H[3]);
            this.INT64Cpy(e, H[4]);
            this.INT64Cpy(f, H[5]);
            this.INT64Cpy(g, H[6]);
            this.INT64Cpy(h, H[7]);

            for (j = 0; j < 16; j++) {
                W[j].h = x[i + 2 * j];
                W[j].l = x[i + 2 * j + 1];
            }

            for (j = 16; j < 80; j++) {
                /* sigma1 */
                this.INT64RRot(r1, W[j - 2], 19);
                this.INT64RevRRot(r2, W[j - 2], 29);
                this.INT64BSft(r3, W[j - 2], 6);
                s1.l = r1.l ^ r2.l ^ r3.l;
                s1.h = r1.h ^ r2.h ^ r3.h;
                /* sigma0 */
                this.INT64RRot(r1, W[j - 15], 1);
                this.INT64RRot(r2, W[j - 15], 8);
                this.INT64BSft(r3, W[j - 15], 7);
                s0.l = r1.l ^ r2.l ^ r3.l;
                s0.h = r1.h ^ r2.h ^ r3.h;

                this.INT64Add4(W[j], s1, W[j - 7], s0, W[j - 16]);
            }

            for (j = 0; j < 80; j++) {
                /* Ch */
                Ch.l = (e.l & f.l) ^ (~e.l & g.l);
                Ch.h = (e.h & f.h) ^ (~e.h & g.h);

                /* Sigma1 */
                this.INT64RRot(r1, e, 14);
                this.INT64RRot(r2, e, 18);
                this.INT64RevRRot(r3, e, 9);
                s1.l = r1.l ^ r2.l ^ r3.l;
                s1.h = r1.h ^ r2.h ^ r3.h;

                /* Sigma0 */
                this.INT64RRot(r1, a, 28);
                this.INT64RevRRot(r2, a, 2);
                this.INT64RevRRot(r3, a, 7);
                s0.l = r1.l ^ r2.l ^ r3.l;
                s0.h = r1.h ^ r2.h ^ r3.h;

                /* Maj */
                Maj.l = (a.l & b.l) ^ (a.l & c.l) ^ (b.l & c.l);
                Maj.h = (a.h & b.h) ^ (a.h & c.h) ^ (b.h & c.h);

                this.INT64Add5(T1, h, s1, Ch, this.SHA512_K[j], W[j]);
                this.INT64Add(T2, s0, Maj);

                this.INT64Cpy(h, g);
                this.INT64Cpy(g, f);
                this.INT64Cpy(f, e);
                this.INT64Add(e, d, T1);
                this.INT64Cpy(d, c);
                this.INT64Cpy(c, b);
                this.INT64Cpy(b, a);
                this.INT64Add(a, T1, T2);
            }
            this.INT64Add(H[0], H[0], a);
            this.INT64Add(H[1], H[1], b);
            this.INT64Add(H[2], H[2], c);
            this.INT64Add(H[3], H[3], d);
            this.INT64Add(H[4], H[4], e);
            this.INT64Add(H[5], H[5], f);
            this.INT64Add(H[6], H[6], g);
            this.INT64Add(H[7], H[7], h);
        }

        /* represent the hash as an array of 32-bit dwords */
        var hash = new Array(16);
        for (i = 0; i < 8; i++) {
            hash[2 * i] = H[i].h;
            hash[2 * i + 1] = H[i].l;
        }
        return hash;
    },
};
