var psl = require("psl");
var { URL } = require("url");

class Fido2LibError extends Error {
    constructor(message, type) {
        super();
        Error.captureStackTrace(this, this.constructor);
        this.name = this.constructor.name;
        this.message = message;
        this.extra = type;
    }
}

// borrowed from:
// https://github.com/niklasvh/base64-arraybuffer/blob/master/lib/base64-arraybuffer.js
// modified to base64url by Yuriy :)
/*
 * base64-arraybuffer
 * https://github.com/niklasvh/base64-arraybuffer
 *
 * Copyright (c) 2012 Niklas von Hertzen
 * Licensed under the MIT license.
 */
var b64UrlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
var b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Use a lookup table to find the index.
var lookupNormal = new Uint8Array(256);
for (var i = 0; i < b64Chars.length; i++) {
    lookupNormal[b64Chars.charCodeAt(i)] = i;
}
var lookupUrl = new Uint8Array(256);
for (var i = 0; i < b64UrlChars.length; i++) {
    lookupUrl[b64UrlChars.charCodeAt(i)] = i;
}

function b64decode(base64) {
    var bufferLength = base64.length * 0.75,
        len = base64.length,
        i, p = 0,
        encoded1, encoded2, encoded3, encoded4;

    if (base64[base64.length - 1] === "=") {
        bufferLength--;
        if (base64[base64.length - 2] === "=") {
            bufferLength--;
        }
    }

    var arraybuffer = new ArrayBuffer(bufferLength),
        bytes = new Uint8Array(arraybuffer);

    for (i = 0; i < len; i += 4) {
        encoded1 = lookup[base64.charCodeAt(i)];
        encoded2 = lookup[base64.charCodeAt(i + 1)];
        encoded3 = lookup[base64.charCodeAt(i + 2)];
        encoded4 = lookup[base64.charCodeAt(i + 3)];

        bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
        bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
        bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
    }

    return arraybuffer;
}

function b64encode(chars, lookup, arraybuffer) {
    console.log("b64encode");
    var bytes = new Uint8Array(arraybuffer),
        i, len = bytes.length,
        base64 = "";

    for (i = 0; i < len; i += 3) {
        base64 += chars[bytes[i] >> 2];
        base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
        base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
        base64 += chars[bytes[i + 2] & 63];
    }

    if ((len % 3) === 2) {
        base64 = base64.substring(0, base64.length - 1) + "=";
    } else if (len % 3 === 1) {
        base64 = base64.substring(0, base64.length - 2) + "==";
    }

    return base64;
}
var b64NormalDecode = b64decode.bind(null, b64Chars, lookupNormal);
var b64NormalEncode = b64encode.bind(null, b64Chars, lookupNormal);
var b64UrlDecode = b64decode.bind(null, b64UrlChars, lookupUrl);
var b64UrlEncode = b64encode.bind(null, b64UrlChars, lookupUrl);

// TODO: remove this debug code
function printHex(msg, buf) {
    // if the buffer was a TypedArray (e.g. Uint8Array), grab its buffer and use that
    if (ArrayBuffer.isView(buf) && buf.buffer instanceof ArrayBuffer) {
        buf = buf.buffer;
    }

    // check the arguments
    if ((typeof msg != "string") ||
        (typeof buf != "object")) {
        console.log("Bad args to printHex");
        return;
    }
    if (!(buf instanceof ArrayBuffer)) {
        console.log("Attempted printHex with non-ArrayBuffer:", buf);
        return;
    }
    // print the buffer as a 16 byte long hex string
    var arr = new Uint8Array(buf);
    var len = buf.byteLength;
    var i, str = "";
    console.log(msg);
    for (i = 0; i < len; i++) {
        var hexch = arr[i].toString(16);
        hexch = (hexch.length == 1) ? ("0" + hexch) : hexch;
        str += hexch.toUpperCase() + " ";
        if (i && !((i + 1) % 16)) {
            console.log(str);
            str = "";
        }
    }
    // print the remaining bytes
    if ((i) % 16) {
        console.log(str);
    }
}

function coerceToBase64Url(thing, name) {
    // Array to Uint8Array
    if (Array.isArray(thing)) {
        thing = Uint8Array.from(thing);
    }

    // Uint8Array, etc. to ArrayBuffer
    if (thing.buffer instanceof ArrayBuffer && !(thing instanceof Buffer)) {
        thing = thing.buffer;
    }

    // ArrayBuffer to Buffer
    if (thing instanceof ArrayBuffer && !(thing instanceof Buffer)) {
        thing = new Buffer(thing);
    }

    // Buffer to base64 string
    if (thing instanceof Buffer) {
        thing = thing.toString("base64");
    }

    if (typeof thing !== "string") {
        throw new Error(`couldn't coerce '${name}' to string`);
    }

    // base64 to base64url
    // NOTE: "=" at the end of challenge is optional, strip it off here so that it's compatible with client
    thing = thing.replace(/\+/g, "-").replace(/\//g, "_").replace(/=*$/g, "");

    return thing;
}

function coerceToArrayBuffer(buf, name) {
    if (buf instanceof Buffer || Array.isArray(buf)) {
        buf = new Uint8Array(buf);
    }

    if (buf instanceof Uint8Array) {
        buf = buf.buffer;
    }

    if (!(buf instanceof ArrayBuffer)) {
        throw new TypeError(`could not coerce '${name}' to ArrayBuffer`);
    }

    return buf;
}

function isBase64Url(str) {
    return !!str.match(/^[A-Za-z0-9\-_]+={0,2}$/);
}

function checkOrigin(str) {
    var originUrl = new URL(str);
    var origin = originUrl.origin;

    if (origin !== str) {
        throw new Error("origin was malformatted");
    }

    if (originUrl.protocol !== "https:") {
        throw new Error("origin should be https");
    }

    if (!psl.isValid(originUrl.hostname) && originUrl.hostname !== "localhost") {
        throw new Error("origin is not a valid eTLD+1");
    }

    return origin;
}

module.exports = {
    printHex,
    // b64NormalDecode,
    // b64NormalEncode,
    // b64UrlDecode,
    // b64UrlEncode,
    Fido2LibError,
    coerceToBase64Url,
    coerceToArrayBuffer,
    isBase64Url,
    checkOrigin
};