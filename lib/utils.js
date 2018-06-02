"use strict";

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

/* istanbul ignore next */
function printHex(msg, buf) {
    // if the buffer was a TypedArray (e.g. Uint8Array), grab its buffer and use that
    if (ArrayBuffer.isView(buf) && buf.buffer instanceof ArrayBuffer) {
        buf = buf.buffer;
    }

    // check the arguments
    if ((typeof msg != "string") ||
        (typeof buf != "object")) {
        console.log("Bad args to printHex"); // eslint-disable-line no-console
        return;
    }
    if (!(buf instanceof ArrayBuffer)) {
        console.log("Attempted printHex with non-ArrayBuffer:", buf); // eslint-disable-line no-console
        return;
    }

    // print the buffer as a 16 byte long hex string
    var arr = new Uint8Array(buf);
    var len = buf.byteLength;
    var i, str = "";
    console.log(msg, `(${buf.byteLength} bytes)`); // eslint-disable-line no-console
    for (i = 0; i < len; i++) {
        var hexch = arr[i].toString(16);
        hexch = (hexch.length == 1) ? ("0" + hexch) : hexch;
        str += hexch.toUpperCase() + " ";
        if (i && !((i + 1) % 16)) {
            console.log(str); // eslint-disable-line no-console
            str = "";
        }
    }
    // print the remaining bytes
    if ((i) % 16) {
        console.log(str); // eslint-disable-line no-console
    }
}

function coerceToBase64(thing, name) {
    if (!name) {
        throw new TypeError("name not specified in coerceToBase64");
    }

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

    return thing;
}

function coerceToBase64Url(thing, name) {
    if (!name) {
        throw new TypeError("name not specified in coerceToBase64Url");
    }

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
    if (!name) {
        throw new TypeError("name not specified in coerceToArrayBuffer");
    }

    if (typeof buf === "string") {
        // base64url to base64
        buf = buf.replace(/-/g, "+").replace(/_/g, "/");
        // base64 to Buffer
        buf = Buffer.from(buf, "base64");
    }

    // Buffer or Array to Uint8Array
    if (buf instanceof Buffer || Array.isArray(buf)) {
        buf = new Uint8Array(buf);
    }

    // Uint8Array to ArrayBuffer
    if (buf instanceof Uint8Array) {
        buf = buf.buffer;
    }

    // error if none of the above worked
    if (!(buf instanceof ArrayBuffer)) {
        throw new TypeError(`could not coerce '${name}' to ArrayBuffer`);
    }

    return buf;
}

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
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

function bufEqual(a, b) {
    var len = a.length;

    if (len !== b.length) {
        return false;
    }

    for (var i = 0; i < len; i++) {
        if (a.readUInt8(i) !== b.readUInt8(i)) {
            return false;
        }
    }

    return true;
}

function abEqual(a, b) {
    var len = a.byteLength;

    if (len !== b.byteLength) {
        return false;
    }

    a = new Uint8Array(a);
    b = new Uint8Array(b);
    for (let i = 0; i < len; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }

    return true;
}


function isPem(pem) {
    if (typeof pem !== "string") {
        return false;
    }

    var pemRegex = /^-----BEGIN PUBLIC KEY-----$\n([A-Za-z0-9+/=]|\n)*^-----END PUBLIC KEY-----$/m;
    return pem.match(pemRegex);
}

function isPositiveInteger(n) {
    return n >>> 0 === parseFloat(n);
}

function abToBuf(ab) {
    return Buffer.from(new Uint8Array(ab));
}

function abToPem(type, ab) {
    var str = coerceToBase64(ab, "abToPem");
    return [
        `-----BEGIN ${type}-----\n`,
        ...str.match(/.{1,64}/g).map((s) => s + "\n"),
        `-----END ${type}-----\n`
    ].join("");
}

function arrayBufferEquals(b1, b2) {
    if (!(b1 instanceof ArrayBuffer) ||
            !(b2 instanceof ArrayBuffer)) {
        console.log("not array buffers");
        return false;
    }

    if (b1.byteLength !== b2.byteLength) {
        console.log("not same length");
        return false;
    }
    b1 = new Uint8Array(b1);
    b2 = new Uint8Array(b2);
    for (let i = 0; i < b1.byteLength; i++) {
        if (b1[i] !== b2[i]) return false;
    }
    return true;
}

module.exports = {
    printHex,
    Fido2LibError,
    coerceToBase64,
    coerceToBase64Url,
    coerceToArrayBuffer,
    ab2str,
    isBase64Url,
    checkOrigin,
    bufEqual,
    abEqual,
    isPem,
    isPositiveInteger,
    abToBuf,
    abToPem,
    arrayBufferEquals
};
