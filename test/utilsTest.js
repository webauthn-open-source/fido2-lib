"use strict";

const utils = require("../lib/utils");
const {
    checkOrigin,
    coerceToBase64,
    coerceToBase64Url,
    coerceToArrayBuffer,
    ab2str,
    str2ab,
    isBase64Url,
    isPem,
    pemToBase64,
    printHex
} = utils;
var assert = require("chai").assert;
const h = require("fido2-helpers");
const {
    abEqual
} = h.functions;

describe("utils", function() {
    it("is object", function() {
        assert.isObject(utils);
    });

    describe("checkOrigin", function() {
        it("throws on invalid eTLD+1", function() {
            assert.throws(() => {
                checkOrigin("https://s3.dualstack.eu-west-1.amazonaws.com");
            }, Error, "origin is not a valid eTLD+1");
        });

        it("throws on undefined origin", function() {
            assert.throws(() => {
                checkOrigin(undefined);
            }, Error, "Invalid URL: undefined");
        });

        it("throws invalid url", function() {
            assert.throws(() => {
                checkOrigin("qwertyasdf");
            }, Error, "Invalid URL: qwertyasdf");
        });

        it("allows localhost", function() {
            var ret = checkOrigin("https://localhost:8443");
            assert.strictEqual(ret, "https://localhost:8443");
        });

        it("throws on non-https", function() {
            assert.throws(() => {
                checkOrigin("http://webauthn.bin.coffee:8080");
            }, Error, "origin should be https");
        });

        it.skip("allows international domain", function() {
            var ret = checkOrigin("https://www.食狮.公司.cn:8080");
            assert.isTrue(ret);
        });

        it("throws error if origin contains URL path");
        it("returns true when origin contains port 443");
        it("throws when origin is just a domain");
        it("rejects invalid eTLD+1 international domain");
        it("allows punycoded domain");
        it("correctly compares punycoded and international domain");
    });

    describe("coerceToBase64Url", () => {
        it("exists", () => {
            assert.isFunction(coerceToBase64Url);
        });

        it("coerce ArrayBuffer to base64url", () => {
            var ab = Uint8Array.from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ]).buffer;
            var res = coerceToBase64Url(ab, "test");
            assert.isString(res);
            assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4_-A");
        });

        it("coerce Uint8Array to base64url", () => {
            var buf = Uint8Array.from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ]);
            var res = coerceToBase64Url(buf, "test");
            assert.isString(res);
            assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4_-A");
        });

        it("coerce Buffer to base64url");

        it("coerce Array to base64url", () => {
            var arr = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ];
            var res = coerceToBase64Url(arr, "test");
            assert.isString(res);
            assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4_-A");
        });

        it("coerce base64 to base64url", () => {
            var b64 = "AAECAwQFBgcJCgsMDQ4/+A==";
            var res = coerceToBase64Url(b64, "test");
            assert.isString(res);
            assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4_-A");
        });

        it("coerce base64url to base64url", () => {
            var b64url = "AAECAwQFBgcJCgsMDQ4_-A";
            var res = coerceToBase64Url(b64url, "test");
            assert.isString(res);
            assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4_-A");
        });

        it("throws on incompatible: number", () => {
            assert.throws(() => {
                coerceToBase64Url(42, "test.number");
            }, Error, "could not coerce 'test.number' to string");
        });

        it("throws on incompatible: undefined", () => {
            assert.throws(() => {
                coerceToBase64Url(undefined, "test.number");
            }, Error, "could not coerce 'test.number' to string");
        });

        it("throws if no name specified");
    });

    describe("coerceToBase64", () => {
        it("exists", () => {
            assert.isFunction(coerceToBase64Url);
        });

        it("coerce ArrayBuffer to base64", () => {
            var ab = Uint8Array.from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ]).buffer;
            var res = coerceToBase64(ab, "test");
            assert.isString(res);
            assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4/+A==");
        });

        it("coerce Uint8Array to base64", () => {
            var buf = Uint8Array.from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ]);
            var res = coerceToBase64(buf, "test");
            assert.isString(res);
            assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4/+A==");
        });

        it("coerce Buffer to base64");

        it("coerce Array to base64", () => {
            var arr = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ];
            var res = coerceToBase64(arr, "test");
            assert.isString(res);
            assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4/+A==");
        });

        it("coerce base64 to base64", () => {
            var b64 = "AAECAwQFBgcJCgsMDQ4/+A==";
            var res = coerceToBase64(b64, "test");
            assert.isString(res);
            assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4/+A==");
        });

        it.skip("coerce base64url to base64", () => {
            var b64url = "AAECAwQFBgcJCgsMDQ4_-A";
            var res = coerceToBase64(b64url, "test");
            assert.isString(res);
            assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4/+A==");
        });

        it("throws on incompatible: number", () => {
            assert.throws(() => {
                coerceToBase64(42, "test.number");
            }, Error, "could not coerce 'test.number' to string");
        });

        it("throws on incompatible: undefined", () => {
            assert.throws(() => {
                coerceToBase64(undefined, "test.number");
            }, Error, "could not coerce 'test.number' to string");
        });

        it("throws if no name specified");
    });

    describe("coerceToArrayBuffer", () => {
        it("exists", () => {
            assert.isFunction(coerceToArrayBuffer);
        });

        it("coerce base64url to ArrayBuffer", () => {
            var b64url = "AAECAwQFBgcJCgsMDQ4_-A";
            var res = coerceToArrayBuffer(b64url, "test");
            assert.instanceOf(res, ArrayBuffer);
            var expectedAb = Uint8Array.from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ]).buffer;
            assert.isTrue(abEqual(res, expectedAb), "got expected ArrayBuffer value");
        });

        it("coerce base64 to ArrayBuffer", () => {
            var b64 = "AAECAwQFBgcJCgsMDQ4/+A==";
            var res = coerceToArrayBuffer(b64, "test");
            assert.instanceOf(res, ArrayBuffer);
            var expectedAb = Uint8Array.from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ]).buffer;
            assert.isTrue(abEqual(res, expectedAb), "got expected ArrayBuffer value");
        });

        it("coerce Array to ArrayBuffer", () => {
            var arr = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ];
            var res = coerceToArrayBuffer(arr, "test");
            assert.instanceOf(res, ArrayBuffer);
            var expectedAb = Uint8Array.from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ]).buffer;
            assert.isTrue(abEqual(res, expectedAb), "got expected ArrayBuffer value");
        });

        it("coerce Buffer to ArrayBuffer");

        it("coerce Uint8Array to ArrayBuffer", () => {
            var buf = Uint8Array.from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ]);
            var res = coerceToArrayBuffer(buf, "test");
            assert.instanceOf(res, ArrayBuffer);
            var expectedAb = Uint8Array.from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ]).buffer;
            assert.isTrue(abEqual(res, expectedAb), "got expected ArrayBuffer value");
        });

        it("coerce ArrayBuffer to ArrayBuffer", () => {
            var ab = Uint8Array.from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ]).buffer;
            var res = coerceToArrayBuffer(ab, "test");
            assert.instanceOf(res, ArrayBuffer);
            var expectedAb = Uint8Array.from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8
            ]).buffer;
            assert.isTrue(abEqual(res, expectedAb), "got expected ArrayBuffer value");
        });

        it("throws on incompatible: number", () => {
            assert.throws(() => {
                coerceToArrayBuffer(42, "test.number");
            }, Error, "could not coerce 'test.number' to ArrayBuffer");
        });

        it("throws on incompatible: undefined", () => {
            assert.throws(() => {
                coerceToArrayBuffer(undefined, "test.number");
            }, Error, "could not coerce 'test.number' to ArrayBuffer");
        });

        it("throws on incompatible: object", () => {
            assert.throws(() => {
                coerceToArrayBuffer({}, "test.number");
            }, Error, "could not coerce 'test.number' to ArrayBuffer");
        });

        it("throws if no name specified");
    });

    describe("ab2str", function() {
        it("converts ArrayBuffer to string");
    });

    describe("str2ab", function() {
        it("converts string to ArrayBuffer", function() {
            var ab = str2ab("abc123");

            var expectedAb = new Uint8Array([
                0x61, 0x62, 0x63, 0x31, 0x32, 0x33
            ]).buffer;

            assert.isTrue(abEqual(ab, expectedAb), "expected result from str2ab");
        });
    });

    describe("isPem", function() {
        it("detects mdsSigningCert", function() {
            assert.isTrue(isPem(h.mds.mdsSigningCert), "correctly detects mdsSigningCert");
        });

        it("detects mdsRootCrl", function() {
            assert.isTrue(isPem(h.mds.mdsRootCrl), "correctly detects mdsRootCrl");
        });

        it("detects assnPublicKey", function() {
            assert.isTrue(isPem(h.lib.assnPublicKey), "correctly detects assnPublicKey");
        });

        it("returns false on undefined input", function() {
            assert.isFalse(isPem(), "false on undefined string");
        });

        it("returns false on bad string", function() {
            assert.isFalse(isPem("foobar"), "false on bad string");
        });
        it("returns false on empty string", function() {
            assert.isFalse(isPem(""), "false on empty string");
        });
    });

    describe("pemToBase64", function() {
        it("converts mdsSigningCert", function() {
            var ret = pemToBase64(h.mds.mdsSigningCert);
            assert.strictEqual(ret, "MIICnTCCAkOgAwIBAgIORvCM1auU6FYVXUebJHcwCgYIKoZIzj0EAwIwUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRDQS0xMB4XDTE1MDgxOTAwMDAwMFoXDTE4MDgxOTAwMDAwMFowZDELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMR4wHAYDVQQDExVNZXRhZGF0YSBUT0MgU2lnbmVyIDMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASKX+p3W2j1GV4lQwn7HXNj4lh9e2wAa6J9tBIQhbQTkqMvNZGnHxOn7yTZ3NpYO5ZGVgr/XC66qli7BWA8jgTfo4HpMIHmMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRckNF+zzxMuLvm+qRjLeJQf0DwyzAfBgNVHSMEGDAWgBRpEV4taWSFnZa41v9czb88dc9MGDA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vbWRzLmZpZG9hbGxpYW5jZS5vcmcvQ0EtMS5jcmwwTwYDVR0gBEgwRjBEBgsrBgEEAYLlHAEDATA1MDMGCCsGAQUFBwIBFidodHRwczovL21kcy5maWRvYWxsaWFuY2Uub3JnL3JlcG9zaXRvcnkwCgYIKoZIzj0EAwIDSAAwRQIhALLbYjBrbhPkwrn3mQjCERIwkMNNT/lfkpNXH+4zjUXEAiBas2lP6jp44Bh4X+tBXqY7y61ijGRIZCaAF1KIlgub0g==");
        });

        it("converts mdsRootCrl", function() {
            var ret = pemToBase64(h.mds.mdsRootCrl);
            assert.strictEqual(ret, "MIIBLTCBswIBATAKBggqhkjOPQQDAzBTMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNRklETyBBbGxpYW5jZTEdMBsGA1UECxMUTWV0YWRhdGEgVE9DIFNpZ25pbmcxDTALBgNVBAMTBFJvb3QXDTE4MDQwNzAwMDAwMFoXDTE4MDcxNTAwMDAwMFqgLzAtMAoGA1UdFAQDAgEMMB8GA1UdIwQYMBaAFNKlHwun9mLIQNTYvbnXjtFUu7xGMAoGCCqGSM49BAMDA2kAMGYCMQCnXSfNppE9vpsGtY9DsPWyR3aVVSPs6i5/3A21a1+rCNoa1cJNWKZJ7IV4cdjIXVUCMQCDh8U8OekdTnuvcG3FaoMJO0y0C0FS5dbTzcuiADjyVbAQeaSsCauVySzyB3lVVgE=");
        });

        it("converts assnPublicKey", function() {
            var ret = pemToBase64(h.lib.assnPublicKey);
            assert.strictEqual(ret, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERez9aO2wBAWO54MuGbEqSdWahSnGMAg35BCNkaE3j8Q+O/ZhhKqTeIKm7El70EG6ejt4sg1ZaoQ5ELg8k3ywTg==");
        });

        it("throws on empty string", function() {
            assert.throws(function() {
                pemToBase64("");
            });
        }, Error, "expected PEM string as input");

        it("throws on non-PEM string", function() {
            assert.throws(function() {
                pemToBase64("");
            });
        }, Error, "expected PEM string as input");

        it("throws on undefined", function() {
            assert.throws(function() {
                pemToBase64();
            });
        }, Error, "expected PEM string as input");
    });

    describe("isBase64Url", function() {
        it("returns true for base64url string");
        it("returns false for base64 string");
        it("returns false for arbitrary string");
        it("returns false for undefined");
        it("returns false for non-string");
    });
});
