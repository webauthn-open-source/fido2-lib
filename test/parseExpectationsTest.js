"use strict";

const parser = require("../lib/parser");
var assert = require("chai").assert;

describe("parseExpectations", function() {
    it("parser is object", function() {
        assert.isObject(parser);
    });

    it("returns Map on good expectations", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg"
        };
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 2);
        assert.strictEqual(ret.get("origin"), exp.origin);
        assert.strictEqual(ret.get("challenge"), exp.challenge);
    });

    it("doesn't add extra items to Map", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg",
            foo: "bar",
            beer: true
        };
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 2);
        assert.strictEqual(ret.get("origin"), exp.origin);
        assert.strictEqual(ret.get("challenge"), exp.challenge);
    });

    it("throws on invalid origin", function() {
        var exp = {
            origin: "asdf",
            challenge: "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg"
        };
        assert.throws(() => {
            parser.parseExpectations(exp);
        }, TypeError, "Invalid URL: asdf");
    });

    it("coerces Array challenge to base64url", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: [
                0xe0, 0x14, 0xb5, 0x60, 0x92, 0x91, 0x09, 0xe0, 0x95, 0xa0, 0xb7, 0x5f, 0x1b, 0xf6, 0xfa, 0xe8,
                0x1b, 0x92, 0x43, 0xe2, 0x36, 0x9f, 0x7e, 0x16, 0xb0, 0xb1, 0x6f, 0xcb, 0xad, 0x9f, 0xa4, 0x85,
                0x45, 0x8e, 0xb9, 0xb7, 0xdb, 0xfb, 0x45, 0x45, 0x08, 0xb1, 0x5f, 0xd5, 0x3c, 0x10, 0x15, 0x53,
                0xae, 0x24, 0xe4, 0xad, 0xe0, 0x29, 0xfb, 0x59, 0xc3, 0xbd, 0x86, 0xe8, 0x44, 0xaf, 0x56, 0x16
            ]
        };
        var base64UrlChallenge = "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg";
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 2);
        assert.strictEqual(ret.get("origin"), exp.origin);
        assert.strictEqual(ret.get("challenge"), base64UrlChallenge);
    });


    it("coerces Uint8Array challenge to base64url", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: Uint8Array.from([
                0xe0, 0x14, 0xb5, 0x60, 0x92, 0x91, 0x09, 0xe0, 0x95, 0xa0, 0xb7, 0x5f, 0x1b, 0xf6, 0xfa, 0xe8,
                0x1b, 0x92, 0x43, 0xe2, 0x36, 0x9f, 0x7e, 0x16, 0xb0, 0xb1, 0x6f, 0xcb, 0xad, 0x9f, 0xa4, 0x85,
                0x45, 0x8e, 0xb9, 0xb7, 0xdb, 0xfb, 0x45, 0x45, 0x08, 0xb1, 0x5f, 0xd5, 0x3c, 0x10, 0x15, 0x53,
                0xae, 0x24, 0xe4, 0xad, 0xe0, 0x29, 0xfb, 0x59, 0xc3, 0xbd, 0x86, 0xe8, 0x44, 0xaf, 0x56, 0x16
            ])
        };
        var base64UrlChallenge = "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg";
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 2);
        assert.strictEqual(ret.get("origin"), exp.origin);
        assert.strictEqual(ret.get("challenge"), base64UrlChallenge);
    });

    it("coerces ArrayBuffer challenge to base64url", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: Uint8Array.from([
                0xe0, 0x14, 0xb5, 0x60, 0x92, 0x91, 0x09, 0xe0, 0x95, 0xa0, 0xb7, 0x5f, 0x1b, 0xf6, 0xfa, 0xe8,
                0x1b, 0x92, 0x43, 0xe2, 0x36, 0x9f, 0x7e, 0x16, 0xb0, 0xb1, 0x6f, 0xcb, 0xad, 0x9f, 0xa4, 0x85,
                0x45, 0x8e, 0xb9, 0xb7, 0xdb, 0xfb, 0x45, 0x45, 0x08, 0xb1, 0x5f, 0xd5, 0x3c, 0x10, 0x15, 0x53,
                0xae, 0x24, 0xe4, 0xad, 0xe0, 0x29, 0xfb, 0x59, 0xc3, 0xbd, 0x86, 0xe8, 0x44, 0xaf, 0x56, 0x16
            ]).buffer
        };
        var base64UrlChallenge = "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg";
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 2);
        assert.strictEqual(ret.get("origin"), exp.origin);
        assert.strictEqual(ret.get("challenge"), base64UrlChallenge);
    });

    it("coerces Buffer challenge to base64url", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: Buffer.from([
                0xe0, 0x14, 0xb5, 0x60, 0x92, 0x91, 0x09, 0xe0, 0x95, 0xa0, 0xb7, 0x5f, 0x1b, 0xf6, 0xfa, 0xe8,
                0x1b, 0x92, 0x43, 0xe2, 0x36, 0x9f, 0x7e, 0x16, 0xb0, 0xb1, 0x6f, 0xcb, 0xad, 0x9f, 0xa4, 0x85,
                0x45, 0x8e, 0xb9, 0xb7, 0xdb, 0xfb, 0x45, 0x45, 0x08, 0xb1, 0x5f, 0xd5, 0x3c, 0x10, 0x15, 0x53,
                0xae, 0x24, 0xe4, 0xad, 0xe0, 0x29, 0xfb, 0x59, 0xc3, 0xbd, 0x86, 0xe8, 0x44, 0xaf, 0x56, 0x16
            ])
        };
        var base64UrlChallenge = "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg";
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 2);
        assert.strictEqual(ret.get("origin"), exp.origin);
        assert.strictEqual(ret.get("challenge"), base64UrlChallenge);
    });

    it("coerces base64 challenge to base64url", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg"
        };
        var base64UrlChallenge = "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg";
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 2);
        assert.strictEqual(ret.get("origin"), exp.origin);
        assert.strictEqual(ret.get("challenge"), base64UrlChallenge);
    });

    it("empty expectations object returns empty map", function() {
        var exp = {};
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 0);
    });

    it("adds flags to map when they exist", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
            flags: new Set(["UP", "AT"])
        };
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 3);
        var flags = ret.get("flags");
        assert.instanceOf(flags, Set);
        assert.strictEqual(flags.size, 2);
        assert.isTrue(flags.has("UP"), "flags has UP");
        assert.isTrue(flags.has("AT"), "flags has AT");
    });

    it("converts Array of flags to Set", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
            flags: ["UP", "AT"]
        };
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 3);
        var flags = ret.get("flags");
        assert.instanceOf(flags, Set);
        assert.strictEqual(flags.size, 2);
        assert.isTrue(flags.has("UP"), "flags has UP");
        assert.isTrue(flags.has("AT"), "flags has AT");
    });

    it("throws if flags is something other than Array or Set", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
            flags: "foo"
        };
        assert.throws(() => {
            parser.parseExpectations(exp);
        }, TypeError, "expected flags to be an Array or a Set, got: string");
    });

    it("adds prevCount to map when it exists", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
            prevCounter: 666
        };
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 3);
        var prevCounter = ret.get("prevCounter");
        assert.isNumber(prevCounter);
        assert.strictEqual(prevCounter, 666);
    });

    it("adds prevCount to map when it's zero", function() {
        var exp = {
            origin: "https://webauthn.bin.coffee",
            challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
            prevCounter: 0
        };
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 3);
        var prevCounter = ret.get("prevCounter");
        assert.isNumber(prevCounter);
        assert.strictEqual(prevCounter, 0);
    });

    it("throws when prevCount is not a number");
    it("adds publicKey to map when it exists");
    it("throws when publicKey is not a string");

    it("works with typical attestation expectations", function() {
        var exp = {
            challenge: "HcsOvH431SaLt1hc7mpkqohMaub+oTO5ao/hzJOkUwQEdTWDhOYTdp4ejQcOCsIYdB64c1fkeqiblg6EkygpUA==",
            origin: "https://localhost:8443",
            publicKey: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESe3kuy9dZzFYR/uw+exFJxKLt6E+\n3Sp0RamB8J63CxYnbRhv6SF6MwQx/LNHJHw7rrN2xioEu88ArEDdk0jHAQ==\n-----END PUBLIC KEY-----\n",
            prevCounter: 0,
            flags: ["UP-or-UV"]
        };
        var ret = parser.parseExpectations(exp);
        assert.instanceOf(ret, Map);
        assert.strictEqual(ret.size, 5);
    });
});
