const parser = require("../lib/parser");
var assert = require("chai").assert;
const h = require("fido2-helpers");

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
        assert.strictEqual(ret.size, 3);
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
        assert.strictEqual(ret.size, 3);
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

    it("throws on undefined origin", function() {
        var exp = {
            challenge: "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg"
        };
        assert.throws(() => {
            parser.parseExpectations(exp);
        }, TypeError, "expected 'origin' should be string, got undefined");
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
        assert.strictEqual(ret.size, 3);
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
        assert.strictEqual(ret.size, 3);
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
        assert.strictEqual(ret.size, 3);
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
        assert.strictEqual(ret.size, 3);
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
        assert.strictEqual(ret.size, 3);
        assert.strictEqual(ret.get("origin"), exp.origin);
        assert.strictEqual(ret.get("challenge"), base64UrlChallenge);
    });
});