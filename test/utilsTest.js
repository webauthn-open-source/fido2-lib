const utils = require("../lib/utils");
const {
    checkOrigin,
    coerceToBase64Url,
    coerceToArrayBuffer,
    isBase64Url
} = utils;
var assert = require("chai").assert;
const h = require("fido2-helpers");

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

        it("returns true when origin contains port 443");
        it("throws when origin is just a domain");
        it("rejects invalid eTLD+1 international domain");
        it("allows punycoded domain");
        it("correctly compares punycoded and international domain");
    });

    describe("coerceToBase64Url", function() {
        it("passes through valid base64url");
        it("converts base64");
        it("converts ArrayBuffer");
        it("converts Uint8Array");
        it("converts Array");
        it("converts Buffer");
        it("throws if it can't convert");
    });

    describe("coerceToArrayBuffer", function() {
        it("passes through ArrayBuffer");
        it("converts base64");
        it("converts base64url");
        it("converts Uint8Array");
        it("converts Array");
        it("converts Buffer");
        it("throws if it can't convert");
    });

    describe("isBase64Url", function() {
        it("returns true for base64url string");
        it("returns false for base64 string");
        it("returns false for arbitrary string");
        it("returns false for undefined");
        it("returns false for non-string");
    });
});