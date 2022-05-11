// Testing lib
import * as chai from "chai";

// Helpers

import {
	arrayBufferEquals,
	abToHex,
	coerceToArrayBuffer,
	coerceToBase64,
	coerceToBase64Url,
	isBase64Url,
	isPem,
	jsObjectToB64,
	pemToBase64,
	str2ab
} from "../lib/main.js";
import * as h from "./helpers/fido2-helpers.js";
const assert = chai.assert;

describe("utils", function() {
	describe("coerceToBase64Url", () => {
		it("exists", () => {
			assert.isFunction(coerceToBase64Url);
		});

		it("coerce ArrayBuffer to base64url", () => {
			let ab = Uint8Array.from([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			]).buffer;
			const res = coerceToBase64Url(ab, "test");
			assert.isString(res);
			assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4_-A");
		});

		it("coerce Uint8Array to base64url", () => {
			let buf = Uint8Array.from([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			]);
			const res = coerceToBase64Url(buf, "test");
			assert.isString(res);
			assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4_-A");
		});

		it("coerce Array to base64url", () => {
			let arr = [
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			];
			const res = coerceToBase64Url(arr, "test");
			assert.isString(res);
			assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4_-A");
		});

		it("coerce base64 to base64url", () => {
			const b64 = "AAECAwQFBgcJCgsMDQ4/+A==";
			const res = coerceToBase64Url(b64, "test");
			assert.isString(res);
			assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4_-A");
		});

		it("coerce base64url to base64url", () => {
			const b64url = "AAECAwQFBgcJCgsMDQ4_-A";
			const res = coerceToBase64Url(b64url, "test");
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

		it("throws if no name specified", () => {
			assert.throws(coerceToBase64Url, Error, "name not specified in coerceToBase64");
		});
	});

	describe("coerceToBase64", () => {
		it("exists", () => {
			assert.isFunction(coerceToBase64Url);
		});

		it("coerce ArrayBuffer to base64", () => {
			let ab = Uint8Array.from([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			]).buffer;
			const res = coerceToBase64(ab, "test");
			assert.isString(res);
			assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4/+A==");
		});

		it("coerce Uint8Array to base64", () => {
			let buf = Uint8Array.from([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			]);
			const res = coerceToBase64(buf, "test");
			assert.isString(res);
			assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4/+A==");
		});

		it("coerce Array to base64", () => {
			let arr = [
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			];
			const res = coerceToBase64(arr, "test");
			assert.isString(res);
			assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4/+A==");
		});

		it("coerce base64 to base64", () => {
			const b64 = "AAECAwQFBgcJCgsMDQ4/+A==";
			const res = coerceToBase64(b64, "test");
			assert.isString(res);
			assert.strictEqual(res, "AAECAwQFBgcJCgsMDQ4/+A==");
		});

		it.skip("coerce base64url to base64", () => {
			const b64url = "AAECAwQFBgcJCgsMDQ4_-A";
			const res = coerceToBase64(b64url, "test");
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

		it("throws if no name specified", () => {
			assert.throws(coerceToBase64, Error, "name not specified in coerceToBase64");
		});
	});

	describe("coerceToArrayBuffer", () => {
		it("exists", () => {
			assert.isFunction(coerceToArrayBuffer);
		});

		it("coerce base64url to ArrayBuffer", () => {
			const b64url = "AAECAwQFBgcJCgsMDQ4_-A";
			const res = coerceToArrayBuffer(b64url, "test");
			assert.instanceOf(res, ArrayBuffer);
			let expectedAb = Uint8Array.from([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			]).buffer;
			assert.isTrue(arrayBufferEquals(res, expectedAb), "got expected ArrayBuffer value");
		});

		it("coerce base64 to ArrayBuffer", () => {
			const b64 = "AAECAwQFBgcJCgsMDQ4/+A==";
			const res = coerceToArrayBuffer(b64, "test");
			assert.instanceOf(res, ArrayBuffer);
			let expectedAb = Uint8Array.from([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			]).buffer;
			assert.isTrue(arrayBufferEquals(res, expectedAb), "got expected ArrayBuffer value");
		});

		it("coerce Array to ArrayBuffer", () => {
			let arr = [
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			];
			const res = coerceToArrayBuffer(arr, "test");
			assert.instanceOf(res, ArrayBuffer);
			let expectedAb = Uint8Array.from([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			]).buffer;
			assert.isTrue(arrayBufferEquals(res, expectedAb), "got expected ArrayBuffer value");
		});

		it("coerce Buffer to ArrayBuffer");

		it("coerce Uint8Array to ArrayBuffer", () => {
			let buf = Uint8Array.from([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			]);
			const res = coerceToArrayBuffer(buf, "test");
			assert.instanceOf(res, ArrayBuffer);
			let expectedAb = Uint8Array.from([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			]).buffer;
			assert.isTrue(arrayBufferEquals(res, expectedAb), "got expected ArrayBuffer value");
		});

		it("coerce ArrayBuffer to ArrayBuffer", () => {
			let ab = Uint8Array.from([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			]).buffer;
			const res = coerceToArrayBuffer(ab, "test");
			assert.instanceOf(res, ArrayBuffer);
			let expectedAb = Uint8Array.from([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x3F, 0xF8,
			]).buffer;
			assert.isTrue(arrayBufferEquals(res, expectedAb), "got expected ArrayBuffer value");
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

		it("throws if no name specified", () => {
			assert.throws(coerceToArrayBuffer, Error, "name not specified in coerceToArrayBuffer");
		});
	});

	describe("ab2str", function() {
		it("converts ArrayBuffer to string");
	});

	describe("str2ab", function() {
		it("converts string to ArrayBuffer", function() {
			const ab = str2ab("abc123");

			let expectedAb = new Uint8Array([
				0x61, 0x62, 0x63, 0x31, 0x32, 0x33,
			]).buffer;

			assert.isTrue(arrayBufferEquals(ab, expectedAb), "expected result from str2ab");
		});
	});

	describe("jsObjectToB64", function() {
		it("converts Object to base64 string", function() {
			assert.strictEqual(jsObjectToB64({ test: true }), "eyJ0ZXN0Ijp0cnVlfQ==");
		});

		it("removes non UTF-8 characters", function() {
			assert.strictEqual(jsObjectToB64({ alternativeDescriptions: { "ru-RU": "FIDO2 Key SDK - Ð¾Ñ\x82 Hideez" } }), jsObjectToB64({ alternativeDescriptions: { "ru-RU": "FIDO2 Key SDK -  Hideez" } }));
		});
	});

	describe("arrayBufferEquals", function() {

		it("compare ArrayBuffer with equal ArrayBuffer", function() {
			const ab = new Uint8Array([1, 2, 3, 4]).buffer;

			let expectedAb = new Uint8Array([1,2,3,4]);

			assert.isFalse(arrayBufferEquals(ab, expectedAb), "expected result from arrayBufferEquals");
		});

		it("compare ArrayBuffer with non equal ArrayBuffer", function() {
			const ab = new Uint8Array([1, 2, 3, 4]).buffer;

			let expectedAb = new Uint8Array([1,2,3,5]);

			assert.isFalse(arrayBufferEquals(ab, expectedAb), "expected result from arrayBufferEquals");
		});

		it("compare Uint8Array with ArrayBuffer", function() {
			const ab = new Uint8Array([1, 2, 3, 4]);

			const expectedAb = new Uint8Array([1, 2, 3, 4]).buffer;

			assert.isFalse(arrayBufferEquals(ab, expectedAb), "expected result from arrayBufferEquals");
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
			let ret = pemToBase64(h.mds.mdsSigningCert);
			assert.strictEqual(ret, "MIICnTCCAkOgAwIBAgIORvCM1auU6FYVXUebJHcwCgYIKoZIzj0EAwIwUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRDQS0xMB4XDTE1MDgxOTAwMDAwMFoXDTE4MDgxOTAwMDAwMFowZDELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMR4wHAYDVQQDExVNZXRhZGF0YSBUT0MgU2lnbmVyIDMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASKX+p3W2j1GV4lQwn7HXNj4lh9e2wAa6J9tBIQhbQTkqMvNZGnHxOn7yTZ3NpYO5ZGVgr/XC66qli7BWA8jgTfo4HpMIHmMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRckNF+zzxMuLvm+qRjLeJQf0DwyzAfBgNVHSMEGDAWgBRpEV4taWSFnZa41v9czb88dc9MGDA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vbWRzLmZpZG9hbGxpYW5jZS5vcmcvQ0EtMS5jcmwwTwYDVR0gBEgwRjBEBgsrBgEEAYLlHAEDATA1MDMGCCsGAQUFBwIBFidodHRwczovL21kcy5maWRvYWxsaWFuY2Uub3JnL3JlcG9zaXRvcnkwCgYIKoZIzj0EAwIDSAAwRQIhALLbYjBrbhPkwrn3mQjCERIwkMNNT/lfkpNXH+4zjUXEAiBas2lP6jp44Bh4X+tBXqY7y61ijGRIZCaAF1KIlgub0g==");
		});

		it("converts mdsRootCrl", function() {
			let ret = pemToBase64(h.mds.mdsRootCrl);
			assert.strictEqual(ret, "MIIBLTCBswIBATAKBggqhkjOPQQDAzBTMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNRklETyBBbGxpYW5jZTEdMBsGA1UECxMUTWV0YWRhdGEgVE9DIFNpZ25pbmcxDTALBgNVBAMTBFJvb3QXDTE4MDQwNzAwMDAwMFoXDTE4MDcxNTAwMDAwMFqgLzAtMAoGA1UdFAQDAgEMMB8GA1UdIwQYMBaAFNKlHwun9mLIQNTYvbnXjtFUu7xGMAoGCCqGSM49BAMDA2kAMGYCMQCnXSfNppE9vpsGtY9DsPWyR3aVVSPs6i5/3A21a1+rCNoa1cJNWKZJ7IV4cdjIXVUCMQCDh8U8OekdTnuvcG3FaoMJO0y0C0FS5dbTzcuiADjyVbAQeaSsCauVySzyB3lVVgE=");
		});

		it("converts assnPublicKey", function() {
			let ret = pemToBase64(h.lib.assnPublicKey);
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
		it("returns true for base64url string", () => {
			assert.isTrue(isBase64Url("dGVzdGluZyE"), "true on base64url string");
		});

		it("returns false for base64 string");
		it("returns false for arbitrary string");
		it("returns false for undefined");
		it("returns false for non-string");
	});

	describe("abToHex", () => {
		it("should throw on string parameter", () => {
			assert.throws(() => {
				abToHex("foobar");
			}, TypeError);
		});

		it("should throw on Uint8Array parameter", () => {
			assert.throws(() => {
				abToHex(new Uint8Array([0, 1, 2]));
			}, TypeError);
		});

		it("should not throw on ArrayBuffer parameter, and return correct hex string", () => {
			const data = new Uint8Array([0, 1, 2, 255, 16, 15]);
			const ab = data.buffer;
			const res = abToHex(ab);
			assert.equal(res, "000102ff100f");
		});
	});
});
