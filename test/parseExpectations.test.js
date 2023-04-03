// Testing lib
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";

// Helpers

import { arrayBufferEquals, coerceToArrayBuffer } from "../lib/main.js";

// Test subject
import { parseExpectations } from "../lib/main.js";
chai.use(chaiAsPromised.default);
const { assert } = chai;

describe("parseExpectations", function() {
	it("returns Map on good expectations", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg",
		};
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 2);
		assert.strictEqual(ret.get("origin"), exp.origin);
		assert.strictEqual(ret.get("challenge"), exp.challenge);
	});

	it("doesn't add extra items to Map", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg",
			foo: "bar",
			beer: true,
		};
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 2);
		assert.strictEqual(ret.get("origin"), exp.origin);
		assert.strictEqual(ret.get("challenge"), exp.challenge);
	});

	it("throws on invalid url", function() {
		const exp = {
			origin: "asdf",
			challenge: "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg",
		};
		assert.throws(() => {
			parseExpectations(exp);
		}, TypeError, "Invalid URL");
	});

	it("throws if expected origin is https:443", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee:443",
			challenge: "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg",
		};
		assert.throws(() => {
			parseExpectations(exp);
		}, Error, "origin was malformatted");
	});

	it("throws if expected rpId is invalid type", function() {
		const exp = {
			rpId: 23,
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg",
		};
		assert.throws(
			() => {
				parseExpectations(exp);
			},
			Error,
			"expected 'rpId' should be string, got number",
		);
	});

	it("throws if expected rpId is invalid", function() {
		const exp = {
			rpId: "foobar",
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg",
		};
		assert.throws(
			() => {
				parseExpectations(exp);
			},
			Error,
			"rpId is not a valid eTLD+1",
		);
	});

	it("sets rpId properly on successful parsing", function() {
		const exp = {
			rpId: "google.com",
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg",
		};
		const ret = parseExpectations(exp);
		assert.strictEqual(ret.get("rpId"), "google.com");
		assert.strictEqual(ret.size, 3);
	});

	it("coerces Array challenge to base64url", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: [
				0xe0,
				0x14,
				0xb5,
				0x60,
				0x92,
				0x91,
				0x09,
				0xe0,
				0x95,
				0xa0,
				0xb7,
				0x5f,
				0x1b,
				0xf6,
				0xfa,
				0xe8,
				0x1b,
				0x92,
				0x43,
				0xe2,
				0x36,
				0x9f,
				0x7e,
				0x16,
				0xb0,
				0xb1,
				0x6f,
				0xcb,
				0xad,
				0x9f,
				0xa4,
				0x85,
				0x45,
				0x8e,
				0xb9,
				0xb7,
				0xdb,
				0xfb,
				0x45,
				0x45,
				0x08,
				0xb1,
				0x5f,
				0xd5,
				0x3c,
				0x10,
				0x15,
				0x53,
				0xae,
				0x24,
				0xe4,
				0xad,
				0xe0,
				0x29,
				0xfb,
				0x59,
				0xc3,
				0xbd,
				0x86,
				0xe8,
				0x44,
				0xaf,
				0x56,
				0x16,
			],
		};
		const base64UrlChallenge = "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg";
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 2);
		assert.strictEqual(ret.get("origin"), exp.origin);
		assert.strictEqual(ret.get("challenge"), base64UrlChallenge);
	});

	it("coerces Uint8Array challenge to base64url", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: Uint8Array.from([
				0xe0, 0x14, 0xb5, 0x60, 0x92, 0x91, 0x09, 0xe0, 0x95, 0xa0, 0xb7, 0x5f, 0x1b, 0xf6, 0xfa, 0xe8,
				0x1b, 0x92, 0x43, 0xe2, 0x36, 0x9f, 0x7e, 0x16, 0xb0, 0xb1, 0x6f, 0xcb, 0xad, 0x9f, 0xa4, 0x85,
				0x45, 0x8e, 0xb9, 0xb7, 0xdb, 0xfb, 0x45, 0x45, 0x08, 0xb1, 0x5f, 0xd5, 0x3c, 0x10, 0x15, 0x53,
				0xae, 0x24, 0xe4, 0xad, 0xe0, 0x29, 0xfb, 0x59, 0xc3, 0xbd, 0x86, 0xe8, 0x44, 0xaf, 0x56, 0x16,
			]),
		};
		const base64UrlChallenge = "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg";
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 2);
		assert.strictEqual(ret.get("origin"), exp.origin);
		assert.strictEqual(ret.get("challenge"), base64UrlChallenge);
	});

	it("coerces ArrayBuffer challenge to base64url", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: Uint8Array.from([
				0xe0, 0x14, 0xb5, 0x60, 0x92, 0x91, 0x09, 0xe0, 0x95, 0xa0, 0xb7, 0x5f, 0x1b, 0xf6, 0xfa, 0xe8,
				0x1b, 0x92, 0x43, 0xe2, 0x36, 0x9f, 0x7e, 0x16, 0xb0, 0xb1, 0x6f, 0xcb, 0xad, 0x9f, 0xa4, 0x85,
				0x45, 0x8e, 0xb9, 0xb7, 0xdb, 0xfb, 0x45, 0x45, 0x08, 0xb1, 0x5f, 0xd5, 0x3c, 0x10, 0x15, 0x53,
				0xae, 0x24, 0xe4, 0xad, 0xe0, 0x29, 0xfb, 0x59, 0xc3, 0xbd, 0x86, 0xe8, 0x44, 0xaf, 0x56, 0x16,
			]).buffer,
		};
		const base64UrlChallenge = "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg";
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 2);
		assert.strictEqual(ret.get("origin"), exp.origin);
		assert.strictEqual(ret.get("challenge"), base64UrlChallenge);
	});

	it("coerces base64 challenge to base64url", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
		};
		const base64UrlChallenge = "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg";
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 2);
		assert.strictEqual(ret.get("origin"), exp.origin);
		assert.strictEqual(ret.get("challenge"), base64UrlChallenge);
	});

	it("empty expectations object returns empty map", function() {
		const exp = {};
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 0);
	});

	it("adds flags to map when they exist", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			flags: new Set(["UP", "AT"]),
		};
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 3);
		const flags = ret.get("flags");
		assert.instanceOf(flags, Set);
		assert.strictEqual(flags.size, 2);
		assert.isTrue(flags.has("UP"), "flags has UP");
		assert.isTrue(flags.has("AT"), "flags has AT");
	});

	it("converts Array of flags to Set", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			flags: ["UP", "AT"],
		};
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 3);
		const flags = ret.get("flags");
		assert.instanceOf(flags, Set);
		assert.strictEqual(flags.size, 2);
		assert.isTrue(flags.has("UP"), "flags has UP");
		assert.isTrue(flags.has("AT"), "flags has AT");
	});

	it("throws if flags is something other than Array or Set", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			flags: "foo",
		};
		assert.throws(() => {
			parseExpectations(exp);
		}, TypeError, "expected flags to be an Array or a Set, got: string");
	});

	it("adds prevCount to map when it exists", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			prevCounter: 666,
		};
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 3);
		const prevCounter = ret.get("prevCounter");
		assert.isNumber(prevCounter);
		assert.strictEqual(prevCounter, 666);
	});

	it("adds prevCount to map when it's zero", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			prevCounter: 0,
		};
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 3);
		const prevCounter = ret.get("prevCounter");
		assert.isNumber(prevCounter);
		assert.strictEqual(prevCounter, 0);
	});

	it("throws when prevCount is not a number", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			prevCounter: "string",
		};
		assert.throws(() => {
			parseExpectations(exp);
		}, TypeError, "expected 'prevCounter' should be Number, got string");
	});

	it("adds publicKey to map when it exists", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			publicKey: "-----BEGIN PUBLIC KEY-----\n" +
				"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERez9aO2wBAWO54MuGbEqSdWahSnG\n" +
				"MAg35BCNkaE3j8Q+O/ZhhKqTeIKm7El70EG6ejt4sg1ZaoQ5ELg8k3ywTg==\n" +
				"-----END PUBLIC KEY-----\n",
		};
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 3);
		const publicKey = ret.get("publicKey");
		assert.isString(publicKey);
		assert.strictEqual(
			publicKey,
			"-----BEGIN PUBLIC KEY-----\n" +
				"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERez9aO2wBAWO54MuGbEqSdWahSnG\n" +
				"MAg35BCNkaE3j8Q+O/ZhhKqTeIKm7El70EG6ejt4sg1ZaoQ5ELg8k3ywTg==\n" +
				"-----END PUBLIC KEY-----\n",
		);
	});

	it("throws when publicKey is not a string", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			publicKey: {},
		};
		assert.throws(() => {
			parseExpectations(exp);
		}, TypeError, "expected 'publicKey' should be String, got object");
	});

	it("adds userHandle to map when it exists", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			prevCounter: 0,
			userHandle: "YWs",
		};

		const ret = parseExpectations(exp);
		let userHandle = ret.get("userHandle");
		assert.isString(userHandle);
		assert.strictEqual(userHandle.length, 3);
		userHandle = coerceToArrayBuffer(userHandle, "userHandle");
		let expectedUserHandle = new Uint8Array([
			0x61, 0x6B,
		]).buffer;

		assert.isTrue(arrayBufferEquals(userHandle, expectedUserHandle), "userHandle has correct value");
	});

	it("adds userHandle to map when null", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			prevCounter: 0,
			userHandle: null,
		};

		const ret = parseExpectations(exp);
		const userHandle = ret.get("userHandle");
		assert.isNull(userHandle);
	});

	it("adds userHandle to map when empty string", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			prevCounter: 0,
			userHandle: "",
		};

		const ret = parseExpectations(exp);
		const userHandle = ret.get("userHandle");
		assert.isString(userHandle);
		assert.strictEqual(userHandle.length, 0);
		assert.strictEqual(userHandle, "");
	});

	it("adds allowCredentials to map when it exists", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			allowCredentials: [{ id: "dGVzdA==", transports: ["usb"], type: "public-key" }],
		};

		const ret = parseExpectations(exp);
		const allowCredentials = ret.get("allowCredentials");
		assert.isArray(allowCredentials);
		assert.strictEqual(allowCredentials.length, 1);
		allowCredentials[0].id = coerceToArrayBuffer(allowCredentials[0].id, "allowCredentials.id");
		const expectedallowCredentialsId = new Uint8Array([
			0x74, 0x65, 0x73, 0x74,
		]).buffer;
		assert.isTrue(
			arrayBufferEquals(allowCredentials[0].id, expectedallowCredentialsId),
			"allowCredentials has correct value",
		);
	});

	it("adds allowCredentials to map when null", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			prevCounter: 0,
			allowCredentials: null,
		};

		const ret = parseExpectations(exp);
		const allowCredentials = ret.get("allowCredentials");
		assert.isNull(allowCredentials);
	});

	it("works when allowCredentials is undefined", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			prevCounter: 0,
		};

		const ret = parseExpectations(exp);
		const allowCredentials = ret.get("allowCredentials");
		assert.isUndefined(allowCredentials);
	});

	it("works when userHandle is undefined", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			prevCounter: 0,
		};

		const ret = parseExpectations(exp);
		const userHandle = ret.get("userHandle");
		assert.isUndefined(userHandle);
	});

	it("throws when allowCredentials is not a array", function() {
		const exp = {
			origin: "https://webauthn.bin.coffee",
			challenge: "4BS1YJKRCeCVoLdfG/b66BuSQ+I2n34WsLFvy62fpIVFjrm32/tFRQixX9U8EBVTriTkreAp+1nDvYboRK9WFg",
			publicKey: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESe3kuy9dZzFYR/uw+exFJxKLt6E+\n3Sp0RamB8J63CxYnbRhv6SF6MwQx/LNHJHw7rrN2xioEu88ArEDdk0jHAQ==\n-----END PUBLIC KEY-----\n",
			allowCredentials: {},
		};
		assert.throws(() => {
			parseExpectations(exp);
		}, TypeError, "expected 'allowCredentials' to be null or array, got object");
	});

	it("works with typical attestation expectations", function() {
		const exp = {
			challenge: "HcsOvH431SaLt1hc7mpkqohMaub+oTO5ao/hzJOkUwQEdTWDhOYTdp4ejQcOCsIYdB64c1fkeqiblg6EkygpUA==",
			origin: "https://localhost:8443",
			publicKey: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESe3kuy9dZzFYR/uw+exFJxKLt6E+\n3Sp0RamB8J63CxYnbRhv6SF6MwQx/LNHJHw7rrN2xioEu88ArEDdk0jHAQ==\n-----END PUBLIC KEY-----\n",
			prevCounter: 0,
			flags: ["UP-or-UV"],
		};
		const ret = parseExpectations(exp);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 5);
	});
});
