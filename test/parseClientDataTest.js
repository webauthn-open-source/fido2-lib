"use strict";

const parser = require("../lib/parser");
var assert = require("chai").assert;
const h = require("fido2-helpers");

describe("parseClientData", function() {
	it("parser is object", function() {
		assert.isObject(parser);
	});

	it("correctly converts attestation JSON", function() {
		var ret = parser.parseClientResponse(h.lib.makeCredentialAttestationNoneResponse);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 6);
		assert.strictEqual(ret.get("challenge"), "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w");
		// assert.deepEqual(ret.get("clientExtensions"), {});
		// assert.strictEqual(ret.get("hashAlgorithm"), "SHA-256");
		assert.strictEqual(ret.get("origin"), "https://localhost:8443");
		assert.strictEqual(ret.get("type"), "webauthn.create");
		assert.strictEqual(ret.get("tokenBinding", undefined));
		assert.instanceOf(ret.get("rawClientDataJson"), ArrayBuffer);
		// TODO: validate rawClientDataJson
	});

	it("correctly parses assertion JSON", function() {
		var ret = parser.parseClientResponse(h.lib.assertionResponse);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 6);
		assert.strictEqual(ret.get("challenge"), "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ");
		// assert.deepEqual(ret.get("clientExtensions"), {});
		// assert.strictEqual(ret.get("hashAlgorithm"), "SHA-256");
		assert.strictEqual(ret.get("origin"), "https://localhost:8443");
		assert.strictEqual(ret.get("type"), "webauthn.get");
		assert.strictEqual(ret.get("tokenBinding", undefined));
		assert.instanceOf(ret.get("rawClientDataJson"), ArrayBuffer);
		// TODO: validate rawClientDataJson
	});

	it("throws error when args are wrong format");
	it("throws when buffer doesn't contain JSON");
	it("throws on malformatted JSON");
	it("throws when buffer contains random data");
});
