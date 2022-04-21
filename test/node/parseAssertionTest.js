// Testing lib
import * as chai from "chai";
const assert = chai.assert;

// Helpers
import * as fido2helpers from "fido2-helpers";
const h = fido2helpers.default;
const { abEqual } = h.functions;

import { ToolBoxRegistration } from "../../lib/node/toolbox.js";
ToolBoxRegistration.registerAsGlobal();

import { appendBuffer, tools } from "../../lib/common/utils.js";

// Test subject
import * as parser from "../../lib/common/parser.js";

describe("parseAuthnrAssertionResponse", function() {
	it("parser is object", function() {
		assert.equal(typeof parser, "object");
	});

	it("parses assertion correctly", async function() {
		let ret = await parser.parseAuthnrAssertionResponse(h.lib.assertionResponse);
		assert.instanceOf(ret, Map);
		assert.strictEqual(ret.size, 6);
		// rpid
		let rpIdHash = ret.get("rpIdHash");
		assert.instanceOf(rpIdHash, ArrayBuffer);
		let expectedRpIdHash = new Uint8Array([
			0x49, 0x96, 0x0D, 0xE5, 0x88, 0x0E, 0x8C, 0x68, 0x74, 0x34, 0x17, 0x0F, 0x64, 0x76, 0x60, 0x5B,
			0x8F, 0xE4, 0xAE, 0xB9, 0xA2, 0x86, 0x32, 0xC7, 0x99, 0x5C, 0xF3, 0xBA, 0x83, 0x1D, 0x97, 0x63,
		]).buffer;
		assert(abEqual(rpIdHash, expectedRpIdHash), "correct rpIdHash");
		// flags
		let flags = ret.get("flags");
		assert.instanceOf(flags, Set);
		assert.strictEqual(flags.size, 1);
		assert.isTrue(flags.has("UP"));
		// counter
		assert.strictEqual(ret.get("counter"), 363);
		// sig
		let sig = ret.get("sig");
		assert.instanceOf(sig, ArrayBuffer);
		let expectedSig = new Uint8Array([
			0x30, 0x46, 0x02, 0x21, 0x00, 0xFA, 0x74, 0x5D, 0xC1, 0xD1, 0x9A, 0x1A, 0x2C, 0x0D, 0x2B, 0xEF,
			0xCA, 0x32, 0x45, 0xDA, 0x0C, 0x35, 0x1D, 0x1B, 0x37, 0xDD, 0xD9, 0x8B, 0x87, 0x05, 0xFF, 0xBE,
			0x61, 0x14, 0x01, 0xFA, 0xA5, 0x02, 0x21, 0x00, 0xB6, 0x34, 0x50, 0x8B, 0x2B, 0x87, 0x4D, 0xEE,
			0xFD, 0xFE, 0x32, 0x28, 0xEC, 0x33, 0xC0, 0x3E, 0x82, 0x8F, 0x7F, 0xC6, 0x58, 0xB2, 0x62, 0x8A,
			0x84, 0xD3, 0xF7, 0x9F, 0x34, 0xB3, 0x56, 0xBB,
		]).buffer;
		assert(abEqual(sig, expectedSig), "correct signature buffer");
		// userHandle
		let userHandle = ret.get("userHandle");
		assert.isUndefined(userHandle);
		// authRawData
		let rawAuthnrData = ret.get("rawAuthnrData");
		assert.instanceOf(rawAuthnrData, ArrayBuffer);
		let expectedAuthnrRawData = new Uint8Array([
			0x49, 0x96, 0x0D, 0xE5, 0x88, 0x0E, 0x8C, 0x68, 0x74, 0x34, 0x17, 0x0F, 0x64, 0x76, 0x60, 0x5B,
			0x8F, 0xE4, 0xAE, 0xB9, 0xA2, 0x86, 0x32, 0xC7, 0x99, 0x5C, 0xF3, 0xBA, 0x83, 0x1D, 0x97, 0x63,
			0x01, 0x00, 0x00, 0x01, 0x6B,
		]).buffer;
		assert(abEqual(rawAuthnrData, expectedAuthnrRawData), "correct rawAuthnrData");
	});

	it("throws if response is not an object");
});

describe("validate signature", function() {

	it("works", async function() {
		let sig = h.lib.assertionResponse.response.signature;
		let pk = h.lib.assnPublicKey;
		let authnrData = h.lib.assertionResponse.response.authenticatorData;
		let clientData = h.lib.assertionResponse.response.clientDataJSON;

		const clientDataHashBuf = await tools().hashDigest(clientData);
		const verify = await tools().verifySignature(pk, sig, appendBuffer(authnrData,clientDataHashBuf));
		assert.equal(verify, true);
	});
});