// Testing lib
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";

// Helpers
import * as h from "./helpers/fido2-helpers.js";

// Test subject
import { arrayBufferEquals, noneAttestation, parseAttestationObject, parseAuthnrAttestationResponse } from "../lib/main.js";
chai.use(chaiAsPromised.default);
const { assert } = chai;

const parser = {
	parseAuthnrAttestationResponse,
	parseAttestationObject,
};

const runs = [
	{ functionName: "parseAuthnrAttestationResponse" },
	{ functionName: "parseAttestationObject" },
];

runs.forEach(function(run) {
	describe(run.functionName + " (without + extensions)", function() {
		it("parser is object", function() {
			assert.equal(typeof parser, "object");
		});

		it("correctly parses extension data", async function() {
			const ret = run.functionName == "parseAuthnrAttestationResponse"
				? await parser[run.functionName](
					h.lib.makeJustExtensionsResponse,
				)
				: await parser[run.functionName](
					h.lib.makeJustExtensionsResponse.response
						.attestationObject,
				);
			
			assert.instanceOf(ret, Map);
			assert.strictEqual(ret.size, 7);
			assert.isDefined(ret.get("webAuthnExtensions"));
			const fmt = ret.get("fmt");
			assert.strictEqual(fmt, "none");
			// got the right authData CBOR
			const rawAuthnrData = ret.get("rawAuthnrData");
			assert.instanceOf(rawAuthnrData, ArrayBuffer);
			const expectedRawAuthnrData = new Uint8Array([
				0x49, 0x96, 0x0D, 0xE5, 0x88, 0x0E, 0x8C, 0x68, 0x74, 0x34, 0x17, 0x0F, 0x64, 0x76, 0x60, 0x5B,
				0x8F, 0xE4, 0xAE, 0xB9, 0xA2, 0x86, 0x32, 0xC7, 0x99, 0x5C, 0xF3, 0xBA, 0x83, 0x1D, 0x97, 0x63, 
				0x81, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x01, 0x6b, 0x63, 0x72, 0x65, 0x64, 0x50, 0x72, 0x6f, 
				0x74, 0x65, 0x63, 0x74, 0x01,
			]).buffer;
			assert(arrayBufferEquals(rawAuthnrData, expectedRawAuthnrData), "authData contains right bytes");
			const rpIdHash = ret.get("rpIdHash");
			const expectedRpIdHash = new Uint8Array([
				0x49, 0x96, 0x0D, 0xE5, 0x88, 0x0E, 0x8C, 0x68, 0x74, 0x34, 0x17, 0x0F, 0x64, 0x76, 0x60, 0x5B,
				0x8F, 0xE4, 0xAE, 0xB9, 0xA2, 0x86, 0x32, 0xC7, 0x99, 0x5C, 0xF3, 0xBA, 0x83, 0x1D, 0x97, 0x63,
			]).buffer;
			assert(arrayBufferEquals(rpIdHash, expectedRpIdHash), "correct rpIdHash");
			// flags
			const flags = ret.get("flags");
			assert.instanceOf(flags, Set);
			assert.strictEqual(flags.size, 2);
			assert.isTrue(flags.has("UP"));
			assert.isTrue(flags.has("ED"));
			// counter
			assert.strictEqual(ret.get("counter"), 0);
			assert.isNumber(ret.get("counter"));
		});
	});
});

describe("parseFn (none)", function() {
	it("throws if attStmn has fields", function() {
		const attStmt = { test: 1 };
		assert.throws(
			() => {
				noneAttestation.parseFn(attStmt);
			},
			Error, "'none' attestation format: attStmt had fields",
		);
	});
});
