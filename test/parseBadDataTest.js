// Testing lib
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";

// Helpers

import { coerceToArrayBuffer, tools } from "../lib/main.js";

// Test subject
import { parseAttestationObject } from "../lib/main.js";

chai.use(chaiAsPromised.default);
const { assert } = chai;

describe("bad clientData", function() {
	it("zero length ArrayBuffer");
	it("ArrayBuffer full of random bytes");
	it("string, but not base64");
	it("malformed JSON");
	it("missing challenge");
	it("challenge isn't bytes");
	it("missing origin");
	it("origin isn't string");
	it("missing type");
	it("type isn't string");
	it("missing malformed tokenBinding");
	it("has hashAlgorithm (removed in WD-08)");
	it("has clientExtensions (removed in WD-08)");
	it("has authenticatorExtensions (removed in WD-08)");
	it("has tokenBindingId (removed in WD-07)");
});

describe("bad attestationObject", function() {
	it("zero length ArrayBuffer");
	it("ArrayBuffer full of random bytes");
	it("string, but not base64");
	/*it("malformed CBOR", async function () {
    await expect((async function () {
      const malformedAttestationObject = Buffer.from(
        "a363666d74506e6f6e656761747453746d74a068617574684461746159012649960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976341000000000000000000000000000000000000000000a20008a2dd5eac1a86a8cd6ed36cd698949689e5bafc4eb05f4579e87d93ba976b2e7376b9b6dfd716e164140ff979a6d4f344b53d6d26e0867bf414b69103bb65cbb2daf7f4112835f064cb1b59a8e584a421da8bd89e387a0b7eeab723ecd79d484c316bfbaec54601b47367490a839ada1401f33d2d258b97ae418ca559346529f5aa37de63127557d04346c7cdeebd25542f2c17fc39389952a26c3ae2a6a6a51ca5010203262001215820bb11cddd6e9e869d1559729a30d89ed49f3631524215961271abbbe28d7b731f225820dbd639132e2ee561965b830530a6a024f1098888f313550515921184c86acac3",
        "hex",
      );
      return await parseAttestationObject(
        coerceToArrayBuffer(
          malformedAttestationObject,
          "malformedAttestationObject",
        ),
      );
    })()).to.be.rejectedWith(
      TypeError,
      "couldn't parse attestationObject CBOR",
    );
  });*/
	it("missing fmt", async function() {
		const missingFmt = {
			attStmt: {},
		};
		await assert.isRejected(
			parseAttestationObject(
				coerceToArrayBuffer(
					tools.cbor.encode(missingFmt),
					"missingFmt",
				),
			),
			Error, "expected attestation CBOR to contain a 'fmt' string",
		);
	});
	it("fmt not string", function() {
		const fmtAdNumber = {
			fmt: 1,
			attStmt: {},
		};
		assert.isRejected(
			parseAttestationObject(
				coerceToArrayBuffer(
					tools.cbor.encode(fmtAdNumber),
					"fmtAdNumber",
				),
			),
			Error, "expected attestation CBOR to contain a 'fmt' string",
		);
	});
	it("missing attStmt", function() {
		const missingAttStmt = {
			fmt: "none",
		};
		assert.isRejected(
			parseAttestationObject(
				coerceToArrayBuffer(
					tools.cbor.encode(missingAttStmt),
					"missingAttStmt",
				),
			),
			Error, "expected attestation CBOR to contain a 'attStmt' object",
		);
	});
	it("malformed attStmt", function() {
		const malformedAttStmt = {
			fmt: "none",
			attStmt: "attStmt",
		};
		assert.isRejected(
			parseAttestationObject(
				coerceToArrayBuffer(
					tools.cbor.encode(malformedAttStmt),
					"malformedAttStmt"
				),
			),
			Error, "expected attestation CBOR to contain a 'attStmt' object",
		);
	});
	it("missing authData", function() {
		const missingAuthData = {
			fmt: "none",
			attStmt: {},
		};
		assert.isRejected(
			parseAttestationObject(
				coerceToArrayBuffer(
					tools.cbor.encode(missingAuthData),
					"missingAuthData",
				),
			),
			Error, "expected attestation CBOR to contain a 'authData' byte sequence",
		);
	});
	it("malformed authData", function() {
		const malformedAuthData = {
			fmt: "none",
			attStmt: {},
			authData: "authData",
		};
		assert.isRejected(
			parseAttestationObject(
				coerceToArrayBuffer(
					tools.cbor.encode(malformedAuthData),
					"malformedAuthData",
				),
			),
			Error, "expected attestation CBOR to contain a 'authData' byte sequence",
		);
	});
});

describe("bad authenticatorData", function() {
	it("zero length ArrayBuffer");
	it("ArrayBuffer full of random bytes");
	it("string, but not base64");
	it("malformed CBOR");
	it("AT flag set, but no attestation data"); // priority
	it("ED flag set, but no extension data"); // priority
	it("AT flag set, but random data"); // priority
	it("ED flag set, but random data"); // priority
	it("RFU1 set");
	it("RFU3 set");
	it("RFU4 set");
	it("RFU5 set");
	it("publicKey is random bytes"); // priority
});

describe("bad signature", function() {
	it("zero length ArrayBuffer");
	it("string, but not base64");
	it("random bytes");
	it("off by one byte"); // priority
});

describe("bad attestation statements", function() {
	it("u2f");
	it("none");
	it("tpm");
});
