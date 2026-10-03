// Testing lib
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";

// Helpers
import { algorithmResponses } from "./fixtures/algorithmResponses.js";

// Test subject
import {
	coerceToArrayBuffer,
	Fido2AssertionResult,
	Fido2AttestationResult,
	Fido2Lib,
	noneAttestation,
	packedAttestation
} from "../lib/main.js";
chai.use(chaiAsPromised.default);
const { assert } = chai;

const origin = "https://localhost:8443";

function ensureAttestationFormat(format) {
	try {
		Fido2Lib.addAttestationFormat(format.name, format.parseFn, format.validateFn);
	} catch (e) {
		if (!e.message.includes("already exists")) throw e;
	}
}

function register(name) {
	const { registration } = algorithmResponses[name];
	return new Fido2Lib().attestationResult(
		{
			rawId: coerceToArrayBuffer(registration.rawId, "rawId"),
			response: {
				attestationObject: coerceToArrayBuffer(registration.attestationObject, "attestationObject"),
				clientDataJSON: coerceToArrayBuffer(registration.clientDataJSON, "clientDataJSON"),
			},
		},
		{ challenge: registration.challenge, origin, factor: "first" },
	);
}

function login(name, publicKey, signature) {
	const { registration, assertion } = algorithmResponses[name];
	return new Fido2Lib().assertionResult(
		{
			rawId: coerceToArrayBuffer(registration.rawId, "rawId"),
			response: {
				authenticatorData: coerceToArrayBuffer(assertion.authenticatorData, "authenticatorData"),
				clientDataJSON: coerceToArrayBuffer(assertion.clientDataJSON, "clientDataJSON"),
				signature: coerceToArrayBuffer(signature || assertion.signature, "signature"),
				userHandle: null,
			},
		},
		{ challenge: assertion.challenge, origin, factor: "first", publicKey, prevCounter: 0, userHandle: null },
	);
}

function tamper(signature) {
	const bytes = new Uint8Array(coerceToArrayBuffer(signature, "signature"));
	bytes[bytes.length - 3] ^= 1;
	return bytes.buffer;
}

describe("signature algorithms", function() {
	beforeEach(function() {
		ensureAttestationFormat(noneAttestation);
		ensureAttestationFormat(packedAttestation);
	});

	const supported = {
		"Ed25519 none": undefined,
		"Ed25519 packed-self": "self",
		"ES256 none": undefined,
		"ES256 packed-self": "self",
		"ES384 none": undefined,
		"ES384 packed-self": "self",
		"ES512 none": undefined,
		"ES512 packed-self": "self",
		"Ed25519 packed-basic:ES256-cert": "basic",
		"ES256 packed-basic:Ed25519-key-ECDSA-CA-cert": "basic",
		"Ed25519 packed-basic:Ed25519-key-ECDSA-CA-cert": "basic",
	};

	Object.entries(supported).forEach(([name, attestationType]) => {
		describe(name, function() {
			it("registers and logs in", async function() {
				const reg = await register(name);
				assert.instanceOf(reg, Fido2AttestationResult);
				assert.strictEqual(reg.audit.info.get("attestation-type"), attestationType);

				const res = await login(name, reg.authnrData.get("credentialPublicKeyPem"));
				assert.instanceOf(res, Fido2AssertionResult);
			});

			it("rejects a tampered login signature", async function() {
				const reg = await register(name);
				await assert.isRejected(
					login(name, reg.authnrData.get("credentialPublicKeyPem"), tamper(algorithmResponses[name].assertion.signature)),
					Error,
					"signature validation failed",
				);
			});
		});
	});

	["ES384 none", "ES512 none"].forEach((name) => {
		it(`rejects a ${name.split(" ")[0]} login signed over SHA-256`, async function() {
			const reg = await register(name);
			await assert.isRejected(
				login(name, reg.authnrData.get("credentialPublicKeyPem"), algorithmResponses[name].assertion.sha256Signature),
				Error,
				"signature validation failed",
			);
		});
	});

	it("rejects an attestation certificate signed with Ed25519", function() {
		return assert.isRejected(
			register("Ed25519 packed-basic:Ed25519-cert"),
			Error,
			"Unsupported signature algorithm",
		);
	});

	it("exports an Ed25519 credential as an OKP JWK", async function() {
		const reg = await register("Ed25519 none");
		const jwk = reg.authnrData.get("credentialPublicKeyJwk");
		assert.strictEqual(jwk.kty, "OKP");
		assert.strictEqual(jwk.crv, "Ed25519");
		assert.strictEqual(jwk.alg, "EdDSA");
	});
});
