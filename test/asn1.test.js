import base64 from "@hexagon/base64";

// Testing lib
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";

import { Fido2Lib } from "../lib/main.js";
import { ecdsaPublicKey } from "./fixtures/ecdsaPublicKey.js";

chai.use(chaiAsPromised.default);
const assert = chai.assert;

const base64urlToArrayBuffer = (str) => {
	return base64.toArrayBuffer(str);
};

const verifyAssertion = async (signature) => {
	const input = {
		credId: "UmFuZG9tQ3JlZElk",
		clientData: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTjJKaE1XVTRNV0ppWm1FeE4yRXlNVGM1T0RBeE5HUmpObU0yWm1JMVl6WTROVEJqTkRWak5EUXdOV1kzWkRKaU5tSTNNalpqT1dZMFpHTTJaRGt4WVEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
		authenticatorData: "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAADw==",
		signature: signature,
		userHandle: "UmFuZG9tVXNlcklk",
	};
	const fido2 = new Fido2Lib({
		timeout: 42,
		rpId: "localhost",
		rpName: "localhost",
		challengeSize: 128,
		attestation: "direct",
		cryptoParams: [-7, -257],
		authenticatorRequireResidentKey: true,
		authenticatorUserVerification: "required",
	});

	const challenge = "N2JhMWU4MWJiZmExN2EyMTc5ODAxNGRjNmM2ZmI1YzY4NTBjNDVjNDQwNWY3ZDJiNmI3MjZjOWY0ZGM2ZDkxYQ";
	return await fido2.assertionResult(
		{
			rawId: base64urlToArrayBuffer(input.credId),
			response: {
				clientDataJSON: input.clientData,
				authenticatorData: base64urlToArrayBuffer(input.authenticatorData),
				signature: input.signature,
				userHandle: input.userHandle,
			},
		},
		{
			rpId: "localhost",
			challenge: challenge,
			origin: "http://localhost:3000",
			factor: "first",
			publicKey: ecdsaPublicKey.examplePem,
			prevCounter: 1,
			userHandle: input.userHandle,
		}
	);
};

describe("ECDSA ASN.1/Der to Raw conversion", function() {
	it("can verify an ECDSA signature with r < 32 bytes and s = 32 bytes", async function() {
		// r < 32 bytes | s = 32 bytes
		const signature = "MEQCHyj3uP1iWNTCw0FpsiTe-e7dulZqWqepuXFmCwRmLBYCIQDQnxAkeQFwX-dmfg8XFz3TIx7wfh0MKw0hTCjc2WgMVw";

		const result = await verifyAssertion(signature);
		assert.strictEqual(result.audit.validRequest, true);
		assert.strictEqual(result.audit.validExpectations, true);
	});
	it("can verify an ECDSA signature with r = 32 bytes and s < 32 bytes", async function() {
		// r = 32 bytes | s < 32 bytes
		const signature = "MEMCIGWd6pkFRvBAfse-jGeYfVhlWDKIRyQZyBA32IpdvbMEAh81mQqkXyT2dej9BdABFXdpqR8nzHO1Tq6gfLGjaiX1";

		const result = await verifyAssertion(signature);
		assert.strictEqual(result.audit.validRequest, true);
		assert.strictEqual(result.audit.validExpectations, true);
	});
	it("can verify an ECDSA signature with r < 32 bytes and s < 32 bytes", async function() {
		// r < 32 bytes | s < 32 bytes
		const signature = "MEICHxWF148JkFV86_NzU-APP-yhVuUHEiVatHdeD6K6A0ACHwWsMWQo33oSBgJ3aSVeY1di7B_TU4GDAT0l3QtvPYg";

		const result = await verifyAssertion(signature);
		assert.strictEqual(result.audit.validRequest, true);
		assert.strictEqual(result.audit.validExpectations, true);
	});
	it("can verify an ECDSA signature with r = 33 bytes and s < 32 bytes", async function() {
		// r = 33 bytes | s < 32 bytes
		const signature = "MEQCIQCw1qPkCZQl1ZGJProqe9MC8rGLAsAHZbAHDe9YNAFRSwIfAvp9Ar5cQm-5ANS3zG0P105PmPRRur6F3i03AiLwBw";

		const result = await verifyAssertion(signature);
		assert.strictEqual(result.audit.validRequest, true);
		assert.strictEqual(result.audit.validExpectations, true);
	});
	it("can verify an ECDSA signature with r < 32 bytes and s = 33 bytes", async function() {
		// r < 32 bytes | s = 33 bytes
		const signature = "MEQCHxipYKPnzWezEzFiZWqvJ8Z4-nAJXnFHV4IarB1g818CIQDdVn-OE3uEjRd--Uqj3IA-Zr5RBJor_K9ZCxXuPpalbg";

		const result = await verifyAssertion(signature);
		assert.strictEqual(result.audit.validRequest, true);
		assert.strictEqual(result.audit.validExpectations, true);
	});
	it("can verify an ECDSA signature with r = 32 bytes (0 padded) and s >= 32 bytes", async function() {
		// r = 32 (0 padded) | s >= 32 bytes
		const signature = "MEUCIADqTxqhzztnVk7XXwEeYhlBADK74-he2RsIbvB918TbAiEA4IYFEPc0-3rYRUhZzlWT2oLscUwszPL-9oZOnaFcNZw";

		const result = await verifyAssertion(signature);
		assert.strictEqual(result.audit.validRequest, true);
		assert.strictEqual(result.audit.validExpectations, true);
	});
	it("can verify an ECDSA signature with r >= 32 bytes and s = 32 bytes (0 padded)", async function() {
		// r >= 32 bytes | s = 32 (0 padded)
		const signature = "MEUCIQCAvO4-mEuaX2tYR-AJ8t8vv1AxCqkJgfxIR1XL4yCy8AIgANf3_Cp4LzlzkG4U8VS0WCVrR6_pTBM5mwhUcERNakc";

		const result = await verifyAssertion(signature);
		assert.strictEqual(result.audit.validRequest, true);
		assert.strictEqual(result.audit.validExpectations, true);
	});
	it("can verify an ECDSA signature with r = 30 bytes and s >= 32 bytes", async function() {
		// r = 30 bytes | s >= 32 bytes
		const signature = "MEMCHhCs-kZTCokgrPfb1CaKEznJjqVisSBzMAqv6S24AQIhAOBeIIWXFgOJwA-39dKfzcuG6woJ03tiR0N2ME9Lp206";

		const result = await verifyAssertion(signature);
		assert.strictEqual(result.audit.validRequest, true);
		assert.strictEqual(result.audit.validExpectations, true);
	});
	it("can verify an ECDSA signature with r >= 32 bytes and s < 30 bytes", async function() {
		// r >= 32 bytes | s < 30 bytes
		const signature = "MEECID8aNcMNP3Q-mPSIdPc-ocNyH1vLo_Lh8JgxFXAV7s6DAh0pc_2hHfN6OBPpj_2asyt6I4FBz-ZeVbaGtI9UXQ";

		const result = await verifyAssertion(signature);
		assert.strictEqual(result.audit.validRequest, true);
		assert.strictEqual(result.audit.validExpectations, true);
	});
});
