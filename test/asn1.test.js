// Testing lib
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";

import crypto from "crypto";
import { Fido2Lib } from "../lib/main.js";

chai.use(chaiAsPromised.default);
const assert = chai.assert;

const sha256 = (data) => {
	return crypto.createHash("sha256").update(data).digest("hex");
};

const base64url = (buf) => {
	return Buffer.from(buf).toString("base64url");
};
const base64urlToBuffer = (str) => {
	return Buffer.from(str, "base64url");
};
const base64urlToArrayBuffer = (str) => {
	const buf = base64urlToBuffer(str);
	return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
};

const generateSignature = (authenticatorData, clientData, privateKey) => {
	const dataHash = sha256(clientData);
	const authenticatorDataHex = base64urlToBuffer(authenticatorData).toString("hex");
	let signature;
	do {
		signature = new Uint8Array(
			crypto.sign(
				null,
				Buffer.from(authenticatorDataHex + dataHash, "hex"),
				privateKey
			)
		);
	} while(signature[3] >= 32);

	return base64url(signature);
};

const generateAuthenticatorData = () => {
	const flags = 5;
	const counter = 15;

	const rpidHash = sha256("localhost", "hex");
	const authData = Buffer.from(
		rpidHash + flags.toString(16).padStart(2, "0") + counter.toString(16).padStart(8, "0"),
		"hex"
	);

	return base64url(authData);
};

const generateInput = (privateKey) => {
	const challenge = sha256("SomeRandomChallenge");
	const clientData = JSON.stringify({
		type: "webauthn.get",
		challenge: base64url(challenge),
		origin: "http://localhost:3000",
		crossOrigin: false,
	});

	const authenticatorData = generateAuthenticatorData();

	return {
		credId: base64url("RandomCredId"),
		clientData: base64url(clientData),
		authenticatorData: authenticatorData,
		signature: generateSignature(authenticatorData, clientData, privateKey),
		userHandle: base64url("RandomUserId"),
	};
};

describe("assertion", function() {
	it("can verify a ECDSA signature with non-standard r / s", async function() {
		const key = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
		const privateKey = key.privateKey.export({ type: "pkcs8", format:"pem" });
		const publicKey = key.publicKey.export({ type: "spki", format:"pem" });
		const input = generateInput(privateKey);
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
	
		const challenge = sha256("SomeRandomChallenge");
		const result = await fido2.assertionResult(
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
				challenge: base64url(challenge),
				origin: "http://localhost:3000",
				factor: "first",
				publicKey: publicKey,
				prevCounter: 1,
				userHandle: input.userHandle,
			}
		);
		assert.strictEqual(result.audit.validRequest, true);
		assert.strictEqual(result.audit.validExpectations, true);
	});
});
