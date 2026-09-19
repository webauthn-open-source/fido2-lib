import { Fido2Lib, PublicKey, coerceToArrayBuffer, coerceToBase64Url } from "fido2-lib";

// STEP 1: Add the extension for app id like specified in https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/Migrating_from_U2F.html
const optionGeneratorFn = (extName, type, value) => value;
const resultParserFn = () => { };
const resultValidatorFn = () => { };
Fido2Lib.addExtension("appid", optionGeneratorFn, resultParserFn, resultValidatorFn);

// STEP 2: Create fido2 instance and enable the extension appid
const f2l = new Fido2Lib({
	rpId: "example.com",
	rpName: "ACME",
	authenticatorAttachment: "cross-platform",
	authenticatorUserVerification: "preferred",
	cryptoParams: [-7],
});
f2l.enableExtension("appid");

// parse a public key from its base64 encoded COSE form
const storedCosePublicKeyToPem = async (b64Cose) => {
	const key = await new PublicKey().fromCose(coerceToArrayBuffer(b64Cose, "pkey"));
	return key.toPem();
};

const main = async () => {
	// STEP 3: Generate authentication challenge
	const authnOptions = await f2l.assertionOptions({
		extensionOptions: {
			appid: "https://www.example.com", // notice lowercase i in appid
		},
	});
	// encode challenge in format supported for data transfer
	authnOptions.challenge = coerceToBase64Url(authnOptions.challenge, "challenge");

	const authnChallenge = {
		allowCredentials: [ // force only specific credentials
			{
				id: "lTqW8H/lHJ4yT0nLOvsvKgcyJCeO8LdUjG5vkXpgO2b0XfyjLMejRvW5oslZtA4B/GgkO/qhTgoBWSlDqCng4Q==",
				type: "public-key",
			},
		],
		...authnOptions,
	};

	const serverResponse = JSON.stringify(authnChallenge, null, 2); // send to client side
	// example response
	// {
	//   "allowCredentials": [
	//     {
	//       "id": "lTqW8H/lHJ4yT0nLOvsvKgcyJCeO8LdUjG5vkXpgO2b0XfyjLMejRvW5oslZtA4B/GgkO/qhTgoBWSlDqCng4Q==",
	//       "type": "public-key"
	//     }
	//   ],
	//   "challenge": "hF6cDwH8Xy6uAkp2ivBIL9Fla4_HNptF5nbtxfHpz2sajVvU4GIHUzY43zIGnU2AGARQp0tD-aiaU3Zecw4ocA",
	//   "timeout": 60000,
	//   "rpId": "example.com",
	//   "userVerification": "preferred",
	//   "extensions": {
	//     "appid": "https://www.example.com"
	//   }
	// }

	// STEP 4: Verify response from client side
	const expectedAuthn = {
		challenge: authnChallenge.challenge,
		origin: "https://www.example.com",
		rpId: authnChallenge.extensions.appid,
		factor: "either",
		publicKey: await storedCosePublicKeyToPem("pQECAy..."), // useful if you don't store the key in PEM format
		prevCounter: 1234,
		userHandle: null,
	};

	// example response
	const authnResponse = {
		id: "lTqW8H/lHJ4yT0nLOvsvKgcyJCeO8LdUjG5vkXpgO2b0XfyjLMejRvW5oslZtA4B/GgkO/qhTgoBWSlDqCng4Q==",
		response: {
			authenticatorData: "lK8QzA8NSNiTPCRHJiqlEt4CmIbp1e_wbVZ04wfB8I0BAAAFlw",
			clientDataJSON: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaEY2Y0R3SDhYeTZ1QWtwMml2QklMOUZsYTRfSE5wdEY1bmJ0eGZIcHoyc2FqVnZVNEdJSFV6WTQzeklHblUyQUdBUlFwMHRELWFpYVUzWmVjdzRvY0EiLCJvcmlnaW4iOiJodHRwczovL3d3dy5zdGFnaW5nLmJpdGZpbmV4LmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
			signature: "MEQCIE_-3E2ZWKs7hdzoV4MqZhbdto4ipqiyHok5fYjxNTE6AiBI4rD6kV_nb4ETc935yCjY1LFCcphnEZtf6FnF3n_YMw",
		},
	};
	authnResponse.id = coerceToArrayBuffer(authnResponse.id, "id"); // convert base64url data to array buffer 

	const authnResult = await f2l.assertionResult(authnResponse, expectedAuthn); // will throw on failure

	const validResponse = authnResult.audit.complete && authnResult.audit.validRequest && authnResult.audit.validExpectations;
	const newCounter = authnResult.authnrData.get("counter");
	const authenticated = validResponse && newCounter > expectedAuthn.prevCounter; // double check also counter to make sure auth passed
	console.log(authenticated); // true
};

await main();

// NOTE! for migrating your u2f credentials to webauthn you can use this example:
// https://github.com/cedarcode/webauthn-ruby/blob/master/docs/u2f_migration.md
