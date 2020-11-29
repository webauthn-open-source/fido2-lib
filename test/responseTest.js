"use strict";

const {
	Fido2Result,
	Fido2AttestationResult,
	Fido2AssertionResult,
} = require("../lib/response");

var assert = require("chai").assert;
const h = require("fido2-helpers");
const { coerceToArrayBuffer } = require("../lib/utils");
const {
	printHex,
	cloneObject,
} = h.functions;

describe("Fido2Result", function() {
	it("is function", function() {
		assert.isFunction(Fido2Result);
	});

	it("throws if called with new", function() {
		assert.throws(() => {
			new Fido2Result();
		}, Error, "Do not create with 'new' operator. Call 'Fido2AttestationResult.create()' or 'Fido2AssertionResult.create()' instead.");
	});
});

describe("Fido2AttestationResult", function() {
	var testReq;
	beforeEach(() => {
		testReq = cloneObject(h.lib.makeCredentialAttestationNoneResponse);
		testReq.response.clientDataJSON = h.lib.makeCredentialAttestationNoneResponse.response.clientDataJSON.slice(0);
		testReq.response.attestationObject = h.lib.makeCredentialAttestationNoneResponse.response.attestationObject.slice(0);
	});

	it("is function", function() {
		assert.isFunction(Fido2AttestationResult);
	});

	it("throws if called with new", function() {
		assert.throws(() => {
			new Fido2AttestationResult();
		}, Error, "Do not create with 'new' operator. Call 'Fido2AttestationResult.create()' or 'Fido2AssertionResult.create()' instead.");
	});

	it("passes with 'none' attestation", async function() {
		var ret = await Fido2AttestationResult.create(h.lib.makeCredentialAttestationNoneResponse, {
			origin: "https://localhost:8443",
			challenge: "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
			flags: ["UP", "AT"],
		});
		assert.instanceOf(ret, Fido2AttestationResult);
	});

	it("passes with 'u2f' attestation", async function() {
		var ret = await Fido2AttestationResult.create(h.lib.makeCredentialAttestationU2fResponse, {
			origin: "https://localhost:8443",
			challenge: "Vu8uDqnkwOjd83KLj6Scn2BgFNLFbGR7Kq_XJJwQnnatztUR7XIBL7K8uMPCIaQmKw1MCVQ5aazNJFk7NakgqA",
			flags: ["UP", "AT"],
		});
		assert.instanceOf(ret, Fido2AttestationResult);
		assert.isObject(ret.audit);
		assert.instanceOf(ret.audit.info, Map);
		assert.instanceOf(ret.audit.warning, Map);
		assert.instanceOf(ret.audit.journal, Set);
		assert.isTrue(ret.audit.info.has("yubico-device-id"));
		assert.strictEqual(ret.audit.info.get("yubico-device-id"), "YubiKey 4/YubiKey 4 Nano");
		assert.isTrue(ret.audit.info.has("attestation-type"));
		assert.strictEqual(ret.audit.info.get("attestation-type"), "basic");
		assert.isTrue(ret.audit.info.has("fido-u2f-transports"));
		var u2fTransports = ret.audit.info.get("fido-u2f-transports");
		assert.instanceOf(u2fTransports, Set);
		assert.strictEqual(u2fTransports.size, 1);
		assert.isTrue(u2fTransports.has("usb"));
	});

	it("passes with Hypersecu u2f attestation", async function() {
		var ret = await Fido2AttestationResult.create(h.lib.makeCredentialAttestationHypersecuU2fResponse, {
			origin: "https://webauthn.org",
			challenge: "pSG9z6Gd5m48WWw9e03AJixbKia0ynEqm7o_9KEkPY0zcaXhjmxoChC5QRnK4E6XIT2QFc_uGycO5lUMygeZgw",
			flags: ["UP", "AT"],
		});

		assert.isObject(ret);
		assert.instanceOf(ret.clientData, Map);
		assert.instanceOf(ret.authnrData, Map);
		assert.isObject(ret.audit);
		assert.instanceOf(ret.audit.info, Map);
		assert.instanceOf(ret.audit.warning, Map);
		assert.strictEqual(ret.audit.warning.size, 1);
		assert.strictEqual(ret.audit.warning.get("attesation-not-validated"), "could not validate attestation because the root attestation certification could not be found");
		assert.strictEqual(ret.audit.info.size, 1);
		assert.strictEqual(ret.audit.info.get("attestation-type"), "basic");
	});

	it("passes with Sam's first u2f attestation", async function() {
		var samAnon1 = {
			"rawId": coerceToArrayBuffer("85YZwBmkHxXoNdCZvUlUuEAYWDfaMYR7AFeelRdVZEJL6IWJPYozsgutHDm3-go8hnM4tNmrGflVH27Ifixfnw", "rawId"),
			"id": coerceToArrayBuffer("85YZwBmkHxXoNdCZvUlUuEAYWDfaMYR7AFeelRdVZEJL6IWJPYozsgutHDm3-go8hnM4tNmrGflVH27Ifixfnw", "id"),
			"response": {
				"clientDataJSON": coerceToArrayBuffer("eyJjaGFsbGVuZ2UiOiJrTldvVXRyUTBPMnB4S2Q4NElhWk9KLUNMSjY5ZWV2bVYtbzhiSGNUaHhnb0otbHNyRVpVUGhXTFd6dzRaSkt6WmVvQkRkTlp1Y0lFeVVtXzRjdXIyUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9", "clientDataJSON"),
				"attestationObject": coerceToArrayBuffer("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQPOWGcAZpB8V6DXQmb1JVLhAGFg32jGEewBXnpUXVWRCS-iFiT2KM7ILrRw5t_oKPIZzOLTZqxn5VR9uyH4sX5-lAQIDJiABIVgg-wdw0fdf-XYOiCWkXpkGsWQ4rFdD1adtm3T1E9EGBLEiWCBxf3Fc35Z1dDWk9py_IrqcjDofanUESVsZlE5rRfQt3g", "attestationObject"),
			},
		};
		var samAnon1Challenge = "kNWoUtrQ0O2pxKd84IaZOJ-CLJ69eevmV-o8bHcThxgoJ-lsrEZUPhWLWzw4ZJKzZeoBDdNZucIEyUm_4cur2Q";
		var ret = await Fido2AttestationResult.create(samAnon1, {
			origin: "https://webauthn.org",
			challenge: samAnon1Challenge,
			flags: ["UP", "AT"],
		});
	});

	it("passes with Sam's second u2f attestation", async function() {
		var ffNonAnon = {
			"rawId": coerceToArrayBuffer("3Rt6TThR4PkGcx8UmGoRXji-xvbgoLDlpYgtVdR8uZ2zU3r6lVf8_R9mXvs2d1dDi3p8x1ApIsg5tl6v5beHUA", "rawId"),
			"id": coerceToArrayBuffer("3Rt6TThR4PkGcx8UmGoRXji-xvbgoLDlpYgtVdR8uZ2zU3r6lVf8_R9mXvs2d1dDi3p8x1ApIsg5tl6v5beHUA", "id"),
			"response": {
				"clientDataJSON": coerceToArrayBuffer("eyJjaGFsbGVuZ2UiOiJRUVRjMjQ2ZmpMSG5ud05ybWluQ0t5SkUtTmczc2tXMzB1cTRMMnZxeF94TmRqOVpJYTRCM0FHaHc2Zl9fUmlqT3M2U2JiUDZtNmxrTGNNSkc0Z1JZZyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9", "clientDataJSON"),
				"attestationObject": coerceToArrayBuffer("o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgMKeGa23je6E2jKxsxwoEKF2u0d08ZGLPT-DG-4Iq8gsCIQDuj9LQtQTYReQ8Drt9iXg7OwxolLOIQojh9BlSrqtoPmN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQN0bek04UeD5BnMfFJhqEV44vsb24KCw5aWILVXUfLmds1N6-pVX_P0fZl77NndXQ4t6fMdQKSLIObZer-W3h1ClAQIDJiABIVggNffg6YQ33oZU8wQEBJzQmIRQW-TmDawtPQzMDoV2P0UiWCCGtepcwfyadjsJEAIRxnBtdMCerQ332aWOC_hGgE74-w", "attestionObject"),
			},
		};
		var ffNonAnonChallenge = "QQTc246fjLHnnwNrminCKyJE-Ng3skW30uq4L2vqx_xNdj9ZIa4B3AGhw6f__RijOs6SbbP6m6lkLcMJG4gRYg";
		var ret = await Fido2AttestationResult.create(ffNonAnon, {
			origin: "https://webauthn.org",
			challenge: ffNonAnonChallenge,
			flags: ["UP", "AT"],
		});
	});

	it("passes with 'packed' attestation", async function() {
		var ret = await Fido2AttestationResult.create(h.lib.makeCredentialAttestationPackedResponse, {
			origin: "https://webauthn.org",
			challenge: "uVX88IgRa0SSrMIRT_q7cRcdfgfRBxCgn_pkpUAnXJK2zOb307wd1OLXQ0AuNaMtBR3amk6HYzp-_VxJTPpwGw",
			flags: ["UP", "AT"],
		});

		assert.isObject(ret);
		assert.strictEqual(ret.authnrData.get("fmt"), "packed");
		assert.isObject(ret.authnrData.get("alg"));
		assert.strictEqual(ret.authnrData.get("alg").algName, "ECDSA_w_SHA256");
		assert.strictEqual(ret.authnrData.get("alg").hashAlg, "SHA256");

		// audit
		var auditInfo = ret.audit.info;
		assert.strictEqual(auditInfo.size, 6);
		assert.isTrue(auditInfo.has("subject-key-identifier"), "audit info has subject-key-identifier");
		assert.isTrue(auditInfo.has("authority-key-identifier"), "audit info has authority-key-identifier");
		assert.isTrue(auditInfo.has("basic-constraints"), "audit info has basic-constraints");
		assert.isTrue(auditInfo.has("fido-u2f-transports"), "audit info has fido-u2f-transports");
		assert.isTrue(auditInfo.has("fido-aaguid"), "audit info has fido-aaguid");
		assert.isTrue(auditInfo.has("attestation-type"), "audit info has attestation-type");
		assert.isTrue(ret.audit.warning.has("attesation-not-validated"), "audit warning has attesation-not-validated");
	});

	it("passes with 'tpm' attestation", async function() {
		var ret = await Fido2AttestationResult.create(h.lib.makeCredentialAttestationTpmResponse, {
			origin: "https://webauthn.org",
			challenge: "wk6LqEXAMAZpqcTYlY2yor5DjiyI_b1gy9nDOtCB1yGYnm_4WG4Uk24FAr7AxTOFfQMeigkRxOTLZNrLxCvV_Q",
			flags: ["UP", "AT"],
		});

		assert.strictEqual(ret.authnrData.get("fmt"), "tpm");
		assert.isObject(ret.authnrData.get("alg"));
		assert.strictEqual(ret.authnrData.get("alg").algName, "RSASSA-PKCS1-v1_5_w_SHA1");
		assert.strictEqual(ret.authnrData.get("alg").hashAlg, "SHA1");
		assert.isString(ret.authnrData.get("ver"));
		assert.strictEqual(ret.authnrData.get("ver"), "2.0");

		// audit
		var auditInfo = ret.audit.info;
		assert.strictEqual(auditInfo.size, 9);
		assert.isTrue(auditInfo.has("key-usage"), "audit info has key-usage");
		assert.isTrue(auditInfo.has("basic-constraints"), "audit info has basic-constraints");
		assert.isTrue(auditInfo.has("certificate-policies"), "audit info has certificate-policies");
		assert.isTrue(auditInfo.has("ext-key-usage"), "audit info has ext-key-usage");
		assert.isTrue(auditInfo.has("subject-alt-name"), "audit info has subject-alt-name");
		assert.isTrue(auditInfo.has("authority-key-identifier"), "audit info has authority-key-identifier");
		assert.isTrue(auditInfo.has("subject-key-identifier"), "audit info has subject-key-identifier");
		assert.isTrue(auditInfo.has("authority-info-access"), "audit info has authority-info-access");
		assert.isTrue(auditInfo.has("attestation-type"), "audit info has attestation-type");
		assert.isTrue(ret.audit.warning.has("attesation-not-validated"), "audit warning has attesation-not-validated");
	});
});

describe("Fido2AssertionResult", function() {
	var testReq;
	beforeEach(() => {
		testReq = cloneObject(h.lib.makeCredentialAttestationNoneResponse);
		testReq.response.clientDataJSON = h.lib.makeCredentialAttestationNoneResponse.response.clientDataJSON.slice(0);
		testReq.response.attestationObject = h.lib.makeCredentialAttestationNoneResponse.response.attestationObject.slice(0);
	});

	it("is function", function() {
		assert.isFunction(Fido2AssertionResult);
	});

	it("throws if called with new", function() {
		assert.throws(() => {
			new Fido2AssertionResult();
		}, Error, "Do not create with 'new' operator. Call 'Fido2AttestationResult.create()' or 'Fido2AssertionResult.create()' instead.");
	});

	it("returns Fido2AssertionResult object on success", async function() {
		var ret = await Fido2AssertionResult.create(h.lib.assertionResponse, {
			origin: "https://localhost:8443",
			challenge: "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
			flags: ["UP"],
			prevCounter: 362,
			publicKey: h.lib.assnPublicKey,
			userHandle: null,
		});
		assert.instanceOf(ret, Fido2AssertionResult);
	});

	it("works with WindowsHello", async function() {
		var ret = await Fido2AssertionResult.create(h.lib.assertionResponseWindowsHello, {
			origin: "https://webauthn.org",
			challenge: "m7ZU0Z-_IiwviFnF1JXeJjFhVBincW69E1Ctj8AQ-Ybb1uc41bMHtItg6JACh1sOj_ZXjonw2acj_JD2i-axEQ",
			flags: ["UP"],
			prevCounter: 0,
			publicKey: h.lib.assnPublicKeyWindowsHello,
			userHandle: "YWs",
		});
		assert.instanceOf(ret, Fido2AssertionResult);
	});
});
