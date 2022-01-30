"use strict";

const { Fido2Lib } = require("../index");
const {
	Fido2AttestationResult,
	Fido2AssertionResult,
} = require("../lib/response");
const chai = require("chai");
const chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
const assert = chai.assert;
const sinon = require("sinon");
const h = require("fido2-helpers");
const noneAttestation = require("../lib/attestations/none");
const u2fAttestation = require("../lib/attestations/fidoU2F");
const packedAttestation = require("../lib/attestations/packed");
const tpmAttestation = require("../lib/attestations/tpm");
const androidSafetyNetAttestation = require("../lib/attestations/androidSafetyNet");
const packedSelfAttestationResponse = require("../fixtures/packedSelfAttestationData.json");

const {
	MdsCollection,
	MdsEntry,
} = require("../lib/mds");

const {
	abToBuf,
	abEqual,
	printHex,
	coerceToArrayBuffer,
} = require("../lib/utils");

const crypto = require("crypto");

function restoreAttestationFormats() {
	// add 'none' attestation format
	Fido2Lib.addAttestationFormat(
		noneAttestation.name,
		noneAttestation.parseFn,
		noneAttestation.validateFn
	);
	// add 'u2f' attestation format
	Fido2Lib.addAttestationFormat(
		u2fAttestation.name,
		u2fAttestation.parseFn,
		u2fAttestation.validateFn
	);
	// add 'packed' attestation format
	Fido2Lib.addAttestationFormat(
		packedAttestation.name,
		packedAttestation.parseFn,
		packedAttestation.validateFn
	);
	// add 'tpm' attestation format
	Fido2Lib.addAttestationFormat(
		tpmAttestation.name,
		tpmAttestation.parseFn,
		tpmAttestation.validateFn
	);
	// add 'android-safetynet' attestation format
	Fido2Lib.addAttestationFormat(
		androidSafetyNetAttestation.name,
		androidSafetyNetAttestation.parseFn,
		androidSafetyNetAttestation.validateFn
	);
}

describe("Fido2Lib", function() {
	it("can create FIDO server object", function() {
		var fs = new Fido2Lib();
		assert(fs);
		assert.isFunction(fs.attestationOptions);
		assert.isFunction(fs.attestationResult);
		assert.isFunction(fs.assertionOptions);
		assert.isFunction(fs.assertionResult);
	});

	describe("config", function() {
		it("can config timeout", function() {
			var fs = new Fido2Lib({
				timeout: 42,
			});
			assert.strictEqual(fs.config.timeout, 42);
		});

		it("can config zero timeout", function() {
			var fs = new Fido2Lib({
				timeout: 0,
			});
			assert.strictEqual(fs.config.timeout, 0);
		});

		it("has default timeout", function() {
			var fs = new Fido2Lib();
			assert.strictEqual(fs.config.timeout, 60000);
		});

		it("throws on bad timeout", function() {
			assert.throws(function() {
				new Fido2Lib({
					timeout: "foo",
				});
			}, TypeError, "expected timeout to be number, got: foo");
		});

		it("throws on NaN timeout", function() {
			assert.throws(function() {
				new Fido2Lib({
					timeout: NaN,
				});
			}, RangeError, "timeout should be zero or positive integer");
		});

		it("throws on floating point timeout", function() {
			assert.throws(function() {
				new Fido2Lib({
					timeout: 3.14,
				});
			}, RangeError, "timeout should be zero or positive integer");
		});

		it("throws on negative timeout", function() {
			assert.throws(function() {
				new Fido2Lib({
					timeout: -1,
				});
			}, RangeError, "timeout should be zero or positive integer");
		});

		it("can config rpId", function() {
			var fs = new Fido2Lib({
				rpId: "example.com",
			});
			assert.strictEqual(fs.config.rpId, "example.com");
		});

		it("throws on bad rpId", function() {
			assert.throws(function() {
				new Fido2Lib({
					rpId: -1,
				});
			}, TypeError, "expected rpId to be string, got: -1");
		});

		it("can config rpName", function() {
			var fs = new Fido2Lib({
				rpName: "ACME",
			});
			assert.strictEqual(fs.config.rpName, "ACME");
		});

		it("has default rpName", function() {
			var fs = new Fido2Lib();
			assert.strictEqual(fs.config.rpName, "Anonymous Service");
		});

		it("throws on bad rpName", function() {
			assert.throws(function() {
				new Fido2Lib({
					rpName: -1,
				});
			}, TypeError, "expected rpName to be string, got: -1");
		});

		it("can config rpIcon", function() {
			var fs = new Fido2Lib({
				rpIcon: "https://example.com/foo.png",
			});
			assert.strictEqual(fs.config.rpIcon, "https://example.com/foo.png");
		});

		it("throws on bad rpIcon", function() {
			assert.throws(function() {
				new Fido2Lib({
					rpIcon: -1,
				});
			}, TypeError, "expected rpIcon to be string, got: -1");
		});

		it("can config challengeSize", function() {
			var fs = new Fido2Lib({
				challengeSize: 128,
			});
			assert.strictEqual(fs.config.challengeSize, 128);
		});

		it("has default challengeSize", function() {
			var fs = new Fido2Lib();
			assert.strictEqual(fs.config.challengeSize, 64);
		});

		it("throws if challengeSize too small", function() {
			assert.throws(function() {
				new Fido2Lib({
					challengeSize: 31,
				});
			}, RangeError, "challenge size too small");
		});

		it("throws on bad challengeSize", function() {
			assert.throws(function() {
				new Fido2Lib({
					challengeSize: "foo",
				});
			}, TypeError, "expected challengeSize to be number, got: foo");
		});

		it("can config direct attestation", function() {
			var fs = new Fido2Lib({
				attestation: "direct",
			});
			assert.strictEqual(fs.config.attestation, "direct");
		});

		it("can config indirect attestation", function() {
			var fs = new Fido2Lib({
				attestation: "indirect",
			});
			assert.strictEqual(fs.config.attestation, "indirect");
		});

		it("can config none attestation", function() {
			var fs = new Fido2Lib({
				attestation: "none",
			});
			assert.strictEqual(fs.config.attestation, "none");
		});

		it("can config defautl attestation", function() {
			var fs = new Fido2Lib();
			assert.strictEqual(fs.config.attestation, "direct");
		});

		it("throws on bad attestation string", function() {
			assert.throws(function() {
				new Fido2Lib({
					attestation: "foo",
				});
			}, TypeError, "expected attestation to be 'direct', 'indirect', or 'none', got: foo");
		});

		it("throws on bad attestation type", function() {
			assert.throws(function() {
				new Fido2Lib({
					attestation: -1,
				});
			}, TypeError, "expected attestation to be 'direct', 'indirect', or 'none', got: -1");
		});

		it("can config authenticatorAttachment to platform", function() {
			var fs = new Fido2Lib({
				authenticatorAttachment: "platform",
			});
			assert.strictEqual(fs.config.authenticatorAttachment, "platform");
		});

		it("can config authenticatorAttachment to cross-platform", function() {
			var fs = new Fido2Lib({
				authenticatorAttachment: "cross-platform",
			});
			assert.strictEqual(fs.config.authenticatorAttachment, "cross-platform");
		});

		it("throws if authenticatorAttachment isn't platform or cross-platform", function() {
			assert.throws(function() {
				new Fido2Lib({
					authenticatorAttachment: "bob",
				});
			}, TypeError, "expected authenticatorAttachment to be 'platform', or 'cross-platform', got: bob");
		});

		it("can config authenticatorRequireResidentKey to false", function() {
			var fs = new Fido2Lib({
				authenticatorRequireResidentKey: false,
			});
			assert.strictEqual(fs.config.authenticatorRequireResidentKey, false);
		});

		it("can config authenticatorRequireResidentKey to true", function() {
			var fs = new Fido2Lib({
				authenticatorRequireResidentKey: true,
			});
			assert.strictEqual(fs.config.authenticatorRequireResidentKey, true);
		});

		it("throws if authenticatorRequireResidentKey is non-boolean", function() {
			assert.throws(function() {
				new Fido2Lib({
					authenticatorRequireResidentKey: 0,
				});
			}, TypeError, "expected authenticatorRequireResidentKey to be boolean, got: 0");
		});

		it("can config authenticatorUserVerification to discouraged", function() {
			var fs = new Fido2Lib({
				authenticatorUserVerification: "discouraged",
			});
			assert.strictEqual(fs.config.authenticatorUserVerification, "discouraged");
		});

		it("can config authenticatorUserVerification to preferred", function() {
			var fs = new Fido2Lib({
				authenticatorUserVerification: "preferred",
			});
			assert.strictEqual(fs.config.authenticatorUserVerification, "preferred");
		});

		it("can config authenticatorUserVerification to required", function() {
			var fs = new Fido2Lib({
				authenticatorUserVerification: "required",
			});
			assert.strictEqual(fs.config.authenticatorUserVerification, "required");
		});

		it("throws if authenticatorUserVerification is not required, preferred, or discouraged", function() {
			assert.throws(function() {
				new Fido2Lib({
					authenticatorUserVerification: "bob",
				});
			}, TypeError, "expected authenticatorUserVerification to be 'required', 'preferred', or 'discouraged', got: bob");
		});

		it("can config cryptoParams order", function() {
			var fs = new Fido2Lib({
				cryptoParams: [-257, -7],
			});
			assert.deepEqual(fs.config.cryptoParams, [-257, -7]);
		});

		it("can config cryptoParams value", function() {
			var fs = new Fido2Lib({
				cryptoParams: [-8],
			});
			assert.deepEqual(fs.config.cryptoParams, [-8]);
		});

		it("can config cryptoParams value", function() {
			var fs = new Fido2Lib();
			assert.deepEqual(fs.config.cryptoParams, [-7, -257]);
		});

		it("throws on bad cryptoParams", function() {
			assert.throws(function() {
				new Fido2Lib({
					cryptoParams: "bob",
				});
			}, TypeError, "expected cryptoParams to be Array, got: bob");
		});

		it("throws on bad value inside cryptoParams", function() {
			assert.throws(function() {
				new Fido2Lib({
					cryptoParams: [-7, "bob", -257],
				});
			}, TypeError, "expected cryptoParam to be number, got: bob");
		});

		it("throws on empty cryptoParams", function() {
			assert.throws(function() {
				new Fido2Lib({
					cryptoParams: [],
				});
			}, TypeError, "cryptoParams must have at least one element");
		});
	});

	describe("attestationOptions", function() {
		var serv;
		beforeEach(function() {
			serv = new Fido2Lib();
		});

		it("returns options", function() {
			return serv.attestationOptions().then((opts) => {
				assert.isObject(opts);
			});
		});

		it("returns a challenge", function() {
			return serv.attestationOptions().then((opts) => {
				assert.instanceOf(opts.challenge, ArrayBuffer);
				assert.strictEqual(opts.challenge.byteLength, 64);
			});
		});

		it("returns a timeout", function() {
			return serv.attestationOptions().then((opts) => {
				assert.isNumber(opts.timeout);
				assert.strictEqual(opts.timeout, 60000);
			});
		});

		it("picks up values from constructors options", function() {
			serv = new Fido2Lib({
				timeout: 42,
				rpId: "example.com",
				rpName: "ACME",
				rpIcon: "https://example.com/logo.png",
				challengeSize: 128,
				attestation: "none",
				cryptoParams: [-8, -9],
				authenticatorAttachment: "platform",
				authenticatorRequireResidentKey: false,
				authenticatorUserVerification: "required",
			});

			return serv.attestationOptions().then((opts) => {
				assert.isObject(opts);
				assert.isNumber(opts.timeout);
				assert.strictEqual(opts.timeout, 42);
				assert.isObject(opts.rp);
				assert.isString(opts.rp.id);
				assert.strictEqual(opts.rp.id, "example.com");
				assert.isString(opts.rp.name);
				assert.strictEqual(opts.rp.name, "ACME");
				assert.isString(opts.rp.icon);
				assert.strictEqual(opts.rp.icon, "https://example.com/logo.png");
				assert.instanceOf(opts.challenge, ArrayBuffer);
				assert.strictEqual(opts.challenge.byteLength, 128);
				assert.isArray(opts.pubKeyCredParams);
				assert.strictEqual(opts.pubKeyCredParams.length, 2);
				assert.deepEqual(opts.pubKeyCredParams, [
					{
						type: "public-key",
						alg: -8,
					}, {
						type: "public-key",
						alg: -9,
					},
				]);
				assert.isNumber(opts.timeout);
				assert.strictEqual(opts.timeout, 42);
				assert.isObject(opts.authenticatorSelection);
				assert.isString(opts.authenticatorSelection.authenticatorAttachment);
				assert.strictEqual(opts.authenticatorSelection.authenticatorAttachment, "platform");
				assert.isBoolean(opts.authenticatorSelection.requireResidentKey);
				assert.strictEqual(opts.authenticatorSelection.requireResidentKey, false);
				assert.isString(opts.authenticatorSelection.userVerification);
				assert.strictEqual(opts.authenticatorSelection.userVerification, "required");
				assert.isString(opts.attestation);
				assert.strictEqual(opts.attestation, "none");
			});
		});

		it("accepts extraData and returns rawChallenge", async function() {
			let extraData = new Uint8Array([0x1, 0x2, 0x3, 0x4]).buffer;
			let opts = await serv.attestationOptions({
				extraData: extraData,
			});

			let challenge = opts.challenge;
			let hash = crypto.createHash("sha256");
			hash.update(abToBuf(opts.rawChallenge));
			hash.update(abToBuf(extraData));
			let calculatedChallenge = new Uint8Array(hash.digest()).buffer;
			assert.isTrue(abEqual(challenge, calculatedChallenge), "extraData hashes match");
		});
	});

	describe("attestationResult", function() {
		var serv;
		beforeEach(function() {
			serv = new Fido2Lib();
		});

		it("validates a credential request with 'none' attestation", function() {
			var expectations = {
				challenge: "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
				origin: "https://localhost:8443",
				factor: "either",
			};

			return serv.attestationResult(h.lib.makeCredentialAttestationNoneResponse, expectations).then((res) => {
				assert.instanceOf(res, Fido2AttestationResult);
				return res;
			});
		});

		it("validates a credential request with 'u2f' attestation");

		it("validates a packed credential that has self attestation", function() {
			const expectations = {
				challenge: "zBNZ9XmBj4cu7xxYI_uSJauAj89yOTZX1xEqKxhQydhYCTdoKB0k8bzs3llRrBxQlNn3WyRovWvYAXmuIiswLQ",
				origin: "http://localhost:3000",
				factor: "either",
			};

			const parsedPackedSelfAttestationResponse = {
				...packedSelfAttestationResponse,
				id: h.functions.b64decode(packedSelfAttestationResponse.id),
				rawId: h.functions.b64decode(packedSelfAttestationResponse.rawId),
				response: {
					attestationObject: h.functions.b64decode(packedSelfAttestationResponse.response.attestationObject),
					clientDataJSON: h.functions.b64decode(packedSelfAttestationResponse.response.clientDataJSON),
				},
			};

			return serv.attestationResult(parsedPackedSelfAttestationResponse, expectations).then((res) => {
				assert.instanceOf(res, Fido2AttestationResult);
				return res;
			});
		});

		it("validates a credential request with 'android-safetynet' attestation", function(){
			var serv = new Fido2Lib();
			var expectations = {
				challenge: "NrRzgRhGy5Y0NlKNhEAqs4ZFVgNGtN49ZyCTOfLk8G1EPY3vnN3zasIZynlCAyUOLdB3-AALfy1XG2MiVps_Vw",
				origin: "https://contubernio.tic.udc.es",
				factor: "second",
			};

			var makeCredentialAttestationSafetyNetResponse = {
				rawId: coerceToArrayBuffer("AcaOtf577JrxNa9lHZ9g1Npx2YgKhU0w-F_fFkzbOZNZRmh4_S4NFXBBOH75Jf5NS76jK9vcuRiamDIn63Jxxw0","rawId"),
				response: {
					attestationObject: coerceToArrayBuffer(
						"o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaTIwMTgxNzAxN2hyZXNwb25zZVkU3mV5SmhiR2NpT2lKU1V6STFOaUlzSW5nMVl5STZXeUpOU1VsR2EzcERRMEpJZFdkQmQwbENRV2RKVWtGT1kxTnJhbVJ6Tlc0MkswTkJRVUZCUVVGd1lUQmpkMFJSV1VwTGIxcEphSFpqVGtGUlJVeENVVUYzVVdwRlRFMUJhMGRCTVZWRlFtaE5RMVpXVFhoSWFrRmpRbWRPVmtKQmIxUkdWV1IyWWpKa2MxcFRRbFZqYmxaNlpFTkNWRnBZU2pKaFYwNXNZM3BGVkUxQ1JVZEJNVlZGUVhoTlMxSXhVbFJKUlU1Q1NVUkdVRTFVUVdWR2R6QjVUVVJCZUUxVVRYaE5WRkY0VGtSc1lVWjNNSGxOVkVGNFRWUkZlRTFVVVhoT1JHeGhUVWQzZUVONlFVcENaMDVXUWtGWlZFRnNWbFJOVWsxM1JWRlpSRlpSVVVsRmQzQkVXVmQ0Y0ZwdE9YbGliV3hvVFZKWmQwWkJXVVJXVVZGSVJYY3hUbUl6Vm5Wa1IwWndZbWxDVjJGWFZqTk5VazEzUlZGWlJGWlJVVXRGZDNCSVlqSTVibUpIVldkVVJYaEVUVkp6ZDBkUldVUldVVkZFUlhoS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDJkbl"+
						"JXbE5RVEJIUTFOeFIxTkpZak5FVVVWQ1FWRlZRVUUwU1VKRWQwRjNaMmRGUzBGdlNVSkJVVU5YUlhKQ1VWUkhXa2RPTVdsYVlrNDVaV2hTWjJsbVYwSjRjV2t5VUdSbmVIY3dNMUEzVkhsS1dtWk5lR3B3TlV3M2FqRkhUbVZRU3pWSWVtUnlWVzlKWkRGNVEwbDVRazE1ZUhGbllYcHhaM1J3V0RWWGNITllWelJXWmsxb1NtSk9NVmt3T1hGNmNYQTJTa1FyTWxCYVpHOVVWVEZyUmxKQlRWZG1UQzlWZFZwMGF6ZHdiVkpZWjBkdE5XcExSSEphT1U1NFpUQTBkazFaVVhJNE9FNXhkMWN2YTJaYU1XZFVUMDVKVlZRd1YzTk1WQzgwTlRJeVFsSlhlR1ozZUdNelVVVXhLMVJMVjJ0TVEzSjJaV3MyVjJ4SmNYbGhRelV5VnpkTlJGSTRUWEJHWldKNWJWTkxWSFozWmsxU2QzbExVVXhVTUROVlREUjJkRFE0ZVVWak9ITndOM2RVUVVoTkwxZEVaemhSYjNSaGNtWTRUMEpJYTI1dldqa3lXR2wyYVdGV05uUlJjV2hTVDBoRFptZHRia05ZYVhobVZ6QjNSVmhEZG5GcFRGUmlVWFJWWWt4elV5ODRTVkowWkZocmNGRkNPVUZuVFVKQlFVZHFaMmRLV1UxSlNVTldSRUZQUW1kT1ZraFJPRUpCWmpo"+
						"RlFrRk5RMEpoUVhkRmQxbEVWbEl3YkVKQmQzZERaMWxKUzNkWlFrSlJWVWhCZDBWM1JFRlpSRlpTTUZSQlVVZ3ZRa0ZKZDBGRVFXUkNaMDVXU0ZFMFJVWm5VVlUyUkVoQ2QzTkJkbUkxTTJjdlF6QTNjSEpVZG5aM1RsRlJURmwzU0hkWlJGWlNNR3BDUW1kM1JtOUJWVzFPU0RSaWFFUnllal"+
						"YyYzFsS09GbHJRblZuTmpNd1NpOVRjM2RhUVZsSlMzZFpRa0pSVlVoQlVVVkZWMFJDVjAxRFkwZERRM05IUVZGVlJrSjZRVUpvYUhSdlpFaFNkMDlwT0haaU1rNTZZME0xZDJFeWEzVmFNamwyV25rNWJtUklUWGhpZWtWM1MzZFpTVXQzV1VKQ1VWVklUVUZMUjBneWFEQmtTRUUyVEhrNWQyRXlhM1ZhTWpsMlduazVibU16U1hsTU1HUlZWWHBHVUUxVE5XcGpibEYzU0ZGWlJGWlNNRkpDUWxsM1JrbEpVMWxZVWpCYVdFNHdURzFHZFZwSVNuWmhWMUYxV1RJNWRFMURSVWRCTVZWa1NVRlJZVTFDWjNkRFFWbEhXalJGVFVGUlNVTk5RWGRIUTJselIwRlJVVUl4Ym10RFFsRk5kMHgzV1VSV1VqQm1Ra05uZDBwcVFXdHZRMHRuU1VsWlpXRklVakJqUkc5MlRESk9lV0pETlhkaE1tdDFXakk1ZGxwNU9VaFdSazE0VkhwRmRWa3pTbk5OU1VsQ1FrRlpTMHQzV1VKQ1FVaFhaVkZKUlVGblUwSTVVVk5DT0dkRWQwRklZMEU1YkhsVlREbEdNMDFEU1ZWV1FtZEpUVXBTVjJwMVRrNUZlR3Q2ZGprNFRVeDVRVXg2UlRkNFdrOU5RVUZCUm5adWRYa3dXbmRCUVVKQlRVRlRSRUpIUVdsRlFUZGxMe"+
						"kJaVW5VemQwRkdiVmRJTWpkTk1uWmlWbU5hTDIxeWNDczBjbVpaWXk4MVNWQktNamxHTm1kRFNWRkRia3REUTBGaFkxWk9aVmxhT0VORFpsbGtSM0JDTWtkelNIaDFUVTlJYTJFdlR6UXhhbGRsUml0NlowSXhRVVZUVlZwVE5uYzNjeloyZUVWQlNESkxhaXRMVFVSaE5XOUxLekpOYzNoMFZDOVVUVFZoTVhSdlIyOUJRVUZDWWpVM2MzUktUVUZCUVZGRVFVVlpkMUpCU1dkRldHSnBiMUJpU25BNWNVTXdSR295TlRoRVJrZFRVazFCVlN0YVFqRkZhVlpGWW1KaUx6UlZkazVGUTBsQ2FFaHJRblF4T0haU2JqbDZSSFo1Y21aNGVYVmtZMGhVVDFOc00yZFVZVmxCTHpkNVZDOUNhVWcwVFVFd1IwTlRjVWRUU1dJelJGRkZRa04zVlVGQk5FbENRVkZFU1VGalVVSnNiV1E0VFVWblRHUnljbkpOWWtKVVEzWndUVmh6ZERVcmQzZ3lSR3htWVdwS1RrcFZVRFJxV1VacVdWVlJPVUl6V0RSRk1ucG1ORGx1V0ROQmVYVmFSbmhCY1U5U2JtSnFMelZxYTFrM1lUaHhUVW93YWpFNWVrWlBRaXR4WlhKNFpXTXdibWh0T0dkWmJFeGlVVzAyYzB0Wk4xQXdaWGhtY2pkSWRVc3pUV3RRTVhCbFl6RTBk"+
						"MFpGVldGSGNVUjNWV0pIWjJ3dmIybDZNemhHV0VORkswTlhPRVV4VVVGRlZXWjJZbEZRVkZsaVMzaFphaXQwUTA1c2MzTXdZbFJUYjB3eVdqSmtMMm96UW5CTU0wMUdkekI1ZUZOTEwxVlVjWGxyVEhJeVFTOU5aR2hLVVcxNGFTdEhLMDFMVWxOelVYSTJNa0Z1V21GMU9YRTJXVVp2YVNz"+
						"NVFVVklLMEUwT0ZoMFNYbHphRXg1UTFSVk0waDBLMkZMYjJoSGJuaEJOWFZzTVZoU2JYRndPRWgyWTBGME16bFFPVFZHV2tkR1NtVXdkWFpzZVdwUGQwRjZXSFZOZFRkTksxQlhVbU1pTENKTlNVbEZVMnBEUTBGNlMyZEJkMGxDUVdkSlRrRmxUekJ0Y1VkT2FYRnRRa3BYYkZGMVJFRk9RbWRyY1docmFVYzVkekJDUVZGelJrRkVRazFOVTBGM1NHZFpSRlpSVVV4RmVHUklZa2M1YVZsWGVGUmhWMlIxU1VaS2RtSXpVV2RSTUVWblRGTkNVMDFxUlZSTlFrVkhRVEZWUlVOb1RVdFNNbmgyV1cxR2MxVXliRzVpYWtWVVRVSkZSMEV4VlVWQmVFMUxVako0ZGxsdFJuTlZNbXh1WW1wQlpVWjNNSGhPZWtFeVRWUlZkMDFFUVhkT1JFcGhSbmN3ZVUxVVJYbE5WRlYzVFVSQmQwNUVTbUZOUlVsNFEzcEJTa0puVGxaQ1FWbFVRV3hXVkUxU05IZElRVmxFVmxGUlMwVjRWa2hpTWpsdVlrZFZaMVpJU2pGak0xRm5WVEpXZVdSdGJHcGFXRTE0UlhwQlVrSm5UbFpDUVUxVVEydGtWVlY1UWtSUlUwRjRWSHBGZDJkblJXbE5RVEJIUTFOeFIxTkpZak5FVVVWQ1FWRlZRVUUwU1VKRWQwRjNaMmRGUzB"+
						"GdlNVSkJVVVJSUjAwNVJqRkpkazR3TlhwclVVODVLM1JPTVhCSlVuWktlbnA1VDFSSVZ6VkVla1ZhYUVReVpWQkRiblpWUVRCUmF6STRSbWRKUTJaTGNVTTVSV3R6UXpSVU1tWlhRbGxyTDJwRFprTXpVak5XV2sxa1V5OWtUalJhUzBORlVGcFNja0Y2UkhOcFMxVkVlbEp5YlVKQ1NqVjNkV1JuZW01a1NVMVpZMHhsTDFKSFIwWnNOWGxQUkVsTFoycEZkaTlUU2tndlZVd3JaRVZoYkhST01URkNiWE5MSzJWUmJVMUdLeXRCWTNoSFRtaHlOVGx4VFM4NWFXdzNNVWt5WkU0NFJrZG1ZMlJrZDNWaFpXbzBZbGhvY0RCTVkxRkNZbXA0VFdOSk4wcFFNR0ZOTTFRMFNTdEVjMkY0YlV0R2MySnFlbUZVVGtNNWRYcHdSbXhuVDBsbk4zSlNNalY0YjNsdVZYaDJPSFpPYld0eE4zcGtVRWRJV0d0NFYxazNiMGM1YWl0S2ExSjVRa0ZDYXpkWWNrcG1iM1ZqUWxwRmNVWktTbE5RYXpkWVFUQk1TMWN3V1RONk5XOTZNa1F3WXpGMFNrdDNTRUZuVFVKQlFVZHFaMmRGZWsxSlNVSk1la0ZQUW1kT1ZraFJPRUpCWmpoRlFrRk5RMEZaV1hkSVVWbEVWbEl3YkVKQ1dYZEdRVmxKUzNkWlFrSlJWVWhCZD"+
						"BWSFEwTnpSMEZSVlVaQ2QwMURUVUpKUjBFeFZXUkZkMFZDTDNkUlNVMUJXVUpCWmpoRFFWRkJkMGhSV1VSV1VqQlBRa0paUlVaS2FsSXJSelJSTmpncllqZEhRMlpIU2tGaWIwOTBPVU5tTUhKTlFqaEhRVEZWWkVsM1VWbE5RbUZCUmtwMmFVSXhaRzVJUWpkQllXZGlaVmRpVTJGTVpDOW"+
						"pSMWxaZFUxRVZVZERRM05IUVZGVlJrSjNSVUpDUTJ0M1NucEJiRUpuWjNKQ1owVkdRbEZqZDBGWldWcGhTRkl3WTBSdmRrd3lPV3BqTTBGMVkwZDBjRXh0WkhaaU1tTjJXak5PZVUxcVFYbENaMDVXU0ZJNFJVdDZRWEJOUTJWblNtRkJhbWhwUm05a1NGSjNUMms0ZGxrelNuTk1ia0p5WVZNMWJtSXlPVzVNTW1SNlkycEpkbG96VG5sTmFUVnFZMjEzZDFCM1dVUldVakJuUWtSbmQwNXFRVEJDWjFwdVoxRjNRa0ZuU1hkTGFrRnZRbWRuY2tKblJVWkNVV05EUVZKWlkyRklVakJqU0UwMlRIazVkMkV5YTNWYU1qbDJXbms1ZVZwWVFuWmpNbXd3WWpOS05VeDZRVTVDWjJ0eGFHdHBSemwzTUVKQlVYTkdRVUZQUTBGUlJVRkhiMEVyVG01dU56aDVObkJTYW1RNVdHeFJWMDVoTjBoVVoybGFMM0l6VWs1SGEyMVZiVmxJVUZGeE5sTmpkR2s1VUVWaGFuWjNVbFF5YVZkVVNGRnlNREptWlhOeFQzRkNXVEpGVkZWM1oxcFJLMnhzZEc5T1JuWm9jMDg1ZEhaQ1EwOUpZWHB3YzNkWFF6bGhTamw0YW5VMGRGZEVVVWc0VGxaVk5sbGFXaTlZZEdWRVUwZFZPVmw2U25GUWFsazRjVE5OUkhoeWVtM"+
						"XhaWEJDUTJZMWJ6aHRkeTkzU2pSaE1rYzJlSHBWY2paR1lqWlVPRTFqUkU4eU1sQk1Va3cyZFROTk5GUjZjek5CTWsweGFqWmllV3RLV1drNGQxZEpVbVJCZGt0TVYxcDFMMkY0UWxaaWVsbHRjVzEzYTIwMWVreFRSRmMxYmtsQlNtSkZURU5SUTFwM1RVZzFOblF5UkhaeGIyWjRjelpDUW1ORFJrbGFWVk53ZUhVMmVEWjBaREJXTjFOMlNrTkRiM05wY2xOdFNXRjBhaTg1WkZOVFZrUlJhV0psZERoeEx6ZFZTelIyTkZwVlRqZ3dZWFJ1V25veGVXYzlQU0pkZlEuZXlKdWIyNWpaU0k2SW05R2VVNWtTVzQwU204M1ZsbFVkRFJrUkVnMlYxRjZkalZ3TjFac1kwZzRhV3RHVmtoTE1EUmxjWE05SWl3aWRHbHRaWE4wWVcxd1RYTWlPakUxT1RFME16TTRNRGMxTmpRc0ltRndhMUJoWTJ0aFoyVk9ZVzFsSWpvaVkyOXRMbWR2YjJkc1pTNWhibVJ5YjJsa0xtZHRjeUlzSW1Gd2EwUnBaMlZ6ZEZOb1lUSTFOaUk2SWl0clVrSk1WM1ZuVm5wNE1sbFVjVEk1VGtneVJWSnVSRzlITlVOMlRrUnRNR2N5ZGsxUWNVUlFZbFU5SWl3aVkzUnpVSEp2Wm1sc1pVMWhkR05vSWpwMGNuVmxMQ0poY0d0"+
						"RFpYSjBhV1pwWTJGMFpVUnBaMlZ6ZEZOb1lUSTFOaUk2V3lJNFVERnpWekJGVUVwamMyeDNOMVY2VW5OcFdFdzJOSGNyVHpVd1JXUXJVa0pKUTNSaGVURm5NalJOUFNKZExDSmlZWE5wWTBsdWRHVm5jbWwwZVNJNmRISjFaU3dpWlhaaGJIVmhkR2x2YmxSNWNHVWlPaUpDUVZOSlF5Sjku"+
						"S3pKWWJYUEJUSUFvamFNbThqQ1hjR3E3ZU9COWxCMnV1LUlrMmNxU29HYzBYNnlTSUNVRlotNmJSbjAtcnZDS25zazlBN0Y0bkt0UUl0dDBsaFFPUnlLOFFuUUNINnFCYlM1NjQ4akt5cFNQXzNTaEdmbWhuRk1PWWU5UlpONDA0Vi0zWl8xR3BaeElvRjZ4VWZRR2UwSUU3UVd6TEcyN3daSlFDZWwwRzZtMXU0d2JBcWllN0dBRXV0Z0tTc0dxcXdYb3NldEZCQnFzUS1mbUk3Y0lEb3pVc01pbkw0ZmE1djkwQWsyZHFLSlFyclZqRWczdzJKYTNjdmo1X0dWMFpzUlVrdDlQY2E3TnBPaGUtejE4a0xCUGpkYlhJNlZLVW1QSjNrY2xmcVZtY1VvRGk4cXVVMW1wVlJ1VTRIdy1QU2VpMEtqUDVVYTI4UTZxZEs2U2pBaGF1dGhEYXRhWMXZV8JswNgrrG46LjoHvBP-XVNbLFy4fMYY3an12FPexUUAAAAAuT_ZYfLmRi-xIoIAIkfeeABBAcaOtf577JrxNa9lHZ9g1Npx2YgKhU0w-F_fFkzbOZNZRmh4_S4NFXBBOH75Jf5NS76jK9vcuRiamDIn63Jxxw2lAQIDJiABIVggKCVQt7mNWFnqmPUTz5n6zHuR1TMvb8RmmH0E3ILATSciWCCs8K3giniEnyLwfll7C8e1g1PPckAN8JXnGWUfHuGVEA",
						"attestationObject"
					),
					clientDataJSON: coerceToArrayBuffer("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTnJSemdSaEd5NVkwTmxLTmhFQXFzNFpGVmdOR3RONDlaeUNUT2ZMazhHMUVQWTN2bk4zemFzSVp5bmxDQXlVT0xkQjMtQUFMZnkxWEcyTWlWcHNfVnciLCJvcmlnaW4iOiJodHRwczpcL1wvY29udHViZXJuaW8udGljLnVkYy5lcyIsImFuZHJvaWRQYWNrYWdlTmFtZSI6ImNvbS5hbmRyb2lkLmNocm9tZSJ9","clientDataJSON"),
				},
			};

			return serv.attestationResult(makeCredentialAttestationSafetyNetResponse, expectations).then(res => {
				assert.instanceOf(res, Fido2AttestationResult);
				return res;
			});
		});

		it("catches bad requests");
	});

	describe("assertionOptions", function() {
		var serv;
		beforeEach(function() {
			serv = new Fido2Lib();
		});

		it("returns a challenge", function() {
			return serv.assertionOptions().then((chal) => {
				assert.isNumber(chal.timeout);
				assert.strictEqual(chal.timeout, 60000);
				assert.instanceOf(chal.challenge, ArrayBuffer);
				assert.strictEqual(chal.challenge.byteLength, 64);
			});
		});

		it("picks up values from constructors options", function() {
			serv = new Fido2Lib({
				timeout: 42,
				rpId: "example.com",
				rpName: "ACME",
				rpIcon: "https://example.com/logo.png",
				challengeSize: 128,
				attestation: "none",
				cryptoParams: [-8, -9],
				authenticatorAttachment: "platform",
				authenticatorRequireResidentKey: false,
				authenticatorUserVerification: "required",
			});

			return serv.assertionOptions().then((opts) => {
				assert.isObject(opts);
				assert.isNumber(opts.timeout);
				assert.strictEqual(opts.timeout, 42);
				assert.isString(opts.rpId);
				assert.strictEqual(opts.rpId, "example.com");
				assert.instanceOf(opts.challenge, ArrayBuffer);
				assert.strictEqual(opts.challenge.byteLength, 128);
				assert.isString(opts.userVerification);
				assert.strictEqual(opts.userVerification, "required");
			});
		});

		it("accepts extraData and returns rawChallenge", async function() {
			let extraData = new Uint8Array([0x1, 0x2, 0x3, 0x4]).buffer;
			let opts = await serv.assertionOptions({
				extraData: extraData,
			});

			let challenge = opts.challenge;
			let hash = crypto.createHash("sha256");
			hash.update(abToBuf(opts.rawChallenge));
			hash.update(abToBuf(extraData));
			let calculatedChallenge = new Uint8Array(hash.digest()).buffer;
			assert.isTrue(abEqual(challenge, calculatedChallenge), "extraData hashes match");
		});
	});

	describe("assertionResult", function() {
		var serv;
		beforeEach(function() {
			serv = new Fido2Lib();
		});

		it("valid an assertion", function() {
			var expectations = {
				challenge: "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
				origin: "https://localhost:8443",
				factor: "either",
				publicKey: h.lib.assnPublicKey,
				prevCounter: 362,
				userHandle: null,
			};

			return serv.assertionResult(h.lib.assertionResponse, expectations).then((res) => {
				assert.instanceOf(res, Fido2AssertionResult);
				return res;
			});
		});

		it("valid assertion without userHandle", function() {
			var expectations = {
				challenge: "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
				origin: "https://localhost:8443",
				factor: "either",
				publicKey: h.lib.assnPublicKey,
				prevCounter: 362,
				userHandle: null,
			};

			var assertionResponse = {
				rawId: h.lib.assertionResponse.rawId,
				response: {
					clientDataJSON: h.lib.assertionResponse.response.clientDataJSON,
					authenticatorData: h.lib.assertionResponse.response.authenticatorData,
					signature: h.lib.assertionResponse.response.signature,
					// userHandle: h.lib.assertionResponse.response.userHandle
				},
			};

			return serv.assertionResult(assertionResponse, expectations).then((res) => {
				assert.instanceOf(res, Fido2AssertionResult);
				return res;
			});
		});

		it("valid assertion without counter supported", function() {
			var expectations = {
				challenge: "g_Pu32bpluktxugNNBLX-ZO5N9ub0D50bJERbKiU2GWON3md0rR9CaQYdPHdCgo-dpi1-9gbJJvmCuHDnh04Rg",
				origin: "https://mighty-fireant-84.loca.lt",
				factor: "first",
				publicKey: "-----BEGIN PUBLIC KEY-----\n" +
				"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0dBhdNNvh2NkaNstlFhrBhi9yrjP\n" +
				"0qPqZvRRnf3zQiN9zDwJ9ZXoyO4dhKz3OIhMBJG6F+muH35fEsWBZI6dhg==\n" +
				"-----END PUBLIC KEY-----\n",
				prevCounter: 0,
				userHandle: null,
			};

			var assertionResponse = {
				rawId: coerceToArrayBuffer("7S8aQSSxqPkztahKbgw36Mr_-hE", "rawId"),
				response: {
					authenticatorData: coerceToArrayBuffer("YS67HU8UTNyqQ5f-EVzitWw5paVnpyhQli2ahN6PS6UFAAAAAA", "authenticatorData"),
					clientDataJSON: coerceToArrayBuffer("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZ19QdTMyYnBsdWt0eHVnTk5CTFgtWk81Tjl1YjBENTBiSkVSYktpVTJHV09OM21kMHJSOUNhUVlkUEhkQ2dvLWRwaTEtOWdiSkp2bUN1SERuaDA0UmciLCJvcmlnaW4iOiJodHRwczovL21pZ2h0eS1maXJlYW50LTg0LmxvY2EubHQifQ", "clientDataJSON"),
					signature: coerceToArrayBuffer("MEQCIEhIhQBglBn1iGMDgF4WFDG7ISJHD1C1Q60drTaijjV2AiBOnQleadMnzcMJ0EBpwoP8zr2V5lBuKvpNfJrcbC1T4w", "signature"),
				},
			};

			return serv.assertionResult(assertionResponse, expectations).then((res) => {
				assert.instanceOf(res, Fido2AssertionResult);
				return res;
			});
		});
	});

	describe("addAttestationFormat", function() {
		afterEach(function() {
			Fido2Lib.deleteAllAttestationFormats();
		});

		after(function() {
			restoreAttestationFormats();
		});

		it("adds to map on success", function() {
			var serv = new Fido2Lib();
			assert.instanceOf(serv.attestationMap, Map);
			var prevSize = serv.attestationMap.size;
			var ret = Fido2Lib.addAttestationFormat("foo", function() {}, function() {});
			assert.isTrue(ret);
			assert.strictEqual(serv.attestationMap.size, prevSize + 1);
			assert.isTrue(serv.attestationMap.has("foo"));
			var newFmt = serv.attestationMap.get("foo");
			assert.isObject(newFmt);
			assert.strictEqual(Object.keys(newFmt).length, 2);
			assert.isFunction(newFmt.parseFn);
			assert.isFunction(newFmt.validateFn);
		});

		it("throws on bad fmt", function() {
			assert.throws(() => {
				Fido2Lib.addAttestationFormat({}, function() {}, function() {});
			}, TypeError, "expected 'fmt' to be string, got: object");
		});

		it("throws on duplicate fmt", function() {
			Fido2Lib.addAttestationFormat("foo", function() {}, function() {});
			assert.throws(() => {
				Fido2Lib.addAttestationFormat("foo", function() {}, function() {});
			}, Error, "can't add format: 'foo' already exists");
		});

		it("throws on bad parseFn", function() {
			assert.throws(() => {
				Fido2Lib.addAttestationFormat("foo", [], function() {});
			}, TypeError, "expected 'parseFn' to be string, got: object");
		});

		it("throws on bad validateFn", function() {
			assert.throws(() => {
				Fido2Lib.addAttestationFormat("foo", function() {}, "blah");
			}, TypeError, "expected 'validateFn' to be string, got: string");
		});
	});

	describe("parseAttestation", function() {
		var parseStub;
		var validateStub;
		beforeEach(function() {
			parseStub = sinon.stub();
			validateStub = sinon.stub();
			Fido2Lib.addAttestationFormat("foo", parseStub, validateStub);
		});

		afterEach(function() {
			Fido2Lib.deleteAllAttestationFormats();
		});

		after(function() {
			restoreAttestationFormats();
		});

		it("returns Map on success", function() {
			var arg = new Map([
				["test", "yup"],
			]);
			parseStub.onCall(0).returns(arg);
			var ret = Fido2Lib.parseAttestation("foo", arg);
			assert.instanceOf(ret, Map);
			assert.strictEqual(parseStub.callCount, 1);
			assert.isTrue(parseStub.calledWith(arg));
		});

		it("success when returning empty map", function() {
			var arg = new Map();
			parseStub.onCall(0).returns(arg);
			var ret = Fido2Lib.parseAttestation("foo", arg);
			assert.instanceOf(ret, Map);
			assert.strictEqual(parseStub.callCount, 1);
			assert.isTrue(parseStub.calledWith(arg));
		});

		it("throws if parseFn doesn't return Map", function() {
			assert.throws(() => {
				Fido2Lib.parseAttestation("foo", { test: "yup" });
			}, Error, "foo parseFn did not return a Map");
		});

		it("throws on non-string format", function() {
			assert.throws(() => {
				Fido2Lib.parseAttestation({}, { test: "yup" });
			}, TypeError, "expected 'fmt' to be string, got: object");
		});

		it("throws on missing format", function() {
			assert.throws(() => {
				Fido2Lib.parseAttestation();
			}, TypeError, "expected 'fmt' to be string, got: undefined");
		});

		it("throws on missing data", function() {
			assert.throws(() => {
				Fido2Lib.parseAttestation("foo");
			}, TypeError, "expected 'attStmt' to be object, got: undefined");
		});
	});

	describe("validateAttestation", function() {
		var parseStub;
		var validateStub;
		var fakeRequest;
		beforeEach(function() {
			parseStub = sinon.stub();
			validateStub = sinon.stub();
			Fido2Lib.addAttestationFormat("foo", parseStub, validateStub);
			fakeRequest = {
				authnrData: new Map([
					["fmt", "foo"],
				]),
			};
		});

		afterEach(function() {
			Fido2Lib.deleteAllAttestationFormats();
		});

		after(function() {
			restoreAttestationFormats();
		});

		it("returns Map on success", async function() {
			validateStub.onCall(0).returns(true);
			var arg = new Map();
			var ret = await Fido2Lib.validateAttestation.call(fakeRequest);
			assert.isTrue(ret);
			assert.strictEqual(validateStub.callCount, 1);
		});

		it("throws if validateFn doesn't return true", async function() {
			return assert.isRejected(Fido2Lib.validateAttestation.call(fakeRequest), Error, "foo validateFn did not return 'true'");
		});

		it("throws on non-string format", function() {
			fakeRequest.authnrData.set("fmt", {});
			return assert.isRejected(Fido2Lib.validateAttestation.call(fakeRequest), TypeError, "expected 'fmt' to be string, got: object");
		});

		it("throws on missing format", function() {
			fakeRequest.authnrData.clear();
			return assert.isRejected(Fido2Lib.validateAttestation.call(fakeRequest), TypeError, "expected 'fmt' to be string, got: undefined");
		});
	});

	describe("createMdsCollection", function() {
		it("throws if no name provided", function() {
			assert.throws(function() {
				Fido2Lib.createMdsCollection();
			}, Error, "expected 'collectionName' to be non-empty string, got: undefined");
		});

		it("returns a MdsCollection", function() {
			var mc = Fido2Lib.createMdsCollection("test");
			assert.instanceOf(mc, MdsCollection);
		});
	});

	describe("addMdsCollection", function() {
		afterEach(function() {
			Fido2Lib.clearMdsCollections();
		});

		it("throws if argument isn't a MdsCollection", function() {
			assert.throws(function() {
				Fido2Lib.addMdsCollection();
			}, Error, "expected 'mdsCollection' to be instance of MdsCollection, got: undefined");
		});

		it("sets the current global MDS collection", async function() {
			var mc = Fido2Lib.createMdsCollection("test");
			await mc.addToc(h.mds.mds2TocJwt);
			mc.addEntry(h.mds.mds2UafEntry);
			assert.strictEqual(mc.entryList.size, 0);
			Fido2Lib.addMdsCollection(mc);
			assert.strictEqual(mc.entryList.size, 1);
		});

		it("can add multiple collections", async function() {
			var mc1 = Fido2Lib.createMdsCollection("fido-mds-1");
			await mc1.addToc(h.mds.mds1TocJwt);
			mc1.addEntry(h.mds.mds1UafEntry);
			assert.strictEqual(mc1.entryList.size, 0);
			Fido2Lib.addMdsCollection(mc1);
			assert.strictEqual(mc1.entryList.size, 1);

			var mc2 = Fido2Lib.createMdsCollection("fido-mds-2");
			await mc2.addToc(h.mds.mds2TocJwt);
			mc2.addEntry(h.mds.mds2UafEntry);
			assert.strictEqual(mc2.entryList.size, 0);
			Fido2Lib.addMdsCollection(mc2);
			assert.strictEqual(mc2.entryList.size, 1);
		});
	});

	describe("findMdsEntry", function() {
		afterEach(function() {
			Fido2Lib.clearMdsCollections();
		});

		it("throws if a global MDS collection hasn't been set", function() {
			assert.throws(function() {
				Fido2Lib.findMdsEntry("4e4e#4005");
			}, Error, "must set MDS collection before attempting to find an MDS entry");
		});

		it("finds a UAF MDS entry in the global collection", async function() {
			var mc = Fido2Lib.createMdsCollection("test");
			await mc.addToc(h.mds.mds2TocJwt);
			mc.addEntry(h.mds.mds2UafEntry);
			Fido2Lib.addMdsCollection(mc);

			var entryList = Fido2Lib.findMdsEntry("4e4e#4005");
			assert.isArray(entryList);
			assert.strictEqual(entryList.length, 1);
			var entry = entryList[0];
			assert.instanceOf(entry, MdsEntry);
			assert.strictEqual(entry.aaid, "4e4e#4005");
		});

		it("finds a UAF MDS entry in the global collection", async function() {
			var mc = Fido2Lib.createMdsCollection("test");
			await mc.addToc(h.mds.mds1TocJwt);
			mc.addEntry(h.mds.mds1U2fEntry);
			Fido2Lib.addMdsCollection(mc);

			var entryList = Fido2Lib.findMdsEntry("923881fe2f214ee465484371aeb72e97f5a58e0a");
			assert.isArray(entryList);
			assert.strictEqual(entryList.length, 1);
			var entry = entryList[0];
			assert.strictEqual(entry.protocolFamily, "u2f");
			assert.deepEqual(entry.attestationCertificateKeyIdentifiers, ["923881fe2f214ee465484371aeb72e97f5a58e0a"]);
			assert.strictEqual(entry.description, "Feitian BioPass FIDO Security Key");
		});

		it("throws if id isn't specified", async function() {
			var mc = Fido2Lib.createMdsCollection("test");
			await mc.addToc(h.mds.mds2TocJwt);
			mc.addEntry(h.mds.mds2UafEntry);
			Fido2Lib.addMdsCollection(mc);

			assert.throws(function() {
				Fido2Lib.findMdsEntry();
			}, Error, "expected 'id' to be String, got: undefined");
		});

		it("can find multiple entries", async function() {
			// Add UAF 4e4e#4005 from FIDO MDS 1
			var mc1 = Fido2Lib.createMdsCollection("fido-mds1-toc");
			await mc1.addToc(h.mds.mds1TocJwt);
			mc1.addEntry(h.mds.mds1UafEntry4e4e4005);
			Fido2Lib.addMdsCollection(mc1);

			// Add UAF 4e4e#4005 from FIDO MDS 2
			var mc2 = Fido2Lib.createMdsCollection("fido-mds2-toc");
			await mc2.addToc(h.mds.mds2TocJwt);
			mc2.addEntry(h.mds.mds2UafEntry);
			Fido2Lib.addMdsCollection(mc2);

			var entryList = Fido2Lib.findMdsEntry("4e4e#4005");
			assert.isArray(entryList);
			assert.strictEqual(entryList.length, 2);

			// first entry from MDS1
			var entry1 = entryList[0];
			assert.strictEqual(entry1.aaid, "4e4e#4005");
			assert.isObject(entry1.collection);
			assert.strictEqual(entry1.collection.name, "fido-mds1-toc");
			assert.isUndefined(entry1.legalHeader);

			// second entry from MDS2
			var entry2 = entryList[1];
			assert.strictEqual(entry2.aaid, "4e4e#4005");
			assert.isObject(entry2.collection);
			assert.strictEqual(entry2.collection.name, "fido-mds2-toc");
			assert.isString(entry2.legalHeader); // distinguishing characteristic of MDS2
		});
	});
});
