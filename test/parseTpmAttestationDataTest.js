"use strict";

const parser = require("../lib/parser");
var assert = require("chai").assert;
const h = require("fido2-helpers");
var {
	coerceToBase64,
	abEqual,
	printHex,
} = require("../lib/utils");

var runs = [
	{ functionName: "parseAuthnrAttestationResponse" },
	{ functionName: "parseAttestationObject" },
];

runs.forEach(function(run) {

	describe(run.functionName + " (tpm)", function() {
		it("parser is object", function() {
			assert.isObject(parser);
		});

		var ret;
		it("can parse", function() {
			ret = run.functionName == "parseAuthnrAttestationResponse" ? parser[run.functionName](h.lib.makeCredentialAttestationTpmResponse) :  parser[run.functionName](h.lib.makeCredentialAttestationTpmResponse.response.attestationObject);
			// console.log("ret", ret);
		});

		it("parser returns Map with correct size", function() {
			assert.instanceOf(ret, Map);
			assert.strictEqual(ret.size, 19);
		});

		it("parses fmt", function() {
			var fmt = ret.get("fmt");
			assert.strictEqual(fmt, "tpm");
		});

		it("parses sig", function() {
			var sig = ret.get("sig");
			assert.instanceOf(sig, ArrayBuffer);
			assert.strictEqual(sig.byteLength, 256);

			var expectedSig = new Uint8Array([
				0x71, 0x5D, 0x62, 0xCD, 0x61, 0x94, 0x58, 0x8B, 0x34, 0x0C, 0x43, 0x99, 0x35, 0x01, 0x9D, 0xAE,
				0x23, 0x4D, 0x5E, 0x8E, 0xA7, 0x6E, 0xB1, 0x83, 0x2F, 0x31, 0x00, 0x7A, 0xCC, 0x02, 0x2B, 0xD9,
				0xE3, 0x60, 0x60, 0x8B, 0x98, 0xE9, 0x07, 0x56, 0x04, 0xB2, 0x69, 0xF8, 0x6C, 0x8C, 0x21, 0x0C,
				0x66, 0x44, 0x26, 0xB8, 0xF5, 0x26, 0x10, 0xE3, 0x03, 0x2A, 0x8B, 0x2A, 0xC6, 0xEA, 0x7F, 0xB6,
				0x25, 0xD0, 0xC0, 0x6E, 0x32, 0x09, 0x6F, 0x53, 0xC9, 0x6A, 0x08, 0x35, 0x61, 0x9A, 0xC9, 0x0E,
				0x2F, 0x72, 0xBE, 0x98, 0xB3, 0xE9, 0x7A, 0x28, 0xC3, 0xE4, 0x83, 0xFF, 0xDD, 0xD9, 0x5C, 0xB0,
				0x85, 0xFA, 0x27, 0x9D, 0x32, 0x43, 0x05, 0xF1, 0x3F, 0xE0, 0x12, 0x11, 0x0F, 0xAD, 0x06, 0x47,
				0x4A, 0x81, 0xCD, 0x36, 0xAB, 0xB6, 0x10, 0xC7, 0x40, 0x53, 0x2A, 0x46, 0xDA, 0x14, 0xB6, 0xE3,
				0xAC, 0x4C, 0x5E, 0x63, 0x79, 0xD5, 0x37, 0x11, 0x03, 0xE8, 0x8D, 0x10, 0x39, 0x88, 0x23, 0x42,
				0xDA, 0x76, 0x82, 0x09, 0x9B, 0x8C, 0x49, 0x44, 0x5D, 0x94, 0xF9, 0xA1, 0x95, 0x6E, 0x6B, 0x01,
				0xA4, 0x59, 0x54, 0x5E, 0x35, 0x65, 0x91, 0x02, 0x8B, 0x98, 0x85, 0x38, 0xCD, 0xAB, 0x3B, 0x45,
				0x29, 0x1A, 0xE4, 0x12, 0x2D, 0x4B, 0xEB, 0xD4, 0xCA, 0x90, 0x3A, 0xC0, 0xF2, 0xB4, 0xC7, 0xFB,
				0xA9, 0x66, 0x4C, 0xBF, 0x04, 0xFF, 0xE7, 0xFF, 0x01, 0x17, 0xA1, 0x8D, 0x74, 0x1D, 0xA5, 0xD9,
				0x5C, 0xE6, 0x20, 0x90, 0x5B, 0x57, 0xA8, 0x3C, 0xCF, 0xB7, 0x63, 0xD1, 0xF4, 0x64, 0x8E, 0x50,
				0x97, 0x06, 0x9F, 0x14, 0x1B, 0x62, 0xEF, 0x4E, 0xAE, 0x52, 0xB1, 0xFB, 0xA0, 0xAD, 0x15, 0x97,
				0x38, 0x9F, 0x01, 0x91, 0xD3, 0x29, 0x94, 0xF7, 0xE5, 0xD2, 0x6C, 0xFA, 0xB2, 0xC5, 0x3F, 0x9F,
			]).buffer;

			assert.isTrue(abEqual(sig, expectedSig), "sig has correct value");
		});

		it("parses version", function() {
			var ver = ret.get("ver");
			assert.isString(ver);
			assert.strictEqual(ver, "2.0");
		});

		it("parses attestation certificate", function() {
			var attCert = ret.get("attCert");

			assert.instanceOf(attCert, ArrayBuffer);
			assert.strictEqual(attCert.byteLength, 1206);
			attCert = coerceToBase64(attCert, "attCert");
			assert.strictEqual(attCert, "MIIEsjCCA5qgAwIBAgIQEyidpWZzRxOSMNfrAvV1fzANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELTE1OTFENEI2RUFGOThEMDEwNDg2NEI2OTAzQTQ4REQwMDI2MDc3RDMwHhcNMTgwNTIwMTYyMDQ0WhcNMjgwNTIwMTYyMDQ0WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvQ6XK2ujM11E7x4SL34p252ncyQTd3+4r5ALQhBbFKS95gUsuENTG+48GBQwu48i06cckm3eH20TUeJvn4+pj6i8LFOrIK14T3P3GFzbxgQLq1KVm63JWDdEXk789JgzQjHNO7DZFKWTEiktwmBUPUA88TjQcXOtrR5EXTrt1FzGzabOepFann3Ny/XtxI8lDZ3QLwPLJfmk7puGtkGNaXOsRC7GLAnoEB7UWvjiyKG6HAtvVTgxcW5OQnHFb9AHycU5QdukXrP0njdCpLCRR0Nq6VMKmVU3MaGh+DCwYEB32sPNPdDkPDWyk16ItwcmXqfSBV5ZOr8ifvcXbCWUWwIDAQABo4IB5TCCAeEwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwbQYDVR0gAQH/BGMwYTBfBgkrBgEEAYI3FR8wUjBQBggrBgEFBQcCAjBEHkIAVABDAFAAQQAgACAAVAByAHUAcwB0AGUAZAAgACAAUABsAGEAdABmAG8AcgBtACAAIABJAGQAZQBuAHQAaQB0AHkwEAYDVR0lBAkwBwYFZ4EFCAMwSgYDVR0RAQH/BEAwPqQ8MDoxODAOBgVngQUCAwwFaWQ6MTMwEAYFZ4EFAgIMB05QQ1Q2eHgwFAYFZ4EFAgEMC2lkOjRFNTQ0MzAwMB8GA1UdIwQYMBaAFMISqVvO+lb4wMFvsVvdAzRHs3qjMB0GA1UdDgQWBBSv4kXTSA8i3NUM0q57lrWpM8p/4TCBswYIKwYBBQUHAQEEgaYwgaMwgaAGCCsGAQUFBzAChoGTaHR0cHM6Ly9hemNzcHJvZG5jdWFpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L25jdS1udGMta2V5aWQtMTU5MWQ0YjZlYWY5OGQwMTA0ODY0YjY5MDNhNDhkZDAwMjYwNzdkMy8zYjkxOGFlNC0wN2UxLTQwNTktOTQ5MS0wYWQyNDgxOTA4MTguY2VyMA0GCSqGSIb3DQEBCwUAA4IBAQAs+vqdkDX09fNNYqzbv3Lh0vl6RgGpPGl+MYgO8Lg1I9UKvEUaaUHm845ABS8m7r9p22RCWO6TSEPS0YUYzAsNuiKiGVna4nB9JWZaV9GDS6aMD0nJ8kNciorDsV60j0Yb592kv1VkOKlbTF7+Z10jaapx0CqhxEIUzEBb8y9Pa8oOaQf8ORhDHZp+mbn/W8rUzXSDS0rFbWKaW4tGpVoKGRH+f9vIeXxGlxVS0wqqRm/r+h1aZInta0OOiL/S4367gZyeLL3eUnzdd+eYySYn2XINPbVacK8ZifdsLMwiNtz5uM1jbqpEn2UoB3Hcdn0hc12jTLPWFfg7GiKQ0hk9");
		});

		it("parses x5c", function() {
			var x5c = ret.get("x5c");

			assert.isArray(x5c);
			assert.strictEqual(x5c.length, 1);
			var cert = x5c[0];

			assert.instanceOf(cert, ArrayBuffer);
			assert.strictEqual(cert.byteLength, 1516);
			cert = coerceToBase64(cert, "cert");
			assert.strictEqual(cert, "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");
		});

		it("parses alg", function() {
			var alg = ret.get("alg");

			assert.isObject(alg);
			assert.strictEqual(Object.keys(alg).length, 2);
			assert.strictEqual(alg.algName, "RSASSA-PKCS1-v1_5_w_SHA1");
			assert.strictEqual(alg.hashAlg, "SHA1");
		});

		describe("certInfo", function() {
			var certInfo;
			it("exists", function() {
				certInfo = ret.get("certInfo");
			});

			it("is Map", function() {
				assert.instanceOf(certInfo, Map);
			});

			it("is correct length", function() {
				assert.strictEqual(certInfo.size, 15);
			});

			it("has raw data", function() {
				var rawCertInfo = certInfo.get("rawCertInfo");
				assert.instanceOf(rawCertInfo, ArrayBuffer);
				assert.strictEqual(rawCertInfo.byteLength, 161);

				var expectedRawCertInfo = new Uint8Array([
					0xFF, 0x54, 0x43, 0x47, 0x80, 0x17, 0x00, 0x22, 0x00, 0x0B, 0xBC, 0x59, 0xF4, 0xDF, 0xD9, 0xA6,
					0xA4, 0x2D, 0xC3, 0xB8, 0x66, 0xAF, 0xF2, 0xDF, 0x0D, 0x19, 0x82, 0x6B, 0xBF, 0x01, 0x4B, 0x67,
					0xAB, 0x0A, 0xD6, 0xEB, 0xB1, 0x76, 0x30, 0x6B, 0x80, 0x07, 0x00, 0x14, 0xAC, 0x9F, 0x3F, 0x05,
					0x69, 0xC6, 0x62, 0xFB, 0x09, 0x14, 0x91, 0xF1, 0xEE, 0xE3, 0x18, 0xC6, 0xF0, 0xC3, 0xDF, 0x9B,
					0x00, 0x00, 0x00, 0x01, 0xB1, 0x5A, 0x48, 0xC7, 0x68, 0x40, 0xF9, 0xE3, 0xD8, 0xF3, 0x9F, 0x05,
					0x01, 0xA9, 0xE0, 0xC4, 0xA5, 0x3F, 0xBB, 0xC4, 0x13, 0x00, 0x22, 0x00, 0x0B, 0x71, 0x21, 0xAE,
					0xBF, 0xA6, 0xB9, 0xAF, 0xD0, 0x70, 0x32, 0xF4, 0x2F, 0x09, 0x25, 0xE0, 0xEC, 0x67, 0x40, 0x8D,
					0xD5, 0x99, 0xA5, 0x7B, 0xFA, 0x0F, 0x80, 0xC7, 0xF1, 0x56, 0x01, 0x08, 0x4F, 0x00, 0x22, 0x00,
					0x0B, 0x01, 0x52, 0x34, 0x79, 0x0F, 0xC0, 0x01, 0x98, 0xCD, 0xBE, 0xB8, 0x54, 0x10, 0xC2, 0xB6,
					0xAB, 0x8C, 0x31, 0xBB, 0x02, 0x05, 0x3A, 0x71, 0xC8, 0x0C, 0x5D, 0x10, 0x96, 0x38, 0x5F, 0xE3,
					0xB4,
				]).buffer;

				assert.isTrue(abEqual(rawCertInfo, expectedRawCertInfo), "rawCertInfo has correct value");
			});

			it("parses magic", function() {
				var magic = certInfo.get("magic");

				assert.strictEqual(magic, 0xff544347);
			});

			it("parses type", function() {
				var type = certInfo.get("type");

				assert.isString(type);
				assert.strictEqual(type, "TPM_ST_ATTEST_CERTIFY");
			});

			it("parses qualifiedSigner", function() {
				var qualifiedSignerHashType = certInfo.get("qualifiedSignerHashType");
				assert.strictEqual(qualifiedSignerHashType, "TPM_ALG_SHA256");

				var qualifiedSigner = certInfo.get("qualifiedSigner");
				assert.instanceOf(qualifiedSigner, ArrayBuffer);
				assert.strictEqual(qualifiedSigner.byteLength, 32);
				qualifiedSigner = coerceToBase64(qualifiedSigner, "qualifiedSigner");
				assert.strictEqual(qualifiedSigner, "vFn039mmpC3DuGav8t8NGYJrvwFLZ6sK1uuxdjBrgAc=");
			});

			it("parses extraData", function() {
				var extraData = certInfo.get("extraData");

				assert.instanceOf(extraData, ArrayBuffer);
				assert.strictEqual(extraData.byteLength, 20);
			});

			it("parses clock", function() {
				var clock = certInfo.get("clock");

				assert.instanceOf(clock, ArrayBuffer);
				assert.strictEqual(clock.byteLength, 8);
			});

			it("parses resetCount", function() {
				var resetCount = certInfo.get("resetCount");

				assert.strictEqual(resetCount, 1749088739);
			});

			it("parses restartCount", function() {
				var restartCount = certInfo.get("restartCount");

				assert.strictEqual(restartCount, 3639844613);
			});

			it("parses safe", function() {
				var safe = certInfo.get("safe");

				assert.strictEqual(safe, true);
			});

			it("parses firmwareVersion", function() {
				var firmwareVersion = certInfo.get("firmwareVersion");

				assert.instanceOf(firmwareVersion, ArrayBuffer);
				assert.strictEqual(firmwareVersion.byteLength, 8);
			});

			it("parses nameHashType", function() {
				var nameHashType = certInfo.get("nameHashType");

				assert.strictEqual(nameHashType, "TPM_ALG_SHA256");
			});

			it("parses name", function() {
				var name = certInfo.get("name");

				assert.instanceOf(name, ArrayBuffer);
				assert.strictEqual(name.byteLength, 32);
			});

			it("parses qualifiedNameHashType", function() {
				var qualifiedNameHashType = certInfo.get("qualifiedNameHashType");
				assert.strictEqual(qualifiedNameHashType, "TPM_ALG_SHA256");

				var qualifiedName = certInfo.get("qualifiedName");
				assert.instanceOf(qualifiedName, ArrayBuffer);
				assert.strictEqual(qualifiedName.byteLength, 32);
			});
		});

		describe("pubArea", function() {
			var pubArea;
			it("exists", function() {
				pubArea = ret.get("pubArea");
			});

			it("is Map", function() {
				assert.instanceOf(pubArea, Map);
			});

			it("is correct length", function() {
				assert.strictEqual(pubArea.size, 10);
			});

			it("has raw data", function() {
				var rawPubArea = pubArea.get("rawPubArea");
				assert.instanceOf(rawPubArea, ArrayBuffer);
				assert.strictEqual(rawPubArea.byteLength, 310);

				var expectedRawPubArea = new Uint8Array([
					0x00, 0x01, 0x00, 0x0B, 0x00, 0x06, 0x04, 0x72, 0x00, 0x20, 0x9D, 0xFF, 0xCB, 0xF3, 0x6C, 0x38,
					0x3A, 0xE6, 0x99, 0xFB, 0x98, 0x68, 0xDC, 0x6D, 0xCB, 0x89, 0xD7, 0x15, 0x38, 0x84, 0xBE, 0x28,
					0x03, 0x92, 0x2C, 0x12, 0x41, 0x58, 0xBF, 0xAD, 0x22, 0xAE, 0x00, 0x10, 0x00, 0x10, 0x08, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC5, 0xDA, 0x6F, 0x4D, 0x93, 0x57, 0xBD, 0xE2, 0x02, 0xF5,
					0xC5, 0x58, 0xCD, 0x0A, 0x31, 0x56, 0xD2, 0x54, 0xF2, 0xE0, 0xAD, 0x9A, 0xB5, 0x79, 0x31, 0xF9,
					0x82, 0x6B, 0x74, 0x7D, 0xE1, 0xAC, 0x4F, 0x29, 0xD6, 0x07, 0x08, 0x74, 0xDC, 0xE5, 0x79, 0x10,
					0xE1, 0x98, 0x44, 0x49, 0x9D, 0x8E, 0x42, 0x47, 0x03, 0x39, 0xB1, 0x70, 0xD0, 0x22, 0xB5, 0x01,
					0xAB, 0x88, 0xE9, 0xC2, 0xF4, 0xED, 0x30, 0x2E, 0x47, 0x19, 0xC7, 0x0D, 0xEB, 0xE8, 0x84, 0x24,
					0x03, 0xED, 0x9B, 0xDF, 0xC2, 0x27, 0x30, 0xA6, 0x1A, 0x1B, 0x70, 0xF6, 0x16, 0xC5, 0xF1, 0xB7,
					0x00, 0xCA, 0xCF, 0x78, 0x46, 0x13, 0x7D, 0xC4, 0xB2, 0xD4, 0x69, 0xA8, 0xE1, 0x5A, 0xAB, 0x4F,
					0xAD, 0x86, 0x57, 0x08, 0x40, 0x22, 0xD2, 0x8F, 0x44, 0xD9, 0x07, 0x53, 0x23, 0x12, 0x6B, 0x70,
					0x07, 0xC9, 0x81, 0x93, 0x9F, 0xDF, 0x72, 0x4C, 0xAF, 0x4F, 0xBE, 0x47, 0x50, 0x40, 0x43, 0x1A,
					0x4E, 0xA0, 0x64, 0x43, 0x0B, 0xCB, 0x2C, 0xFA, 0xD7, 0xD0, 0x5B, 0xDB, 0x9F, 0x64, 0xB5, 0xB0,
					0xE0, 0x95, 0x2E, 0xCF, 0x86, 0x79, 0x27, 0x3D, 0x6C, 0x6D, 0xFA, 0x81, 0x60, 0x1F, 0x14, 0x50,
					0x33, 0x16, 0xA1, 0x3D, 0x07, 0x82, 0xC3, 0x1A, 0x3E, 0x6B, 0xDD, 0xED, 0x3D, 0x7B, 0xC4, 0x6B,
					0xC1, 0xFA, 0x9B, 0xEF, 0x0D, 0xFF, 0x83, 0xB7, 0xDE, 0xAF, 0x14, 0x6B, 0x58, 0x2C, 0x46, 0x44,
					0x82, 0x1A, 0x3C, 0x62, 0xED, 0xBA, 0xA6, 0xBE, 0x42, 0x2B, 0xF0, 0x4E, 0x43, 0xED, 0xAF, 0x5F,
					0xD3, 0x78, 0x30, 0x86, 0x15, 0x3D, 0x73, 0x61, 0xA2, 0x03, 0x06, 0x1A, 0x62, 0x98, 0xAB, 0x26,
					0xE1, 0x33, 0x7C, 0xA1, 0xC9, 0xED, 0x06, 0x74, 0x1A, 0x59, 0x05, 0x47, 0x79, 0x88, 0xE7, 0x20,
					0x30, 0x4E, 0xAE, 0x18, 0x9D, 0x7F,
				]).buffer;

				assert.isTrue(abEqual(rawPubArea, expectedRawPubArea), "rawPubArea has correct value");
			});

			it("parses type", function() {
				var type = pubArea.get("type");

				assert.strictEqual(type, "TPM_ALG_RSA");
			});

			it("parses nameAlg", function() {
				var nameAlg = pubArea.get("nameAlg");

				assert.strictEqual(nameAlg, "TPM_ALG_SHA256");
			});

			it("parses objectAttributes", function() {
				var objectAttributes = pubArea.get("objectAttributes");

				assert.instanceOf(objectAttributes, Set);
				assert.strictEqual(objectAttributes.size, 7);
				assert.isTrue(objectAttributes.has("FIXED_TPM"), "objectAttributes has FIXED_TPM");
				assert.isTrue(objectAttributes.has("FIXED_PARENT"), "objectAttributes has FIXED_PARENT");
				assert.isTrue(objectAttributes.has("SENSITIVE_DATA_ORIGIN"), "objectAttributes has SENSITIVE_DATA_ORIGIN");
				assert.isTrue(objectAttributes.has("USER_WITH_AUTH"), "objectAttributes has USER_WITH_AUTH");
				assert.isTrue(objectAttributes.has("NO_DA"), "objectAttributes has NO_DA");
				assert.isTrue(objectAttributes.has("DECRYPT"), "objectAttributes has DECRYPT");
				assert.isTrue(objectAttributes.has("SIGN_ENCRYPT"), "objectAttributes has SIGN_ENCRYPT");

			});

			it("parses authPolicy", function() {
				var authPolicy = pubArea.get("authPolicy");

				assert.instanceOf(authPolicy, ArrayBuffer);
				assert.strictEqual(authPolicy.byteLength, 32);
			});

			it("parses symmetric", function() {
				var symmetric = pubArea.get("symmetric");

				assert.strictEqual(symmetric, "TPM_ALG_NULL");
			});

			it("parses scheme", function() {
				var scheme = pubArea.get("scheme");

				assert.strictEqual(scheme, "TPM_ALG_NULL");
			});

			it("parses keyBits", function() {
				var keyBits = pubArea.get("keyBits");

				assert.strictEqual(keyBits, 2048);
			});

			it("parses exponent", function() {
				var exponent = pubArea.get("exponent");

				assert.isNumber(exponent);
				assert.strictEqual(exponent, 65537);
			});

			it("parses unique", function() {
				var unique = pubArea.get("unique");

				assert.instanceOf(unique, ArrayBuffer);
				assert.strictEqual(unique.byteLength, 256);
			});
		});

		it("parses rawAuthnrData", function() {
			var rawAuthnrData = ret.get("rawAuthnrData");

			assert.instanceOf(rawAuthnrData, ArrayBuffer);
			assert.strictEqual(rawAuthnrData.byteLength, 359);
		});

		it("parses rpIdHash", function() {
			var rpIdHash = ret.get("rpIdHash");

			assert.instanceOf(rpIdHash, ArrayBuffer);
			assert.strictEqual(rpIdHash.byteLength, 32);
		});

		it("parses flags", function() {
			var flags = ret.get("flags");

			assert.instanceOf(flags, Set);
			assert.strictEqual(flags.size, 3);
			assert.isTrue(flags.has("UP"), "flags has UP");
			assert.isTrue(flags.has("UV"), "flags has UV");
			assert.isTrue(flags.has("AT"), "flags has AT");
		});

		it("parses counter", function() {
			var counter = ret.get("counter");

			assert.isNumber(counter);
			assert.strictEqual(counter, 0);
		});

		it("parses aaguid", function() {
			var aaguid = ret.get("aaguid");

			assert.instanceOf(aaguid, ArrayBuffer);
			assert.strictEqual(aaguid.byteLength, 16);
		});

		it("parses credId", function() {
			var credIdLen = ret.get("credIdLen");
			assert.strictEqual(credIdLen, 32);
			var credId = ret.get("credId");
			assert.instanceOf(credId, ArrayBuffer);
			assert.strictEqual(credId.byteLength, 32);
		});

		it("parses credentialPublicKeyCose", function() {
			var credentialPublicKeyCose = ret.get("credentialPublicKeyCose");

			assert.instanceOf(credentialPublicKeyCose, ArrayBuffer);
			assert.strictEqual(credentialPublicKeyCose.byteLength, 272);
		});

		it("parses credentialPublicKeyJwk", function() {
			var credentialPublicKeyJwk = ret.get("credentialPublicKeyJwk");

			assert.isObject(credentialPublicKeyJwk);
			assert.strictEqual(Object.keys(credentialPublicKeyJwk).length, 4);
			assert.strictEqual(credentialPublicKeyJwk.kty, "RSA");
			assert.strictEqual(credentialPublicKeyJwk.alg, "RSASSA-PKCS1-v1_5_w_SHA256");
			assert.strictEqual(credentialPublicKeyJwk.n, "xdpvTZNXveIC9cVYzQoxVtJU8uCtmrV5MfmCa3R94axPKdYHCHTc5XkQ4ZhESZ2OQkcDObFw0CK1AauI6cL07TAuRxnHDevohCQD7ZvfwicwphobcPYWxfG3AMrPeEYTfcSy1Gmo4VqrT62GVwhAItKPRNkHUyMSa3AHyYGTn99yTK9PvkdQQEMaTqBkQwvLLPrX0Fvbn2S1sOCVLs+GeSc9bG36gWAfFFAzFqE9B4LDGj5r3e09e8Rrwfqb7w3/g7ferxRrWCxGRIIaPGLtuqa+QivwTkPtr1/TeDCGFT1zYaIDBhpimKsm4TN8ocntBnQaWQVHeYjnIDBOrhidfw==");
			assert.strictEqual(credentialPublicKeyJwk.e, "AQAB");
		});

		it("parses credentialPublicKeyPem", function() {
			var credentialPublicKeyPem = ret.get("credentialPublicKeyPem");
			assert.isString(credentialPublicKeyPem);
			assert.strictEqual(credentialPublicKeyPem.length, 451);
		});
	});
});