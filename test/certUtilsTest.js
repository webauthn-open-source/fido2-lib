"use strict";

const {
	Certificate,
	CertManager,
	CRL,
	helpers: certHelpers,
} = require("../lib/certUtils");
const { resolveOid } = certHelpers;
const chai = require("chai");
var chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
var assert = chai.assert;
var h = require("fido2-helpers");
const { printHex } = require("../lib/utils");
let abEqual = h.functions.abEqual;

describe("cert utils", function() {
	afterEach(function() {
		CertManager.removeAll();
	});

	describe("Certificate", function() {
		it("is function", function() {
			assert.isFunction(Certificate);
		});

		describe("constructor", function() {
			it("can create new cert", function() {
				var cert = new Certificate(h.certs.yubicoRoot);
				assert.instanceOf(cert, Certificate);
				assert.isObject(cert._cert);
			});

			it("throws if no arg to constructor", function() {
				assert.throws(() => {
					new Certificate();
				}, TypeError, "could not coerce 'certificate' to ArrayBuffer");
			});

			it("throws if constructor arg can't be coerced to ArrayBuffer", function() {
				assert.throws(() => {
					new Certificate(3);
				}, TypeError, "could not coerce 'certificate' to ArrayBuffer");
			});

			it("throws if cert is empty ArrayBuffer", function() {
				assert.throws(() => {
					new Certificate([]);
				}, Error, "cert was empty (0 bytes)");
			});

			it("can create from PEM");
		});


		describe("verify", function() {
			it("can verify root cert", function() {
				var cert = new Certificate(h.certs.yubicoRoot);
				var p = cert.verify();
				assert.instanceOf(p, Promise);
				return p;
			});

			it("throws if root cert isn't found", async function() {
				var cert = new Certificate(h.certs.yubiKeyAttestation);
				var p;
				try {
					p = await cert.verify();
				} catch (err) {
					assert.instanceOf(err, Error);
					assert.strictEqual(err.message, "Please provide issuer certificate as a parameter");
				}
				assert.isUndefined(p);
				return Promise.resolve();
			});

			it("can verify cert with root cert", async function() {
				CertManager.addCert(h.certs.yubicoRoot);
				var cert = new Certificate(h.certs.yubiKeyAttestation);
				await cert.verify();
			});
		});

		describe("getPublicKey", function() {
			it("can extract public key of attestation", function() {
				var cert = new Certificate(h.certs.yubiKeyAttestation);
				var p = cert.getPublicKey();
				assert.instanceOf(p, Promise);
				return p.then((jwk) => {
					assert.isObject(jwk);
					assert.strictEqual(jwk.kty, "EC");
					assert.strictEqual(jwk.crv, "P-256");
					assert.strictEqual(jwk.x, "SzMfdz2BRLmZXL5FhVF-F1g6pHYjaVy-haxILIAZ8sk");
					assert.strictEqual(jwk.y, "uUZ64EWw5m8TGy6jJDyR_aYC4xjz_F2NKnq65yvRQwk");
				});
			});

			it("can extract public key of root", function() {
				var cert = new Certificate(h.certs.yubicoRoot);
				var p = cert.getPublicKey();
				assert.instanceOf(p, Promise);
				return p.then((jwk) => {
					assert.isObject(jwk);
					assert.strictEqual(jwk.kty, "RSA");
					assert.strictEqual(jwk.alg, "RS256");
					assert.strictEqual(jwk.e, "AQAB");
					assert.strictEqual(jwk.n, "v48GLoQVZamomFhDLK1hYrICfj7TPdXkq6SOEyu1Od5sAiGsEgx8vL1JpOTdigI_Wm70_TT-UjEtYUIt7rMaGBqJ10IHzumV8lAPWvigJKnRZwZ5croEngjnqfBHWRX7GkRbTI5MM-RnM9j8uLyGLwnTBz7cGs9G1bs53rniBM-k50IxOt0Xbds28J3m8ExuWcm3lksG88vgSd-GR3FITwGPPciUF7hNCMzGRXBAWzzUW1hAkSoI6v_6k_Z5gzhVZUkQrdsIqj0s5bsJ_r_rLkBAbFI0xjBHdubSl105DVttcCFm8XkslKE18C7xkusZcEEoDaZNql2MH_Il4O1VmQ");
				});
			});
		});

		describe("getSerial", function() {
			it("returns correct serial for attestation", function() {
				var cert = new Certificate(h.certs.yubiKeyAttestation);
				var serial = cert.getSerial();
				assert.strictEqual(serial, "Yubico U2F EE Serial 1432534688");
			});
			it("returns correct serial for root", function() {
				var cert = new Certificate(h.certs.yubicoRoot);
				var serial = cert.getSerial();
				assert.strictEqual(serial, "Yubico U2F Root CA Serial 457200631");
			});
		});

		describe("getIssuer", function() {
			it("returns correct issuer for attestation", function() {
				var cert = new Certificate(h.certs.yubiKeyAttestation);
				var serial = cert.getIssuer();
				assert.strictEqual(serial, "Yubico U2F Root CA Serial 457200631");
			});

			it("returns correct issuer for root", function() {
				var cert = new Certificate(h.certs.yubicoRoot);
				var serial = cert.getIssuer();
				assert.strictEqual(serial, "Yubico U2F Root CA Serial 457200631");
			});
		});

		describe("getVersion", function() {
			it("returns correct version for attestation", function() {
				var cert = new Certificate(h.certs.yubiKeyAttestation);
				var version = cert.getVersion();
				assert.isNumber(version);
				assert.strictEqual(version, 3);
			});

			it("returns correct version for root", function() {
				var cert = new Certificate(h.certs.yubicoRoot);
				var version = cert.getVersion();
				assert.isNumber(version);
				assert.strictEqual(version, 3);
			});
		});

		describe("getExtensions", function() {
			it("returns correct extensions for attestation", function() {
				var cert = new Certificate(h.certs.yubiKeyAttestation);
				var extensions = cert.getExtensions();
				assert.instanceOf(extensions, Map);
				assert.strictEqual(extensions.size, 2);
				assert.isTrue(extensions.has("yubico-device-id"));
				assert.isTrue(extensions.has("fido-u2f-transports"));
				assert.strictEqual(extensions.get("yubico-device-id"), "YubiKey 4/YubiKey 4 Nano");
				var u2fTransports = extensions.get("fido-u2f-transports");
				assert.instanceOf(u2fTransports, Set);
				assert.strictEqual(u2fTransports.size, 1);
				assert.isTrue(u2fTransports.has("usb"));
			});

			it("returns correct extensions for root", function() {
				var cert = new Certificate(h.certs.yubicoRoot);
				var extensions = cert.getExtensions();
				assert.instanceOf(extensions, Map);
				assert.strictEqual(extensions.size, 3);
				assert.isTrue(extensions.has("subject-key-identifier"));
				assert.isTrue(extensions.has("basic-constraints"));
				assert.isTrue(extensions.has("key-usage"));
				assert.instanceOf(extensions.get("subject-key-identifier"), ArrayBuffer);
				assert.isObject(extensions.get("basic-constraints"));
				assert.instanceOf(extensions.get("key-usage"), Set);
				assert.isTrue(extensions.get("key-usage").has("cRLSign"));
				assert.isTrue(extensions.get("key-usage").has("keyCertSign"));
			});

			it("returns FIDO2 extensions", function() {
				var cert = new Certificate(h.certs.feitianFido2);
				var extensions = cert.getExtensions();
				assert.instanceOf(cert.warning, Map);
				assert.strictEqual(cert.warning.size, 0);

				assert.instanceOf(extensions, Map);
				assert.strictEqual(extensions.size, 5);

				// subject-key-identifier
				var subjectKeyId = extensions.get("subject-key-identifier");
				assert.instanceOf(subjectKeyId, ArrayBuffer);
				assert.strictEqual(subjectKeyId.byteLength, 20);

				// authority-key-identifier
				var authorityKeyId = extensions.get("authority-key-identifier");
				assert.instanceOf(authorityKeyId, Map);
				assert.strictEqual(authorityKeyId.size, 1);
				assert.instanceOf(authorityKeyId.get("key-identifier"), ArrayBuffer);

				// basic-constraints
				var basicConstraints = extensions.get("basic-constraints");
				assert.isObject(basicConstraints);
				assert.strictEqual(Object.keys(basicConstraints).length, 1);
				assert.strictEqual(basicConstraints.cA, false);

				// fido-u2f-transports
				var transports = extensions.get("fido-u2f-transports");
				assert.instanceOf(transports, Set);
				assert.strictEqual(transports.size, 1);
				assert.isTrue(transports.has("usb"), "transports has USB");

				// 'fido-u2f-transports' => Set { 'usb' },

				// fido-aaguid
				var aaguid = extensions.get("fido-aaguid");
				assert.instanceOf(aaguid, ArrayBuffer);
				var expectedAaguid = new Uint8Array([0x42, 0x38, 0x32, 0x45, 0x44, 0x37, 0x33, 0x43, 0x38, 0x46, 0x42, 0x34, 0x45, 0x35, 0x41, 0x32]).buffer;
				assert.isTrue(abEqual(aaguid, expectedAaguid), "correct aaguid value");
			});

			it("returns correct extensions for TPM attestation", function() {
				var cert = new Certificate(h.certs.tpmAttestation);
				var extensions = cert.getExtensions();
				assert.instanceOf(extensions, Map);
				assert.strictEqual(extensions.size, 8);
				// key usage
				var keyUsage = extensions.get("key-usage");
				assert.instanceOf(keyUsage, Set);
				assert.strictEqual(keyUsage.size, 1);
				assert.isTrue(keyUsage.has("digitalSignature"), "key-usage has digital signature");
				// basic constraints
				var basicConstraints = extensions.get("basic-constraints");
				assert.isObject(basicConstraints);
				assert.strictEqual(Object.keys(basicConstraints).length, 1);
				assert.strictEqual(basicConstraints.cA, false);
				// certificate policies
				var certPolicies = extensions.get("certificate-policies");
				assert.isArray(certPolicies);
				assert.strictEqual(certPolicies.length, 1);
				var policyQualifiers = certPolicies[0];
				assert.isObject(policyQualifiers);
				assert.strictEqual(policyQualifiers.id, "policy-qualifiers");
				assert.isArray(policyQualifiers.value);
				assert.strictEqual(policyQualifiers.value.length, 1);
				var policyQualifier = policyQualifiers.value[0];
				assert.isObject(policyQualifier);
				assert.strictEqual(policyQualifier.id, "policy-qualifier");
				assert.isArray(policyQualifier.value);
				assert.strictEqual(policyQualifier.value.length, 1);
				assert.strictEqual(policyQualifier.value[0], "TCPA  Trusted  Platform  Identity");
				// extended key usage
				var extKeyUsage = extensions.get("ext-key-usage");
				assert.isArray(extKeyUsage);
				assert.strictEqual(extKeyUsage.length, 1);
				assert.strictEqual(extKeyUsage[0], "tcg-kp-aik-certificate");
				// alternate name
				var subjAltNames = extensions.get("subject-alt-name");
				assert.isArray(subjAltNames);
				assert.strictEqual(subjAltNames.length, 1);
				var subjAltName = subjAltNames[0];
				assert.isObject(subjAltName);
				assert.strictEqual(Object.keys(subjAltName).length, 1);
				var generalNames = subjAltName.directoryName;
				assert.instanceOf(generalNames, Map);
				assert.strictEqual(generalNames.size, 3);
				assert.strictEqual(generalNames.get("tcg-at-tpm-version"), "id:13");
				assert.strictEqual(generalNames.get("tcg-at-tpm-model"), "NPCT6xx");
				assert.strictEqual(generalNames.get("tcg-at-tpm-manufacturer"), "id:4E544300");
				// authority key identifier
				var authKeyId = extensions.get("authority-key-identifier");
				assert.instanceOf(authKeyId, Map);
				assert.strictEqual(authKeyId.size, 1);
				authKeyId = authKeyId.get("key-identifier");
				assert.instanceOf(authKeyId, ArrayBuffer);
				var expectedAuthKeyId = new Uint8Array([
					0xC2, 0x12, 0xA9, 0x5B, 0xCE, 0xFA, 0x56, 0xF8, 0xC0, 0xC1, 0x6F, 0xB1, 0x5B, 0xDD, 0x03, 0x34,
					0x47, 0xB3, 0x7A, 0xA3,
				]).buffer;
				assert.isTrue(abEqual(authKeyId, expectedAuthKeyId), "got expected authority key identifier");
				// subject key identifier
				var subjectKeyId = extensions.get("subject-key-identifier");
				assert.instanceOf(subjectKeyId, ArrayBuffer);
				var expectedSubjectKeyId = new Uint8Array([
					0xAF, 0xE2, 0x45, 0xD3, 0x48, 0x0F, 0x22, 0xDC, 0xD5, 0x0C, 0xD2, 0xAE, 0x7B, 0x96, 0xB5, 0xA9,
					0x33, 0xCA, 0x7F, 0xE1,
				]).buffer;
				assert.isTrue(abEqual(subjectKeyId, expectedSubjectKeyId), "got expected authority key identifier");
				// info access
				var infoAccess = extensions.get("authority-info-access");
				assert.instanceOf(infoAccess, Map);
				assert.strictEqual(infoAccess.size, 1);
				var certAuthIss = infoAccess.get("cert-authority-issuers");
				assert.isObject(certAuthIss);
				assert.strictEqual(Object.keys(certAuthIss).length, 1);
				assert.strictEqual(certAuthIss.uniformResourceIdentifier, "https://azcsprodncuaikpublish.blob.core.windows.net/ncu-ntc-keyid-1591d4b6eaf98d0104864b6903a48dd0026077d3/3b918ae4-07e1-4059-9491-0ad248190818.cer");
			});
		});

		describe("getSubject", function() {
			it("returns correct extensions for attestation", function() {
				var cert = new Certificate(h.certs.yubiKeyAttestation);
				var subject = cert.getSubject();
				assert.instanceOf(subject, Map);
				assert.strictEqual(subject.size, 1);
				assert.strictEqual(subject.get("common-name"), "Yubico U2F EE Serial 1432534688");

			});

			it("returns correct extensions for root", function() {
				var cert = new Certificate(h.certs.yubicoRoot);
				var subject = cert.getSubject();
				assert.instanceOf(subject, Map);
				assert.strictEqual(subject.size, 1);
				assert.strictEqual(subject.get("common-name"), "Yubico U2F Root CA Serial 457200631");
			});

			it("returns correct values for Feitian FIDO2", function() {
				var cert = new Certificate(h.certs.feitianFido2);
				var subject = cert.getSubject();
				assert.instanceOf(subject, Map);
				assert.strictEqual(subject.size, 4);
				assert.strictEqual(subject.get("country-name"), "CN");
				assert.strictEqual(subject.get("organization-name"), "Feitian Technologies");
				assert.strictEqual(subject.get("organizational-unit-name"), "Authenticator Attestation");
				assert.strictEqual(subject.get("common-name"), "FT BioPass FIDO2 USB");
			});
		});
	});

	describe("helpers", function() {
		describe("resolveOid", function() {
			it("decodes U2F USB transport type", function() {
				var ret = resolveOid(
					"1.3.6.1.4.1.45724.2.1.1",
					new Uint8Array([0x03, 0x02, 0x05, 0x20]).buffer
				);
				assert.isObject(ret);
				assert.strictEqual(ret.id, "fido-u2f-transports");
				assert.instanceOf(ret.value, Set);
				assert.strictEqual(ret.value.size, 1);
				assert.isTrue(ret.value.has("usb"));
			});

			it("decodes U2F Bluetooth Classic transport type", function() {
				var ret = resolveOid(
					"1.3.6.1.4.1.45724.2.1.1",
					new Uint8Array([0x03, 0x02, 0x07, 0x80]).buffer
				);
				assert.isObject(ret);
				assert.strictEqual(ret.id, "fido-u2f-transports");
				assert.instanceOf(ret.value, Set);
				assert.strictEqual(ret.value.size, 1);
				assert.isTrue(ret.value.has("bluetooth-classic"));
			});

			it("decodes U2F USB+NFC transport type", function() {
				var ret = resolveOid(
					"1.3.6.1.4.1.45724.2.1.1",
					new Uint8Array([0x03, 0x02, 0x04, 0x30]).buffer
				);
				assert.isObject(ret);
				assert.strictEqual(ret.id, "fido-u2f-transports");
				assert.instanceOf(ret.value, Set);
				assert.strictEqual(ret.value.size, 2);
				assert.isTrue(ret.value.has("usb"));
				assert.isTrue(ret.value.has("nfc"));
			});

			it("decodes U2F USB Internal transport type", function() {
				var ret = resolveOid(
					"1.3.6.1.4.1.45724.2.1.1",
					new Uint8Array([0x03, 0x02, 0x03, 0x08]).buffer
				);
				assert.isObject(ret);
				assert.strictEqual(ret.id, "fido-u2f-transports");
				assert.instanceOf(ret.value, Set);
				assert.strictEqual(ret.value.size, 1);
				assert.isTrue(ret.value.has("usb-internal"));
			});

			it("decodes all transport types", function() {
				var ret = resolveOid(
					"1.3.6.1.4.1.45724.2.1.1",
					new Uint8Array([0x03, 0x02, 0x03, 0xF8]).buffer
				);
				assert.isObject(ret);
				assert.strictEqual(ret.id, "fido-u2f-transports");
				assert.instanceOf(ret.value, Set);
				assert.strictEqual(ret.value.size, 5);
				assert.isTrue(ret.value.has("bluetooth-classic"));
				assert.isTrue(ret.value.has("bluetooth-low-energy"));
				assert.isTrue(ret.value.has("usb"));
				assert.isTrue(ret.value.has("nfc"));
				assert.isTrue(ret.value.has("usb-internal"));
			});

			it("decodes YubiKey Nano device type");
		});
	});

	describe("CRL", function() {
		it("can create mdsRootCrl", function() {
			var ret = new CRL(h.mds.mdsRootCrl);
			assert.isObject(ret);
			assert.isObject(ret._crl);
		});

		it("can create ca1Crl", function() {
			var ret = new CRL(h.mds.ca1Crl);
			assert.isObject(ret);
			assert.isObject(ret._crl);
		});
	});

	describe("CertManager", function() {
		it("is function", function() {
			assert.isFunction(CertManager);
		});

		it("has static methods", function() {
			assert.isFunction(CertManager.addCert);
			assert.isFunction(CertManager.removeAll);
		});

		describe("addCert", function() {
			it("throws if no cert", function() {
				assert.throws(() => {
					CertManager.addCert();
				}, TypeError, "could not coerce 'certificate' to ArrayBuffer");
			});

			it("can add cert", function() {
				CertManager.addCert(h.certs.yubicoRoot);
			});
		});

		describe("getCerts", function() {
			it("returns empty Map if no certs added", function() {
				var ret = CertManager.getCerts();
				assert.instanceOf(ret, Map);
				assert.strictEqual(ret.size, 0);
			});

			it("returns Map with added cert", function() {
				CertManager.addCert(h.certs.yubicoRoot);
				var ret = CertManager.getCerts();
				assert.instanceOf(ret, Map);
				assert.strictEqual(ret.size, 1);
				assert.isTrue(ret.has("Yubico U2F Root CA Serial 457200631"));
			});
		});

		describe("removeAll", function() {
			it("can clear all"); // if this didn't work, afterEach would fail...
		});

		describe("verifyCertChain", function() {
			it("rejects on empty arguments", function() {
				return assert.isRejected(CertManager.verifyCertChain(), Error, "expected 'certs' to be non-empty Array, got: undefined");
			});

			it("works for MDS2", function() {
				var certs = [
					new Certificate(h.mds.mdsSigningCert),
					new Certificate(h.mds.mdsIntermediateCert),
				];
				var trustedRoots = [
					new Certificate(h.mds.mdsRootCert),
				];

				var certRevocationLists = [
					new CRL(h.mds.mdsRootCrl),
					new CRL(h.mds.ca1Crl),
				];

				var ret = CertManager.verifyCertChain(certs, trustedRoots, certRevocationLists);
				assert.instanceOf(ret, Promise);
				return ret;
			});

			it("works for TPM");

			it("will create certs from input arrays", function() {
				var certs = [
					h.mds.mdsSigningCert,
					h.mds.mdsIntermediateCert,
				];
				var trustedRoots = [
					h.mds.mdsRootCert,
				];

				var certRevocationLists = [
					h.mds.mdsRootCrl,
					h.mds.ca1Crl,
				];

				var ret = CertManager.verifyCertChain(certs, trustedRoots, certRevocationLists);
				assert.instanceOf(ret, Promise);
				return ret;
			});

			it("rejects on bad value in certs");
			it("rejects on bad value in roots");
			it("rejects on bad value in CRLs");
		});
	});
});
