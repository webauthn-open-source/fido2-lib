// Testing lib
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";

// Helpers

import { arrayBufferEquals, Certificate, CertManager, CRL, helpers as certHelpers } from "../lib/main.js";
import * as h from "./helpers/fido2-helpers.js";

chai.use(chaiAsPromised.default);
const assert = chai.assert;

const { resolveOid } = certHelpers;

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
				const cert = new Certificate(h.certs.yubicoRoot);
				assert.instanceOf(cert, Certificate);
				assert.isObject(cert._cert);
			});

			it("can decode base64 encoded cert", function() {
				const cert = new Certificate(h.certs.truUCert);
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
				const cert = new Certificate(h.certs.yubicoRoot);
				const p = cert.verify();
				assert.instanceOf(p, Promise);
				return p;
			});

			it("throws if root cert isn't found", async function() {
				const cert = new Certificate(h.certs.yubiKeyAttestation);
				let p;
				try {
					p = await cert.verify();
				} catch (err) {
					assert.instanceOf(err, Error);
					assert.strictEqual(
						err.message,
						"Please provide issuer certificate as a parameter",
					);
				}
				assert.isUndefined(p);
				return Promise.resolve();
			});

			it("can verify cert with root cert", async function() {
				CertManager.addCert(h.certs.yubicoRoot);
				const cert = new Certificate(h.certs.yubiKeyAttestation);
				await cert.verify();
			});
		});

		describe("getPublicKey", function() {
			it("can extract public key of attestation", async function() {
				const cert = new Certificate(h.certs.yubiKeyAttestation);
				const jwk = await cert.getPublicKeyJwk();
				assert.isObject(jwk);
				assert.strictEqual(jwk.kty, "EC");
				assert.strictEqual(jwk.crv, "P-256");
				assert.strictEqual(
					jwk.x,
					"SzMfdz2BRLmZXL5FhVF-F1g6pHYjaVy-haxILIAZ8sk",
				);
				assert.strictEqual(
					jwk.y,
					"uUZ64EWw5m8TGy6jJDyR_aYC4xjz_F2NKnq65yvRQwk",
				);
			});

			it("can extract public key of root", async function() {
				const cert = new Certificate(h.certs.yubicoRoot);
				const publicKeyJwk = await cert.getPublicKeyJwk();
				assert.isObject(publicKeyJwk);
				assert.strictEqual(publicKeyJwk.kty, "RSA");
				assert.strictEqual(publicKeyJwk.alg, "RS256");
				assert.strictEqual(publicKeyJwk.e, "AQAB");
				assert.strictEqual(
					publicKeyJwk.n,
					"v48GLoQVZamomFhDLK1hYrICfj7TPdXkq6SOEyu1Od5sAiGsEgx8vL1JpOTdigI_Wm70_TT-UjEtYUIt7rMaGBqJ10IHzumV8lAPWvigJKnRZwZ5croEngjnqfBHWRX7GkRbTI5MM-RnM9j8uLyGLwnTBz7cGs9G1bs53rniBM-k50IxOt0Xbds28J3m8ExuWcm3lksG88vgSd-GR3FITwGPPciUF7hNCMzGRXBAWzzUW1hAkSoI6v_6k_Z5gzhVZUkQrdsIqj0s5bsJ_r_rLkBAbFI0xjBHdubSl105DVttcCFm8XkslKE18C7xkusZcEEoDaZNql2MH_Il4O1VmQ",
				);
			});
		});

		describe("getSerial", function() {
			it("returns correct serial for attestation", function() {
				const cert = new Certificate(h.certs.yubiKeyAttestation);
				const serial = cert.getSerial("v2");
				assert.strictEqual(serial, "1432534688");
			});
			it("returns correct serial for root", function() {
				const cert = new Certificate(h.certs.yubicoRoot);
				const serial = cert.getSerial("v2");
				assert.strictEqual(
					serial,
					"457200631",
				);
			});
		});

		describe("getIssuer", function() {
			it("returns correct issuer for attestation", function() {
				const cert = new Certificate(h.certs.yubiKeyAttestation);
				const serial = cert.getIssuer();
				assert.strictEqual(
					serial,
					"Yubico U2F Root CA Serial 457200631",
				);
			});

			it("returns correct issuer for root", function() {
				const cert = new Certificate(h.certs.yubicoRoot);
				const serial = cert.getIssuer();
				assert.strictEqual(
					serial,
					"Yubico U2F Root CA Serial 457200631",
				);
			});
		});

		describe("getVersion", function() {
			it("returns correct version for attestation", function() {
				const cert = new Certificate(h.certs.yubiKeyAttestation);
				const version = cert.getVersion();
				assert.isNumber(version);
				assert.strictEqual(version, 3);
			});

			it("returns correct version for root", function() {
				const cert = new Certificate(h.certs.yubicoRoot);
				const version = cert.getVersion();
				assert.isNumber(version);
				assert.strictEqual(version, 3);
			});
		});

		describe("getExtensions", function() {
			it("returns correct extensions for attestation", function() {
				const cert = new Certificate(h.certs.yubiKeyAttestation);
				const extensions = cert.getExtensions();
				assert.instanceOf(extensions, Map);
				assert.strictEqual(extensions.size, 2);
				assert.isTrue(extensions.has("yubico-device-id"));
				assert.isTrue(extensions.has("fido-u2f-transports"));
				assert.strictEqual(
					extensions.get("yubico-device-id"),
					"YubiKey 4/YubiKey 4 Nano",
				);
				const u2fTransports = extensions.get("fido-u2f-transports");
				assert.instanceOf(u2fTransports, Set);
				assert.strictEqual(u2fTransports.size, 1);
				assert.isTrue(u2fTransports.has("usb"));
			});

			it("does not throw for non-critical extensions, when unknown extension types are included", function() {
				const cert = new Certificate(h.certs.certificateWithIntegerExtension);
				const extensions = cert.getExtensions();
			});

			it("returns correct extensions for root", function() {
				const cert = new Certificate(h.certs.yubicoRoot);
				const extensions = cert.getExtensions();
				assert.instanceOf(extensions, Map);
				assert.strictEqual(extensions.size, 3);
				assert.isTrue(extensions.has("subject-key-identifier"));
				assert.isTrue(extensions.has("basic-constraints"));
				assert.isTrue(extensions.has("key-usage"));
				assert.instanceOf(
					extensions.get("subject-key-identifier"),
					ArrayBuffer,
				);
				assert.isObject(extensions.get("basic-constraints"));
				assert.instanceOf(extensions.get("key-usage"), Set);
				assert.isTrue(extensions.get("key-usage").has("cRLSign"));
				assert.isTrue(extensions.get("key-usage").has("keyCertSign"));
			});

			it("returns FIDO2 extensions", function() {
				const cert = new Certificate(h.certs.feitianFido2);
				const extensions = cert.getExtensions();
				assert.instanceOf(cert.warning, Map);
				assert.strictEqual(cert.warning.size, 0);

				assert.instanceOf(extensions, Map);
				assert.strictEqual(extensions.size, 5);

				// subject-key-identifier
				const subjectKeyId = extensions.get("subject-key-identifier");
				assert.instanceOf(subjectKeyId, ArrayBuffer);
				assert.strictEqual(subjectKeyId.byteLength, 20);

				// authority-key-identifier
				const authorityKeyId = extensions.get(
					"authority-key-identifier",
				);
				assert.instanceOf(authorityKeyId, Map);
				assert.strictEqual(authorityKeyId.size, 1);
				assert.instanceOf(
					authorityKeyId.get("key-identifier"),
					ArrayBuffer,
				);

				// basic-constraints
				const basicConstraints = extensions.get("basic-constraints");
				assert.isObject(basicConstraints);
				assert.strictEqual(Object.keys(basicConstraints).length, 1);
				assert.strictEqual(basicConstraints.cA, false);

				// fido-u2f-transports
				const transports = extensions.get("fido-u2f-transports");
				assert.instanceOf(transports, Set);
				assert.strictEqual(transports.size, 1);
				assert.isTrue(transports.has("usb"), "transports has USB");

				// 'fido-u2f-transports' => Set { 'usb' },

				// fido-aaguid
				const aaguid = extensions.get("fido-aaguid");
				assert.instanceOf(aaguid, ArrayBuffer);
				let expectedAaguid = new Uint8Array([0x42, 0x38, 0x32, 0x45, 0x44, 0x37, 0x33, 0x43, 0x38, 0x46, 0x42, 0x34, 0x45, 0x35, 0x41, 0x32]).buffer;
				assert.isTrue(
					arrayBufferEquals(aaguid, expectedAaguid),
					"correct aaguid value",
				);
			});

			it("returns correct extensions for TPM attestation", function() {
				const cert = new Certificate(h.certs.tpmAttestation);
				const extensions = cert.getExtensions();
				assert.instanceOf(extensions, Map);
				assert.strictEqual(extensions.size, 8);
				// key usage
				const keyUsage = extensions.get("key-usage");
				assert.instanceOf(keyUsage, Set);
				assert.strictEqual(keyUsage.size, 1);
				assert.isTrue(
					keyUsage.has("digitalSignature"),
					"key-usage has digital signature",
				);
				// basic constraints
				const basicConstraints = extensions.get("basic-constraints");
				assert.isObject(basicConstraints);
				assert.strictEqual(Object.keys(basicConstraints).length, 1);
				assert.strictEqual(basicConstraints.cA, false);
				// certificate policies
				const certPolicies = extensions.get("certificate-policies");
				assert.isArray(certPolicies);
				assert.strictEqual(certPolicies.length, 1);
				const policyQualifiers = certPolicies[0];
				assert.isObject(policyQualifiers);
				assert.strictEqual(policyQualifiers.id, "policy-qualifiers");
				assert.isArray(policyQualifiers.value);
				assert.strictEqual(policyQualifiers.value.length, 1);
				const policyQualifier = policyQualifiers.value[0];
				assert.isObject(policyQualifier);
				assert.strictEqual(policyQualifier.id, "policy-qualifier");
				assert.isArray(policyQualifier.value);
				assert.strictEqual(policyQualifier.value.length, 1);
				assert.strictEqual(
					policyQualifier.value[0],
					"TCPA  Trusted  Platform  Identity",
				);
				// extended key usage
				const extKeyUsage = extensions.get("ext-key-usage");
				assert.isArray(extKeyUsage);
				assert.strictEqual(extKeyUsage.length, 1);
				assert.strictEqual(extKeyUsage[0], "tcg-kp-aik-certificate");
				// alternate name
				const subjAltNames = extensions.get("subject-alt-name");
				assert.isArray(subjAltNames);
				assert.strictEqual(subjAltNames.length, 1);
				const subjAltName = subjAltNames[0];
				assert.isObject(subjAltName);
				assert.strictEqual(Object.keys(subjAltName).length, 1);
				const generalNames = subjAltName.directoryName;
				assert.instanceOf(generalNames, Map);
				assert.strictEqual(generalNames.size, 3);
				assert.strictEqual(
					generalNames.get("tcg-at-tpm-version"),
					"id:13",
				);
				assert.strictEqual(
					generalNames.get("tcg-at-tpm-model"),
					"NPCT6xx",
				);
				assert.strictEqual(
					generalNames.get("tcg-at-tpm-manufacturer"),
					"id:4E544300",
				);
				// authority key identifier
				let authKeyId = extensions.get("authority-key-identifier");
				assert.instanceOf(authKeyId, Map);
				assert.strictEqual(authKeyId.size, 1);
				authKeyId = authKeyId.get("key-identifier");
				assert.instanceOf(authKeyId, ArrayBuffer);
				let expectedAuthKeyId = new Uint8Array([
					0xC2, 0x12, 0xA9, 0x5B, 0xCE, 0xFA, 0x56, 0xF8, 0xC0, 0xC1, 0x6F, 0xB1, 0x5B, 0xDD, 0x03, 0x34,
					0x47, 0xB3, 0x7A, 0xA3,
				]).buffer;
				assert.isTrue(
					arrayBufferEquals(authKeyId, expectedAuthKeyId),
					"got expected authority key identifier",
				);
				// subject key identifier
				const subjectKeyId = extensions.get("subject-key-identifier");
				assert.instanceOf(subjectKeyId, ArrayBuffer);
				let expectedSubjectKeyId = new Uint8Array([
					0xAF, 0xE2, 0x45, 0xD3, 0x48, 0x0F, 0x22, 0xDC, 0xD5, 0x0C, 0xD2, 0xAE, 0x7B, 0x96, 0xB5, 0xA9,
					0x33, 0xCA, 0x7F, 0xE1,
				]).buffer;
				assert.isTrue(
					arrayBufferEquals(subjectKeyId, expectedSubjectKeyId),
					"got expected authority key identifier",
				);
				// info access
				const infoAccess = extensions.get("authority-info-access");
				assert.instanceOf(infoAccess, Map);
				assert.strictEqual(infoAccess.size, 1);
				const certAuthIss = infoAccess.get("cert-authority-issuers");
				assert.isObject(certAuthIss);
				assert.strictEqual(Object.keys(certAuthIss).length, 1);
				assert.strictEqual(
					certAuthIss.uniformResourceIdentifier,
					"https://azcsprodncuaikpublish.blob.core.windows.net/ncu-ntc-keyid-1591d4b6eaf98d0104864b6903a48dd0026077d3/3b918ae4-07e1-4059-9491-0ad248190818.cer",
				);
			});
		});

		describe("getSubject", function() {
			it("returns correct extensions for attestation", function() {
				const cert = new Certificate(h.certs.yubiKeyAttestation);
				const subject = cert.getSubject();
				assert.instanceOf(subject, Map);
				assert.strictEqual(subject.size, 1);
				assert.strictEqual(
					subject.get("common-name"),
					"Yubico U2F EE Serial 1432534688",
				);
			});

			it("returns correct extensions for root", function() {
				const cert = new Certificate(h.certs.yubicoRoot);
				const subject = cert.getSubject();
				assert.instanceOf(subject, Map);
				assert.strictEqual(subject.size, 1);
				assert.strictEqual(
					subject.get("common-name"),
					"Yubico U2F Root CA Serial 457200631",
				);
			});

			it("returns correct values for Feitian FIDO2", function() {
				const cert = new Certificate(h.certs.feitianFido2);
				const subject = cert.getSubject();
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
				const ret = resolveOid(
					"1.3.6.1.4.1.45724.2.1.1",
					0x20
				);
				assert.isObject(ret);
				assert.strictEqual(ret.id, "fido-u2f-transports");
				assert.instanceOf(ret.value, Set);
				assert.strictEqual(ret.value.size, 1);
				assert.isTrue(ret.value.has("usb"));
			});

			it("decodes U2F Bluetooth Classic transport type", function() {
				const ret = resolveOid(
					"1.3.6.1.4.1.45724.2.1.1",
					0x80
				);
				assert.isObject(ret);
				assert.strictEqual(ret.id, "fido-u2f-transports");
				assert.instanceOf(ret.value, Set);
				assert.strictEqual(ret.value.size, 1);
				assert.isTrue(ret.value.has("bluetooth-classic"));
			});

			it("decodes U2F USB+NFC transport type", function() {
				const ret = resolveOid(
					"1.3.6.1.4.1.45724.2.1.1",
					0x30
				);
				assert.isObject(ret);
				assert.strictEqual(ret.id, "fido-u2f-transports");
				assert.instanceOf(ret.value, Set);
				assert.strictEqual(ret.value.size, 2);
				assert.isTrue(ret.value.has("usb"));
				assert.isTrue(ret.value.has("nfc"));
			});

			it("decodes U2F USB Internal transport type", function() {
				const ret = resolveOid(
					"1.3.6.1.4.1.45724.2.1.1",
					0x08
				);
				assert.isObject(ret);
				assert.strictEqual(ret.id, "fido-u2f-transports");
				assert.instanceOf(ret.value, Set);
				assert.strictEqual(ret.value.size, 1);
				assert.isTrue(ret.value.has("usb-internal"));
			});

			it("decodes all transport types", function() {
				const ret = resolveOid(
					"1.3.6.1.4.1.45724.2.1.1",
					0xF8
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
			const ret = new CRL(h.mds.mdsRootCrl);
			assert.isObject(ret);
			assert.isObject(ret._crl);
		});

		it("can create ca1Crl", function() {
			const ret = new CRL(h.mds.ca1Crl);
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
				assert.throws(
					() => {
						CertManager.addCert();
					},
					TypeError,
					"could not coerce 'certificate' to ArrayBuffer",
				);
			});

			it("can add cert", function() {
				CertManager.addCert(h.certs.yubicoRoot);
			});
		});

		describe("getCerts", function() {
			it("returns empty Map if no certs added", function() {
				const ret = CertManager.getCerts();
				assert.instanceOf(ret, Map);
				assert.strictEqual(ret.size, 0);
			});

			it("returns Map with added cert", function() {
				CertManager.addCert(h.certs.yubicoRoot);
				const ret = CertManager.getCerts();
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
				return assert.isRejected(
					CertManager.verifyCertChain(),
					Error,
					"expected 'certs' to be non-empty Array, got: undefined",
				);
			});

			// Deprecated, TODO: Something similar for MDS3?
			it.skip("works for MDS2", function() {
				const certs = [
					new Certificate(h.mds.mdsSigningCert),
					new Certificate(h.mds.mdsIntermediateCert),
				];
				const trustedRoots = [
					new Certificate(h.mds.mdsRootCert),
				];

				const certRevocationLists = [
					new CRL(h.mds.mdsRootCrl),
					new CRL(h.mds.ca1Crl),
				];

				const ret = CertManager.verifyCertChain(
					certs,
					trustedRoots,
					certRevocationLists,
				);
				assert.instanceOf(ret, Promise);
				return ret;
			});

			it("works for TPM");

			// ToDo: Needs to be updated to use valid certs and crls, currenctly skipped
			it.skip("will create certs from input arrays", function() {
				const certs = [
					h.mds.mdsSigningCert,
					h.mds.mdsIntermediateCert,
				];
				const trustedRoots = [
					h.mds.mdsRootCert,
				];

				const certRevocationLists = [
					h.mds.mdsRootCrl,
					h.mds.ca1Crl,
				];

				const ret = CertManager.verifyCertChain(
					certs,
					trustedRoots,
					certRevocationLists,
				);
				assert.instanceOf(ret, Promise);
				return ret;
			});

			it("rejects on bad value in certs");
			it("rejects on bad value in roots");
			it("rejects on bad value in CRLs");
		});
	});
});
