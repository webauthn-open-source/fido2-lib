// Testing lib
import { assertEquals, assertRejects, assertThrows } from "./common/deps.js";

// Helpers
import { ToolBoxRegistration } from "../../lib/deno/toolbox.js";
ToolBoxRegistration.registerAsGlobal();

import { abEqual } from "../../lib/common/utils.js";
import * as h from "../helpers/fido2-helpers.js";

// Test subject
import { Fido2Lib } from "../../lib/deno/webauthn.js";

import {
  Certificate,
  CertManager,
  CRL,
  helpers as certHelpers,
} from "../../lib/common/certUtils.js";

Deno.test("Certificate is function", async () => {
  assertEquals(typeof Certificate, "function");
});
Deno.test("Certificate constructor can create new cert", async () => {
  var cert = new Certificate(h.certs.yubicoRoot);
  assertEquals(cert instanceof Certificate, true);
  assertEquals(typeof cert._cert, "object");
});
Deno.test("Certificate constructor throws if no arg to constructor", function () {
  assertThrows(
    () => {
      new Certificate();
    },
    TypeError,
    "could not coerce 'certificate' to ArrayBuffer",
  );
});
Deno.test("Certificate constructor throws if constructor arg can't be coerced to ArrayBuffer", function () {
  assertThrows(
    () => {
      new Certificate(3);
    },
    TypeError,
    "could not coerce 'certificate' to ArrayBuffer",
  );
});

Deno.test("Certificate constructor throws if cert is empty ArrayBuffer", function () {
  assertThrows(
    () => {
      new Certificate([]);
    },
    Error,
    "cert was empty (0 bytes)",
  );
});

Deno.test("Certificate verify can verify root cert", function () {
  var cert = new Certificate(h.certs.yubicoRoot);
  var p = cert.verify();
  assertEquals(p instanceof Promise, true);
  return p;
});

Deno.test("Certificate verify throws if root cert isn't found", async function () {
  var cert = new Certificate(h.certs.yubiKeyAttestation);
  var p;
  try {
    p = await cert.verify();
  } catch (err) {
    assertEquals(err instanceof Error, true);
    assertEquals(
      err.message,
      "Please provide issuer certificate as a parameter",
    );
  }
  assertEquals(typeof p, "undefined");
  return Promise.resolve();
});

Deno.test("Certificate verify can verify cert with root cert", async function () {
  CertManager.addCert(h.certs.yubicoRoot);
  var cert = new Certificate(h.certs.yubiKeyAttestation);
  await cert.verify();
});

Deno.test("Certificate getPublicKey can extract public key of attestation", function () {
  var cert = new Certificate(h.certs.yubiKeyAttestation);
  var p = cert.getPublicKey();
  assertEquals(p instanceof Promise, true);
  return p.then((jwk) => {
    assertEquals(typeof jwk, "object");
    assertEquals(jwk.kty, "EC");
    assertEquals(jwk.crv, "P-256");
    assertEquals(jwk.x, "SzMfdz2BRLmZXL5FhVF-F1g6pHYjaVy-haxILIAZ8sk");
    assertEquals(jwk.y, "uUZ64EWw5m8TGy6jJDyR_aYC4xjz_F2NKnq65yvRQwk");
  });
});

Deno.test("Certificate getPublicKey can extract public key of root", function () {
  var cert = new Certificate(h.certs.yubicoRoot);
  var p = cert.getPublicKey();
  assertEquals(p instanceof Promise, true);
  return p.then((jwk) => {
    assertEquals(typeof jwk, "object");
    assertEquals(jwk.kty, "RSA");
    assertEquals(jwk.alg, "RS256");
    assertEquals(jwk.e, "AQAB");
    assertEquals(
      jwk.n,
      "v48GLoQVZamomFhDLK1hYrICfj7TPdXkq6SOEyu1Od5sAiGsEgx8vL1JpOTdigI_Wm70_TT-UjEtYUIt7rMaGBqJ10IHzumV8lAPWvigJKnRZwZ5croEngjnqfBHWRX7GkRbTI5MM-RnM9j8uLyGLwnTBz7cGs9G1bs53rniBM-k50IxOt0Xbds28J3m8ExuWcm3lksG88vgSd-GR3FITwGPPciUF7hNCMzGRXBAWzzUW1hAkSoI6v_6k_Z5gzhVZUkQrdsIqj0s5bsJ_r_rLkBAbFI0xjBHdubSl105DVttcCFm8XkslKE18C7xkusZcEEoDaZNql2MH_Il4O1VmQ",
    );
  });
});

Deno.test("Certificate getSerial returns correct serial for attestation", function () {
  var cert = new Certificate(h.certs.yubiKeyAttestation);
  var serial = cert.getSerial();
  assertEquals(serial, "Yubico U2F EE Serial 1432534688");
});

Deno.test("Certificate getSerial returns correct serial for root", function () {
  var cert = new Certificate(h.certs.yubicoRoot);
  var serial = cert.getSerial();
  assertEquals(serial, "Yubico U2F Root CA Serial 457200631");
});

Deno.test("Certificate getIssuer returns correct issuer for attestation", function () {
  var cert = new Certificate(h.certs.yubiKeyAttestation);
  var serial = cert.getIssuer();
  assertEquals(serial, "Yubico U2F Root CA Serial 457200631");
});

Deno.test("Certificate getIssuer returns correct issuer for root", function () {
  var cert = new Certificate(h.certs.yubicoRoot);
  var serial = cert.getIssuer();
  assertEquals(serial, "Yubico U2F Root CA Serial 457200631");
});
Deno.test("Certificate getVersion returns correct version for attestation", function () {
  var cert = new Certificate(h.certs.yubiKeyAttestation);
  var version = cert.getVersion();
  assertEquals(version, 3);
});

Deno.test("Certificate getVersion returns correct version for root", function () {
  var cert = new Certificate(h.certs.yubicoRoot);
  var version = cert.getVersion();
  assertEquals(version, 3);
});

Deno.test("Certificate getExtensions returns correct extensions for attestation", function () {
  var cert = new Certificate(h.certs.yubiKeyAttestation);
  var extensions = cert.getExtensions();
  assertEquals(extensions instanceof Map, true);
  assertEquals(extensions.size, 2);
  assertEquals(extensions.has("yubico-device-id"), true);
  assertEquals(extensions.has("fido-u2f-transports"), true);
  assertEquals(extensions.get("yubico-device-id"), "YubiKey 4/YubiKey 4 Nano");
  var u2fTransports = extensions.get("fido-u2f-transports");
  assertEquals(u2fTransports instanceof Set, true);
  assertEquals(u2fTransports.size, 1);
  assertEquals(u2fTransports.has("usb"), true);
});

Deno.test("Certificate getExtensions returns correct extensions for root", function () {
  var cert = new Certificate(h.certs.yubicoRoot);
  var extensions = cert.getExtensions();
  assertEquals(true, extensions instanceof Map);
  assertEquals(extensions.size, 3);
  assertEquals(true, extensions.has("subject-key-identifier"));
  assertEquals(true, extensions.has("basic-constraints"));
  assertEquals(true, extensions.has("key-usage"));
  assertEquals(
    extensions.get("subject-key-identifier") instanceof ArrayBuffer,
    true,
  );
  assertEquals(typeof extensions.get("basic-constraints"), "object");
  assertEquals(true, extensions.get("key-usage") instanceof Set);
  assertEquals(true, extensions.get("key-usage").has("cRLSign"));
  assertEquals(true, extensions.get("key-usage").has("keyCertSign"));
});

Deno.test("Certificate getExtensions returns FIDO2 extensions", function () {
  var cert = new Certificate(h.certs.feitianFido2);
  var extensions = cert.getExtensions();
  assertEquals(true, cert.warning instanceof Map);
  assertEquals(cert.warning.size, 0);

  assertEquals(true, extensions instanceof Map);
  assertEquals(extensions.size, 5);

  // subject-key-identifier
  var subjectKeyId = extensions.get("subject-key-identifier");
  assertEquals(true, subjectKeyId instanceof ArrayBuffer);
  assertEquals(subjectKeyId.byteLength, 20);

  // authority-key-identifier
  var authorityKeyId = extensions.get("authority-key-identifier");
  assertEquals(true, authorityKeyId instanceof Map);
  assertEquals(authorityKeyId.size, 1);
  assertEquals(
    true,
    authorityKeyId.get("key-identifier") instanceof ArrayBuffer,
  );

  // basic-constraints
  var basicConstraints = extensions.get("basic-constraints");
  assertEquals(typeof basicConstraints, "object");
  assertEquals(Object.keys(basicConstraints).length, 1);
  assertEquals(basicConstraints.cA, false);

  // fido-u2f-transports
  var transports = extensions.get("fido-u2f-transports");
  assertEquals(true, transports instanceof Set);
  assertEquals(transports.size, 1);
  assertEquals(true, transports.has("usb"), "transports has USB");

  // 'fido-u2f-transports' => Set { 'usb' },

  // fido-aaguid
  var aaguid = extensions.get("fido-aaguid");
  assertEquals(true, aaguid instanceof ArrayBuffer);
  var expectedAaguid = new Uint8Array([
    0x42,
    0x38,
    0x32,
    0x45,
    0x44,
    0x37,
    0x33,
    0x43,
    0x38,
    0x46,
    0x42,
    0x34,
    0x45,
    0x35,
    0x41,
    0x32,
  ]).buffer;
  assertEquals(
    true,
    abEqual(aaguid, expectedAaguid),
    "correct aaguid value",
  );
});

Deno.test("Certificate getExtensions returns correct extensions for TPM attestation", function () {
  var cert = new Certificate(h.certs.tpmAttestation);
  var extensions = cert.getExtensions();
  assertEquals(true, extensions instanceof Map);
  assertEquals(extensions.size, 8);
  // key usage
  var keyUsage = extensions.get("key-usage");
  assertEquals(true, keyUsage instanceof Set);
  assertEquals(keyUsage.size, 1);
  assertEquals(
    true,
    keyUsage.has("digitalSignature"),
    "key-usage has digital signature",
  );
  // basic constraints
  var basicConstraints = extensions.get("basic-constraints");
  assertEquals(typeof basicConstraints, "object");
  assertEquals(Object.keys(basicConstraints).length, 1);
  assertEquals(basicConstraints.cA, false);
  // certificate policies
  var certPolicies = extensions.get("certificate-policies");
  assertEquals(true, Array.isArray(certPolicies));
  assertEquals(certPolicies.length, 1);
  var policyQualifiers = certPolicies[0];
  assertEquals(typeof policyQualifiers, "object");
  assertEquals(policyQualifiers.id, "policy-qualifiers");
  assertEquals(true, Array.isArray(policyQualifiers.value));
  assertEquals(policyQualifiers.value.length, 1);
  var policyQualifier = policyQualifiers.value[0];
  assertEquals(typeof policyQualifier, "object");
  assertEquals(policyQualifier.id, "policy-qualifier");
  assertEquals(true, Array.isArray(policyQualifier.value));
  assertEquals(policyQualifier.value.length, 1);
  assertEquals(policyQualifier.value[0], "TCPA  Trusted  Platform  Identity");
  // extended key usage
  var extKeyUsage = extensions.get("ext-key-usage");
  assertEquals(true, Array.isArray(extKeyUsage));
  assertEquals(extKeyUsage.length, 1);
  assertEquals(extKeyUsage[0], "tcg-kp-aik-certificate");
  // alternate name
  var subjAltNames = extensions.get("subject-alt-name");
  assertEquals(true, Array.isArray(subjAltNames));
  assertEquals(subjAltNames.length, 1);
  var subjAltName = subjAltNames[0];
  assertEquals(typeof subjAltName, "object");
  assertEquals(Object.keys(subjAltName).length, 1);
  var generalNames = subjAltName.directoryName;
  assertEquals(true, generalNames instanceof Map);
  assertEquals(generalNames.size, 3);
  assertEquals(generalNames.get("tcg-at-tpm-version"), "id:13");
  assertEquals(generalNames.get("tcg-at-tpm-model"), "NPCT6xx");
  assertEquals(generalNames.get("tcg-at-tpm-manufacturer"), "id:4E544300");
  // authority key identifier
  var authKeyId = extensions.get("authority-key-identifier");
  assertEquals(true, authKeyId instanceof Map);
  assertEquals(authKeyId.size, 1);
  authKeyId = authKeyId.get("key-identifier");
  assertEquals(true, authKeyId instanceof ArrayBuffer);
  var expectedAuthKeyId = new Uint8Array([
    0xC2,
    0x12,
    0xA9,
    0x5B,
    0xCE,
    0xFA,
    0x56,
    0xF8,
    0xC0,
    0xC1,
    0x6F,
    0xB1,
    0x5B,
    0xDD,
    0x03,
    0x34,
    0x47,
    0xB3,
    0x7A,
    0xA3,
  ]).buffer;
  assertEquals(
    true,
    abEqual(authKeyId, expectedAuthKeyId),
    "got expected authority key identifier",
  );
  // subject key identifier
  var subjectKeyId = extensions.get("subject-key-identifier");
  assertEquals(true, subjectKeyId instanceof ArrayBuffer);
  var expectedSubjectKeyId = new Uint8Array([
    0xAF,
    0xE2,
    0x45,
    0xD3,
    0x48,
    0x0F,
    0x22,
    0xDC,
    0xD5,
    0x0C,
    0xD2,
    0xAE,
    0x7B,
    0x96,
    0xB5,
    0xA9,
    0x33,
    0xCA,
    0x7F,
    0xE1,
  ]).buffer;
  assertEquals(
    true,
    abEqual(subjectKeyId, expectedSubjectKeyId),
    "got expected authority key identifier",
  );
  // info access
  var infoAccess = extensions.get("authority-info-access");
  assertEquals(true, infoAccess instanceof Map);
  assertEquals(infoAccess.size, 1);
  var certAuthIss = infoAccess.get("cert-authority-issuers");
  assertEquals(typeof certAuthIss, "object");
  assertEquals(Object.keys(certAuthIss).length, 1);
  assertEquals(
    certAuthIss.uniformResourceIdentifier,
    "https://azcsprodncuaikpublish.blob.core.windows.net/ncu-ntc-keyid-1591d4b6eaf98d0104864b6903a48dd0026077d3/3b918ae4-07e1-4059-9491-0ad248190818.cer",
  );
});

Deno.test("Certificate getSubject returns correct extensions for attestation", function () {
  var cert = new Certificate(h.certs.yubiKeyAttestation);
  var subject = cert.getSubject();
  assertEquals(true, subject instanceof Map);
  assertEquals(subject.size, 1);
  assertEquals(subject.get("common-name"), "Yubico U2F EE Serial 1432534688");
});

Deno.test("Certificate getSubject returns correct extensions for root", function () {
  var cert = new Certificate(h.certs.yubicoRoot);
  var subject = cert.getSubject();
  assertEquals(true, subject instanceof Map);
  assertEquals(subject.size, 1);
  assertEquals(
    subject.get("common-name"),
    "Yubico U2F Root CA Serial 457200631",
  );
});

Deno.test("Certificate getSubject returns correct values for Feitian FIDO2", function () {
  var cert = new Certificate(h.certs.feitianFido2);
  var subject = cert.getSubject();
  assertEquals(true, subject instanceof Map);
  assertEquals(subject.size, 4);
  assertEquals(subject.get("country-name"), "CN");
  assertEquals(subject.get("organization-name"), "Feitian Technologies");
  assertEquals(
    subject.get("organizational-unit-name"),
    "Authenticator Attestation",
  );
  assertEquals(subject.get("common-name"), "FT BioPass FIDO2 USB");
});

Deno.test("Helpers resolveOid decodes U2F USB transport type", function () {
  var ret = certHelpers.resolveOid(
    "1.3.6.1.4.1.45724.2.1.1",
    new Uint8Array([0x03, 0x02, 0x05, 0x20]).buffer,
  );
  assertEquals(typeof ret, "object");
  assertEquals(ret.id, "fido-u2f-transports");
  assertEquals(true, ret.value instanceof Set);
  assertEquals(ret.value.size, 1);
  assertEquals(true, ret.value.has("usb"));
});

Deno.test("Helpers resolveOid decodes U2F Bluetooth Classic transport type", function () {
  var ret = certHelpers.resolveOid(
    "1.3.6.1.4.1.45724.2.1.1",
    new Uint8Array([0x03, 0x02, 0x07, 0x80]).buffer,
  );
  assertEquals(typeof ret, "object");
  assertEquals(ret.id, "fido-u2f-transports");
  assertEquals(true, ret.value instanceof Set);
  assertEquals(ret.value.size, 1);
  assertEquals(true, ret.value.has("bluetooth-classic"));
});

Deno.test("decodes U2F USB+NFC transport type", function () {
  var ret = certHelpers.resolveOid(
    "1.3.6.1.4.1.45724.2.1.1",
    new Uint8Array([0x03, 0x02, 0x04, 0x30]).buffer,
  );
  assertEquals(typeof ret, "object");
  assertEquals(ret.id, "fido-u2f-transports");
  assertEquals(true, ret.value instanceof Set);
  assertEquals(ret.value.size, 2);
  assertEquals(true, ret.value.has("usb"));
  assertEquals(true, ret.value.has("nfc"));
});

Deno.test("Helpers resolveOid decodes U2F USB Internal transport type", function () {
  var ret = certHelpers.resolveOid(
    "1.3.6.1.4.1.45724.2.1.1",
    new Uint8Array([0x03, 0x02, 0x03, 0x08]).buffer,
  );
  assertEquals(typeof ret, "object");
  assertEquals(ret.id, "fido-u2f-transports");
  assertEquals(true, ret.value instanceof Set);
  assertEquals(ret.value.size, 1);
  assertEquals(true, ret.value.has("usb-internal"));
});

Deno.test("Helpers resolveOid decodes all transport types", function () {
  var ret = certHelpers.resolveOid(
    "1.3.6.1.4.1.45724.2.1.1",
    new Uint8Array([0x03, 0x02, 0x03, 0xF8]).buffer,
  );
  assertEquals(typeof ret, "object");
  assertEquals(ret.id, "fido-u2f-transports");
  assertEquals(true, ret.value instanceof Set);
  assertEquals(ret.value.size, 5);
  assertEquals(true, ret.value.has("bluetooth-classic"));
  assertEquals(true, ret.value.has("bluetooth-low-energy"));
  assertEquals(true, ret.value.has("usb"));
  assertEquals(true, ret.value.has("nfc"));
  assertEquals(true, ret.value.has("usb-internal"));
});

Deno.test("CRL can create mdsRootCrl", function () {
  var ret = new CRL(h.mds.mdsRootCrl);
  assertEquals(typeof ret, "object");
  assertEquals(typeof ret._crl, "object");
});

Deno.test("CRL can create ca1Crl", function () {
  var ret = new CRL(h.mds.ca1Crl);
  assertEquals(typeof ret, "object");
  assertEquals(typeof ret._crl, "object");
});

Deno.test("CertManager is function", function () {
  assertEquals(typeof CertManager, "function");
});

Deno.test("CertManager has static methods", function () {
  assertEquals(typeof CertManager.addCert, "function");
  assertEquals(typeof CertManager.removeAll, "function");
});

Deno.test("CertManager addCert throws if no cert", function () {
  assertThrows(
    () => {
      CertManager.addCert();
    },
    TypeError,
    "could not coerce 'certificate' to ArrayBuffer",
  );

  CertManager.removeAll();
});

Deno.test("CertManager addCert can add cert", function () {
  CertManager.addCert(h.certs.yubicoRoot);

  CertManager.removeAll();
});

Deno.test("CertManager getCerts returns empty Map if no certs added", function () {
  var ret = CertManager.getCerts();
  assertEquals(true, ret instanceof Map);
  assertEquals(ret.size, 0);
});

Deno.test("CertManager getCerts returns Map with added cert", function () {
  CertManager.addCert(h.certs.yubicoRoot);
  var ret = CertManager.getCerts();
  assertEquals(true, ret instanceof Map);
  assertEquals(ret.size, 1);
  assertEquals(true, ret.has("Yubico U2F Root CA Serial 457200631"));

  CertManager.removeAll();
});

Deno.test("CerManager verifyCertChain rejects on empty arguments", function () {
  assertRejects(() => {
    return CertManager.verifyCertChain();
  }, "expected 'certs' to be non-empty Array, got: undefined");
  CertManager.removeAll();
});

Deno.test("CerManager verifyCertChain works for MDS2", function () {
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

  var ret = CertManager.verifyCertChain(
    certs,
    trustedRoots,
    certRevocationLists,
  );
  assertEquals(true, ret instanceof Promise);

  CertManager.removeAll();

  return ret;
});

Deno.test("CerManager verifyCertChain will create certs from input arrays", function () {
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

  var ret = CertManager.verifyCertChain(
    certs,
    trustedRoots,
    certRevocationLists,
  );
  assertEquals(true, ret instanceof Promise);

  CertManager.removeAll();

  return ret;
});
