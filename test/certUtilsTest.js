"use strict";

const { Fido2Lib } = require("../index");
const {
    Certificate,
    CertManager,
    helpers: certHelpers
} = require("../lib/certUtils");
const { resolveOid } = certHelpers;
var assert = require("chai").assert;
var sinon = require("sinon");
var h = require("fido2-helpers");
const noneAttestation = require("../lib/attestations/none");
const { printHex } = require("../lib/utils");

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
                console.log("extensions", extensions);
                assert.instanceOf(extensions, Map);
                assert.strictEqual(extensions.size, 3);
                assert.isTrue(extensions.has("subject-key-identifier"));
                assert.isTrue(extensions.has("basic-constraints"));
                assert.isTrue(extensions.has("key-usage"));
                assert.instanceOf(extensions.get("subject-key-identifier"), ArrayBuffer);
                assert.instanceOf(extensions.get("basic-constraints"), ArrayBuffer);
                assert.instanceOf(extensions.get("key-usage"), ArrayBuffer);
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

    describe("RootManager", function() {
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
            it("returns empty Array if no certs added", function() {
                var ret = CertManager.getCerts();
                assert.isArray(ret);
                assert.strictEqual(ret.length, 0);
            });

            it("returns Array with added cert", function() {
                CertManager.addCert(h.certs.yubicoRoot);
                var ret = CertManager.getCerts();
                assert.isArray(ret);
                assert.strictEqual(ret.length, 1);
            });
        });

        describe("removeAll", function() {
            it("can clear all"); // if this didn't work, afterEach would fail...
        });
    });
});
