const { Fido2Lib } = require("../index");
const {
    Certificate,
    CertManager
} = require("../lib/cert-utils");
var assert = require("chai").assert;
var sinon = require("sinon");
var h = require("fido2-helpers");
const noneAttestation = require("../lib/attestations/none");

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
                console.log("cert._cert", cert._cert);
                // console.log("serialNumber", cert._cert.serialNumber);
                // console.log("subject", cert._cert.subject.typesAndValues[0].value.valueBlock.value);
                // console.log("issuer", cert._cert.issuer.typesAndValues[0].value.valueBlock.value);
                // console.log("version", cert._cert.version);
                // console.log("extensions", cert._cert.extensions);
                cert.getExtensions();
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
            it("can extract public key of attestation");
            it("can extract public key of root");
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
            it("returns correct serial for attestation", function() {
                var cert = new Certificate(h.certs.yubiKeyAttestation);
                var serial = cert.getIssuer();
                assert.strictEqual(serial, "Yubico U2F Root CA Serial 457200631");
            });

            it("returns correct serial for root", function() {
                var cert = new Certificate(h.certs.yubicoRoot);
                var serial = cert.getIssuer();
                assert.strictEqual(serial, "Yubico U2F Root CA Serial 457200631");
            });
        });

        describe("getCertVersion", function() {
            it("returns correct serial for attestation");
            it("returns correct serial for root");
        });

        describe.skip("getExtensions", function() {
            it("returns correct serial for attestation", function() {
                var cert = new Certificate(h.certs.yubiKeyAttestation);
                var extensions = cert.getExtensions();
                assert.fail();
            });

            it("returns correct serial for root");
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
            it("can clear all");
        });
    });
});