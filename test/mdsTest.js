"use strict";

const {
    MdsEntry,
    MdsCollection
} = require("../lib/mds");
const chai = require("chai");
var chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
var assert = chai.assert;
const h = require("fido2-helpers");
const {
    printHex,
    ab2str,
    str2ab,
    coerceToArrayBuffer,
    coerceToBase64Url
} = require("../lib/utils");

describe("MdsCollection", function() {
    it("is a function", function() {
        assert.isFunction(MdsCollection);
    });

    it("is a class", function() {
        var mdsCollection = new MdsCollection();
        assert.isObject(mdsCollection);
        assert.isFunction(mdsCollection.addToc);
        assert.isFunction(mdsCollection.addEntry);
        assert.isFunction(mdsCollection.validate);
        assert.isFunction(mdsCollection.findEntry);
    });

    describe("addToc", function() {
        var mc;
        beforeEach(function() {
            mc = new MdsCollection();
        });

        it("returns a promise", async function() {
            var p = mc.addToc();
            assert.instanceOf(p, Promise);
            try {
                await p;
            } catch (e) {
                // empty
            }
        });

        it("rejects if no jwk provided", function() {
            return assert.isRejected(mc.addToc(), Error, "expected MDS TOC to be non-empty string");
        });

        it("parses MDS1 TOC", async function() {
            var toc = await mc.addToc(
                h.mds.mds1TocJwt,
                h.mds.mdsRootCert,
                [
                    h.mds.mdsRootCrl,
                    h.mds.ca1Crl
                ]
            );
            assert.isObject(toc);
            assert.isString(toc.nextUpdate);
            assert.strictEqual(toc.nextUpdate, "2018-06-18");
            assert.isNumber(toc.no);
            assert.strictEqual(toc.no, 62);
            assert.isArray(toc.entries);
            assert.strictEqual(toc.entries.length, 66);
            assert.isString(toc.raw);
        });

        it("parses MDS2 TOC", async function() {
            var toc = await mc.addToc(
                h.mds.mds2TocJwt,
                h.mds.mdsRootCert,
                [
                    h.mds.mdsRootCrl,
                    h.mds.ca1Crl
                ]
            );
            assert.isObject(toc);
            assert.isString(toc.nextUpdate);
            assert.strictEqual(toc.nextUpdate, "2018-06-18");
            assert.isString(toc.legalHeader);
            assert.isNumber(toc.no);
            assert.strictEqual(toc.no, 2);
            assert.isArray(toc.entries);
            assert.strictEqual(toc.entries.length, 7);
            assert.isString(toc.raw);
        });

        it("works with array of root certs", function() {
            return mc.addToc(
                h.mds.mds1TocJwt,
                [
                    h.mds.mdsRootCert,
                ],
                [
                    h.mds.mdsRootCrl,
                    h.mds.ca1Crl
                ]
            );
        });

        it("MDS1 works with default root cert", function() {
            return mc.addToc(h.mds.mds1TocJwt);
        });

        it("MDS2 works with default root cert", function() {
            return mc.addToc(h.mds.mds2TocJwt);
        });

        it("works with no CRLs", function() {
            return mc.addToc(
                h.mds.mds1TocJwt,
                h.mds.mdsRootCert
            );
        });

        it("parses MDS2 TOC", function() {
            return mc.addToc(h.mds.mds2TocJwt);
        });

        it("throws on bad signature", function() {
            var tocParts = h.mds.mds2TocJwt.split(".");
            tocParts[2] = tocParts[2].toUpperCase(); // mess up the signature
            var toc = tocParts.join(".");
            return assert.isRejected(mc.addToc(toc), Error, "invalid signature");
        });

        it("throws on bad cert chain", function() {
            return assert.isRejected(mc.addToc(h.mds.mds2TocJwt, [h.certs.yubicoRoot]), Error, "No valid certificate paths found");
        });
    });

    describe("getToc", function() {
        var mc;
        beforeEach(function() {
            mc = new MdsCollection();
        });

        it("starts as null", function() {
            var toc = mc.getToc();
            assert.isNull(mc.toc);
            assert.isNull(toc);
        });

        it("returns correct object for MDS1", async function() {
            assert.isNull(mc.toc);
            await mc.addToc(h.mds.mds1TocJwt);
            var toc = mc.getToc();
            assert.isObject(toc);
            assert.isString(toc.nextUpdate);
            assert.strictEqual(toc.nextUpdate, "2018-06-18");
            assert.isNumber(toc.no);
            assert.strictEqual(toc.no, 62);
            assert.isArray(toc.entries);
            assert.strictEqual(toc.entries.length, 66);
        });

        it("returns correct object for MDS2", async function() {
            assert.isNull(mc.toc);
            await mc.addToc(h.mds.mds2TocJwt);
            var toc = mc.getToc();
            assert.isObject(toc);
            assert.isString(toc.nextUpdate);
            assert.strictEqual(toc.nextUpdate, "2018-06-18");
            assert.isString(toc.legalHeader);
            assert.isNumber(toc.no);
            assert.strictEqual(toc.no, 2);
            assert.isArray(toc.entries);
            assert.strictEqual(toc.entries.length, 7);
        });

        it("has raw");
    });

    describe("addEntry", function() {
        var mc;
        beforeEach(function() {
            mc = new MdsCollection();
        });

        it("throws on invalid jwk", function() {
            assert.throws(function() {
                mc.addEntry();
            }, Error, "expected MDS entry to be non-empty string");
        });

        it("creates new MDS1 entry");

        it("creates new MDS2 entry", function() {
            mc.addEntry(h.mds.mds2Entry);
        });

        it("has raw");
        it("has correct ID");
    });

    describe("validate", function() {
        var mc;
        beforeEach(function() {
            mc = new MdsCollection();
        });

        it("throws if no TOC", function() {
            mc.addEntry(h.mds.mds2Entry);
            assert.throws(function() {
                mc.validate();
            }, Error, "add MDS TOC before attempting to validate MDS collection");
        });

        it("throws if no entries", async function() {
            await mc.addToc(h.mds.mds2TocJwt);
            assert.throws(function() {
                mc.validate();
            }, Error, "add MDS entries before attempting to validate MDS collection");
        });

        it("adds good entry", async function() {
            await mc.addToc(h.mds.mds2TocJwt);
            mc.addEntry(h.mds.mds2Entry);
            mc.validate();
            assert.strictEqual(mc.entryList.size, 1);
            assert.isTrue(mc.entryList.has("4e4e#4005"), "added entry 4e4e#4005");
            var entry = mc.entryList.get("4e4e#4005");

            // check that TOC data was copied to new entry:
            // url
            assert.strictEqual(entry.url, "https://mds2.fidoalliance.org/metadata/4e4e%234005");
            // timeOfLastStatusChange
            assert.strictEqual(entry.timeOfLastStatusChange, "2018-05-19");
            // hash
            assert.strictEqual(entry.hash, "iuRviMMnBrXnVrjI0TiacTzKqdG8VXTA6PUy4r7Sxhk=");
            // id
            assert.strictEqual(entry.aaid, "4e4e#4005");
            assert.isUndefined(entry.aaguid);
            assert.isUndefined(entry.attestationCertificateKeyIdentifiers);
            // statusReports
            assert.isArray(entry.statusReports);
            assert.strictEqual(entry.statusReports.length, 1);

            // check the entry data was copied to new entry:
            // assertionScheme
            assert.strictEqual(entry.assertionScheme, "UAFV1TLV");
            // attachmentHint
            assert.isArray(entry.attachmentHint);
            assert.strictEqual(entry.attachmentHint.length, 1);
            assert.isTrue(entry.attachmentHint.includes("internal"));
            // attestationRootCertificates
            assert.isArray(entry.attestationRootCertificates);
            assert.strictEqual(entry.attestationRootCertificates.length, 0);
            // attestationTypes
            assert.isArray(entry.attestationTypes);
            assert.strictEqual(entry.attestationTypes.length, 1);
            assert.isTrue(entry.attestationTypes.includes("basic-surrogate"));
            // authenticationAlgorithm
            assert.strictEqual(entry.authenticationAlgorithm, "ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW");
            // authenticatorVersion
            assert.strictEqual(entry.authenticatorVersion, 256);
            // description
            assert.strictEqual(entry.description, "Touch ID, Face ID, or Passcode");
            // icon
            assert.isString(entry.icon);
            // isSecondFactorOnly
            assert.isFalse(entry.isSecondFactorOnly);
            // keyProtection
            assert.isArray(entry.keyProtection);
            assert.strictEqual(entry.keyProtection.length, 2);
            assert.isTrue(entry.keyProtection.includes("hardware"));
            assert.isTrue(entry.keyProtection.includes("tee"));
            // legalHeader
            assert.isString(entry.legalHeader);
            // matcherProtection
            assert.isArray(entry.matcherProtection);
            assert.strictEqual(entry.matcherProtection.length, 1);
            assert.isTrue(entry.matcherProtection.includes("hardware"));
            // protocolFamily
            assert.strictEqual(entry.protocolFamily, "uaf");
            // publicKeyAlgAndEncoding
            assert.strictEqual(entry.publicKeyAlgAndEncoding, "ALG_KEY_RSA_2048_RAW");
            // tcDisplay
            assert.isArray(entry.tcDisplay);
            assert.strictEqual(entry.tcDisplay.length, 1);
            assert.isTrue(entry.tcDisplay.includes("any"));
            assert.strictEqual(entry.tcDisplayContentType, "text/plain");
            assert.deepEqual(entry.upv, [
                {
                    major: 1,
                    minor: 1
                }, {
                    major: 1,
                    minor: 0
                }
            ]);
            assert.isArray(entry.userVerificationDetails);
            assert.strictEqual(entry.userVerificationDetails.length, 2);
            assert.isArray(entry.userVerificationDetails[0]);
            assert.deepEqual(
                entry.userVerificationDetails[0],
                [
                    {
                        type: "code",
                        userVerification: ["passcode"],
                        base: 10,
                        blockSlowdown: 60,
                        maxRetries: 5,
                        minLength: 4
                    }
                ]
            );
            assert.isArray(entry.userVerificationDetails[1]);
            assert.deepEqual(
                entry.userVerificationDetails[1],
                [
                    {
                        type: "biometric",
                        userVerification: ["fingerprint"],
                        blockSlowdown: 0,
                        maxReferenceDataSets: 5,
                        maxRetries: 5
                    }
                ]
            );
            // raw
            assert.isString(entry.raw);
        });
    });

    describe("findEntry", function() {
        var mc;
        before(async function() {
            mc = new MdsCollection();
            await mc.addToc(h.mds.mds2TocJwt);
            mc.addEntry(h.mds.mds2Entry);
            mc.validate();
        });

        it("throws if id is bad type", function() {
            assert.throws(function() {
                mc.findEntry();
            }, Error, "expected 'id' to be String, got: undefined");
        });

        it("returns MdsEntry", function() {
            var entry = mc.findEntry("4e4e#4005");
            assert.instanceOf(entry, MdsEntry);
            assert.strictEqual(entry.aaid, "4e4e#4005");
        });

        it("returns null on entry not found", function() {
            var entry = mc.findEntry("ffff#ffff");
            assert.isNull(entry);
        });
    });
});
