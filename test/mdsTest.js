"use strict";

const {
	MdsEntry,
	MdsCollection,
} = require("../lib/mds");

const {
	str2ab,
	coerceToBase64Url,
	jsObjectToB64,
} = require("../lib/utils");

const chai = require("chai");
const crypto = require("crypto");
const h = require("fido2-helpers");
const fs = require("fs");

var chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
var assert = chai.assert;

describe("MdsCollection", function() {
	it("is a function", function() {
		assert.isFunction(MdsCollection);
	});

	it("is a class", function() {
		var mdsCollection = new MdsCollection("test");
		assert.isObject(mdsCollection);
		assert.isFunction(mdsCollection.addToc);
		assert.isFunction(mdsCollection.addEntry);
		assert.isFunction(mdsCollection.validate);
		assert.isFunction(mdsCollection.findEntry);
		assert.strictEqual(mdsCollection.name, "test");
	});

	it("throws if no name specified in constructor", function() {
		assert.throws(function() {
			new MdsCollection();
		}, Error, "expected 'collectionName' to be non-empty string, got: undefined");
	});

	it("throws if name is empty string", function() {
		assert.throws(function() {
			new MdsCollection("");
		}, Error, "expected 'collectionName' to be non-empty string, got: ");
	});

	describe("addToc", function() {
		var mc;
		beforeEach(function() {
			mc = new MdsCollection("test");
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
			return assert.isRejected(mc.addToc(undefined), Error, "expected MDS TOC to be non-empty string");
		});

		it("rejects if TOC is empty string", function() {
			// bad toc
			var toc = "";
			return assert.isRejected(mc.addToc(toc), Error, "expected MDS TOC to be non-empty string");
		});

		it("rejects if TOC is junk string", function() {
			// bad toc
			var toc = "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r";
			return assert.isRejected(mc.addToc(toc), Error, "could not parse and validate MDS TOC: Unexpected token � in JSON at position 0");
		});

		it("rejects if TOC header is missing alg", function() {
			var jwtHeader = {
				// alg: "foo",
				typ: "JWT",
				x5c: [
					"sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r",
					"sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r",
				],
			};
			jwtHeader = coerceToBase64Url(str2ab(JSON.stringify(jwtHeader)), "JWT header");
			var jwtBody = "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r";
			var jwtSig = "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r";
			var toc = jwtHeader + "." + jwtBody + "." + jwtSig;
			return assert.isRejected(mc.addToc(toc), Error, "could not parse and validate MDS TOC: Algorithm not allowed: undefined");
		});

		it("rejects if TOC header is missing typ", function() {
			var jwtHeader = {
				alg: "foo",
				// typ: "JWT",
				x5c: [
					"sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r",
					"sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r",
				],
			};
			jwtHeader = coerceToBase64Url(str2ab(JSON.stringify(jwtHeader)), "JWT header");
			var jwtBody = "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r";
			var jwtSig = "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r";
			var toc = jwtHeader + "." + jwtBody + "." + jwtSig;
			return assert.isRejected(mc.addToc(toc), Error, "could not parse and validate MDS TOC: no key found");
		});

		it("rejects if TOC header x5c only has one entry", function() {
			var jwtHeader = {
				alg: "foo",
				typ: "JWT",
				x5c: [
					"sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r",
					// "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r"
				],
			};
			jwtHeader = coerceToBase64Url(str2ab(JSON.stringify(jwtHeader)), "JWT header");
			var jwtBody = "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r";
			var jwtSig = "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r";
			var toc = jwtHeader + "." + jwtBody + "." + jwtSig;
			return assert.isRejected(mc.addToc(toc), Error, "could not parse and validate MDS TOC: no key found");
		});

		it("rejects if TOC header x5c is missing", function() {
			var jwtHeader = {
				alg: "foo",
				typ: "JWT",
				// x5c: [
				//     "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r",
				//     "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r"
				// ]
			};
			jwtHeader = coerceToBase64Url(str2ab(JSON.stringify(jwtHeader)), "JWT header");
			var jwtBody = "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r";
			var jwtSig = "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r";
			var toc = jwtHeader + "." + jwtBody + "." + jwtSig;
			return assert.isRejected(mc.addToc(toc), Error, "could not parse and validate MDS TOC: no key found");
		});

		it("parses MDS1 TOC", async function() {
			var toc = await mc.addToc(
				h.mds.mds1TocJwt,
				h.mds.mdsRootCert,
				[
					h.mds.mdsRootCrl,
					h.mds.ca1Crl,
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
			assert.strictEqual(toc.raw, h.mds.mds1TocJwt);
		});

		it("parses MDS2 TOC", async function() {
			var toc = await mc.addToc(
				h.mds.mds2TocJwt,
				h.mds.mdsRootCert,
				[
					h.mds.mdsRootCrl,
					h.mds.ca1Crl,
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
					h.mds.ca1Crl,
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
			return assert.isRejected(mc.addToc(toc), Error, "could not parse and validate MDS TOC: no key found");
		});

		it("throws on bad cert chain", function() {
			return assert.isRejected(mc.addToc(h.mds.mds2TocJwt, [h.certs.yubicoRoot]), Error, "No valid certificate paths found");
		});
	});

	describe("getToc", function() {
		var mc;
		beforeEach(function() {
			mc = new MdsCollection("test");
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
			assert.isString(toc.raw);
			assert.strictEqual(toc.raw, h.mds.mds1TocJwt);
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
			assert.isString(toc.raw);
			assert.strictEqual(toc.raw, h.mds.mds2TocJwt);
		});
	});

	describe("addEntry", function() {
		var mc;
		beforeEach(function() {
			mc = new MdsCollection("test");
		});

		it("throws on invalid jwk", function() {
			assert.throws(function() {
				mc.addEntry();
			}, Error, "expected MDS entry to be non-empty string");
		});

		it("creates new MDS1 entry");

		it("creates new MDS1 UAF entry", function() {
			assert.strictEqual(mc.unvalidatedEntryList.size, 0);
			mc.addEntry(h.mds.mds1UafEntry);
			assert.strictEqual(mc.unvalidatedEntryList.size, 1);
		});

		it("creates new MDS1 U2F entry", function() {
			assert.strictEqual(mc.unvalidatedEntryList.size, 0);
			mc.addEntry(h.mds.mds1U2fEntry);
			assert.strictEqual(mc.unvalidatedEntryList.size, 1);
			assert.isTrue(mc.unvalidatedEntryList.has("923881fe2f214ee465484371aeb72e97f5a58e0a"));
		});

		it("creates new MDS2 UAF entry", function() {
			assert.strictEqual(mc.unvalidatedEntryList.size, 0);
			mc.addEntry(h.mds.mds2UafEntry);
			assert.strictEqual(mc.unvalidatedEntryList.size, 1);
			assert.isTrue(mc.unvalidatedEntryList.has("4e4e#4005"));
		});

		it("has raw");
		it("has correct ID");
	});

	describe("validate", function() {
		var mc;
		beforeEach(function() {
			mc = new MdsCollection("test");
		});

		it("throws if no TOC", function() {
			mc.addEntry(h.mds.mds2UafEntry);
			assert.throws(function() {
				mc.validate();
			}, Error, "add MDS TOC before attempting to validate MDS collection");
		});

		it("throws if entry hash doesn't match TOC hash");

		it("throws if no entries", async function() {
			await mc.addToc(h.mds.mds2TocJwt);
			assert.throws(function() {
				mc.validate();
			}, Error, "add MDS entries before attempting to validate MDS collection");
		});

		it("adds MDS1 U2F entry", async function() {
			await mc.addToc(h.mds.mds1TocJwt);
			mc.addEntry(h.mds.mds1U2fEntry);
			mc.validate();
			assert.strictEqual(mc.entryList.size, 1);
			assert.isTrue(mc.entryList.has("923881fe2f214ee465484371aeb72e97f5a58e0a"), "added entry 4e4e#4005");
			var entry = mc.entryList.get("923881fe2f214ee465484371aeb72e97f5a58e0a");
			assert.strictEqual(entry.protocolFamily, "u2f");
			assert.strictEqual(entry.authenticationAlgorithm, "ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW");
			assert.strictEqual(entry.publicKeyAlgAndEncoding, "ALG_KEY_ECC_X962_RAW");
			assert.deepEqual(entry.attestationTypes, ["basic-full"]);
			assert.deepEqual(entry.userVerificationDetails, [[{ userVerification: ["fingerprint"] }]]);
			assert.strictEqual(entry.isSecondFactorOnly, true);
			assert.deepEqual(entry.statusReports, [
				{
					status: "FIDO_CERTIFIED",
					url: "",
					certificate: "",
					effectiveDate: "2017-11-28",
				},
			]);
		});

		it("adds MDS1 UAF entry", async function() {
			await mc.addToc(h.mds.mds1TocJwt);
			mc.addEntry(h.mds.mds1UafEntry);
			mc.validate();
			assert.strictEqual(mc.entryList.size, 1);
			assert.isTrue(mc.entryList.has("0013#0001"), "added entry 4e4e#4005");
			var entry = mc.entryList.get("0013#0001");
			assert.strictEqual(entry.protocolFamily, "uaf");
			assert.strictEqual(entry.hash, "06LZxJ5mNuNZj48IZLV816bfp3A7GVtO2O-EeQ1pkTY=");
			assert.strictEqual(entry.aaid, "0013#0001");
			assert.strictEqual(entry.timeOfLastStatusChange, "2015-05-20");
		});

		it("adds MDS1 FIDO2 entry");

		it("adds MDS2 U2F entry");
		it("adds MDS2 FIDO2 entry");
		it("adds MDS2 UAF entry", async function() {
			await mc.addToc(h.mds.mds2TocJwt);
			mc.addEntry(h.mds.mds2UafEntry);
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
					minor: 1,
				}, {
					major: 1,
					minor: 0,
				},
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
						minLength: 4,
					},
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
						maxRetries: 5,
					},
				]
			);
			// raw
			assert.isString(entry.raw);
			// collection
			assert.instanceOf(entry.collection, MdsCollection);
		});

		it("adds MDS3 UAF entry", async function() {
			await mc.addToc(fs.readFileSync("./test/mdsV3.jwt", "utf8"));
			mc.addEntry("ewogICAgICAiYWFpZCI6ICI0ZTRlIzQwMDUiLAogICAgICAibWV0YWRhdGFTdGF0ZW1lbnQiOiB7CiAgICAgICAgImxlZ2FsSGVhZGVyIjogImh0dHBzOi8vZmlkb2FsbGlhbmNlLm9yZy9tZXRhZGF0YS9tZXRhZGF0YS1zdGF0ZW1lbnQtbGVnYWwtaGVhZGVyLyIsCiAgICAgICAgImFhaWQiOiAiNGU0ZSM0MDA1IiwKICAgICAgICAiZGVzY3JpcHRpb24iOiAiVG91Y2ggSUQsIEZhY2UgSUQsIG9yIFBhc3Njb2RlIiwKICAgICAgICAiYXV0aGVudGljYXRvclZlcnNpb24iOiAyNTYsCiAgICAgICAgInByb3RvY29sRmFtaWx5IjogInVhZiIsCiAgICAgICAgInNjaGVtYSI6IDMsCiAgICAgICAgInVwdiI6IFsKICAgICAgICAgIHsKICAgICAgICAgICAgIm1ham9yIjogMSwKICAgICAgICAgICAgIm1pbm9yIjogMAogICAgICAgICAgfSwKICAgICAgICAgIHsKICAgICAgICAgICAgIm1ham9yIjogMSwKICAgICAgICAgICAgIm1pbm9yIjogMQogICAgICAgICAgfQogICAgICAgIF0sCiAgICAgICAgImF1dGhlbnRpY2F0aW9uQWxnb3JpdGhtcyI6IFsKICAgICAgICAgICJyc2FfZW1zYV9wa2NzMV9zaGEyNTZfcmF3IgogICAgICAgIF0sCiAgICAgICAgInB1YmxpY0tleUFsZ0FuZEVuY29kaW5ncyI6IFsKICAgICAgICAgICJyc2FfMjA0OF9yYXciCiAgICAgICAgXSwKICAgICAgICAiYXR0ZXN0YXRpb25UeXBlcyI6IFsKICAgICAgICAgICJiYXNpY19zdXJyb2dhdGUiCiAgICAgICAgXSwKICAgICAgICAidXNlclZlcmlmaWNhdGlvbkRldGFpbHMiOiBbCiAgICAgICAgICBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAidXNlclZlcmlmaWNhdGlvbk1ldGhvZCI6ICJwYXNzY29kZV9pbnRlcm5hbCIsCiAgICAgICAgICAgICAgImNhRGVzYyI6IHsKICAgICAgICAgICAgICAgICJiYXNlIjogMTAsCiAgICAgICAgICAgICAgICAibWluTGVuZ3RoIjogNCwKICAgICAgICAgICAgICAgICJtYXhSZXRyaWVzIjogNSwKICAgICAgICAgICAgICAgICJibG9ja1Nsb3dkb3duIjogNjAKICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgIF0sCiAgICAgICAgICBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAidXNlclZlcmlmaWNhdGlvbk1ldGhvZCI6ICJmaW5nZXJwcmludF9pbnRlcm5hbCIsCiAgICAgICAgICAgICAgImJhRGVzYyI6IHsKICAgICAgICAgICAgICAgICJzZWxmQXR0ZXN0ZWRGUlIiOiAwLAogICAgICAgICAgICAgICAgInNlbGZBdHRlc3RlZEZBUiI6IDAsCiAgICAgICAgICAgICAgICAibWF4VGVtcGxhdGVzIjogMCwKICAgICAgICAgICAgICAgICJtYXhSZXRyaWVzIjogNSwKICAgICAgICAgICAgICAgICJibG9ja1Nsb3dkb3duIjogMAogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgXQogICAgICAgIF0sCiAgICAgICAgImtleVByb3RlY3Rpb24iOiBbCiAgICAgICAgICAiaGFyZHdhcmUiLAogICAgICAgICAgInRlZSIKICAgICAgICBdLAogICAgICAgICJtYXRjaGVyUHJvdGVjdGlvbiI6IFsKICAgICAgICAgICJ0ZWUiCiAgICAgICAgXSwKICAgICAgICAiYXR0YWNobWVudEhpbnQiOiBbCiAgICAgICAgICAiaW50ZXJuYWwiCiAgICAgICAgXSwKICAgICAgICAidGNEaXNwbGF5IjogWwogICAgICAgICAgImFueSIKICAgICAgICBdLAogICAgICAgICJ0Y0Rpc3BsYXlDb250ZW50VHlwZSI6ICJ0ZXh0L3BsYWluIiwKICAgICAgICAiYXR0ZXN0YXRpb25Sb290Q2VydGlmaWNhdGVzIjogW10sCiAgICAgICAgImljb24iOiAiZGF0YTppbWFnZS9wbmc7YmFzZTY0LGlWQk9SdzBLR2dvQUFBQU5TVWhFVWdBQUFFZ0FBQUJJQ0FZQUFBQlY3Yk5IQUFBQUFYTlNSMElBcnM0YzZRQUFBQnhwUkU5VUFBQUFBZ0FBQUFBQUFBQWtBQUFBS0FBQUFDUUFBQUFrQUFBRkpidUoyRWtBQUFUeFNVUkJWSGdCN0pZeGJpTkhFRVVGSjE0WUM1akpBZ3NuSHNPT0hQRUFDMmh5QitJTk5LRXpNblNtdWNCaWVRUHlCbUxnbkx5QmVBUFNKMWplZ0g2ZjZocVV5OVBhWGcwSk8rQUFYOTFkVlYzOS81L21RRGZINC9IbWlyd0hWM08rY0VHdUJsME55djk4U2o0dDF4dDB2VUhYRzNUUlg4R2c1amNEbjU5L3JMNERIOEFNYkJ4V3pGdndHM2cvOEpoaEdrcytWTG1hMXhKSDlBVEloR01oWkY3ejJ2TnkvRXZpdzl6OVNzYUlyTUcrMEpRKzg3UjM4cFhIRHROWTRtS3VwcFFvb2taZ0hveFpzLzRFcHVEMkJTaXZPdFdiYWJwOW85THpjL3hMNHNQY0xXQ0lrQXBzd1djZ29iZDkyNGlycm5ZWXh6cHlNdm9PTE1CZjRGODFjWS9XSlVia2FvWnQ3bVBqWWhJQS9nUjNMbnpEV21iTXdBcnNnZDJNdmxINURXaEJad2h6bWZVNytOWDM3cHZueEpmRUwyWVF4TitERDBhWXVRVEpsQzNvTTZJMGRtRC9IRlN1OXp1Yjk0MGxSdVJxTG1JUTVMODFvaElDOVBZbHJOU0UwanJkckZwbk1YNWpaOFl4Sjc0a2ZoR0RqQ0NrWnlCbnpJN2NBa3pCTGFoc240MHBybStPdmwxUElHZmNpdHdQdGkrT0pVYmthaTVpRUdUSFlOc2o2RE14aWUyK0pWSE1TMnYyNlRaT2djeU5adWxGOVBiTmlTK0puOTBnU09vL1k1SDFBbVRNQXhoNUE3UUdOWmlCRnN6QkJxelNXckVKcVB3K3pZbmRneDA0QnZ3VWEwdU15TldjMVNDSXlweEkrSkZZWmFTWmowQURaRVNzZldtOXAzNEphdXVsa2JWdWxGNkE3ZDM0dk9ZNThTWHhZWnNkRXdpK2RTUkZWcVFiVnlJeExUZ0FFL1BhY2U5N002L0FrK3RiKzNOTGpNalZuTk9ncFNNb2M3cnZnZVpnNi9MUm1EVTU0Y0hoTWNYVTY1aUJqT3JNWVA0cDFXMytWd1pCNnZ0RVRFSWt5SnZUc0k2M1JqVUwwUHRmdFJlbnVmcUJLWGdDZldiTmlaKytiNHc2VHpXMTljbmRqcEw0V1c0UVpHYUpWSjg1VVpDTStjZkgyb1JvbERDRGo5dWNuTXhhZzloM1M4eWJ0TFE5SlVia2FzNWxrTWlKY0dPa05FOHhFeUx6YXN0clpEMUtkU3ZHUGJCYVB4NklLNjkrbmJITWE3QURzWGFjZW5mMU9mRWw4Y0VHUVhDY1NENmFlTllpNTRuSG0xV1JYNFlhWDUrYnl5enRxNUlKSSthTDBFYzFadEl2cWlzeElsY3piRE9IUTJZRzlHMnc2ejFtN2dWR2MxUXZFYjdtTmZOVzR2WFE2eUgwMjdQdWJsdE9mRW44SEFiTmpReWp6UEhpb3psNis5RU0xU3pBSFRpOStXZlpKK0ZWaWl1dnVyaDNROHhlVEJQeUcrdFRZa1N1WnJCQlJrSkV3VGFRN0FRVGx4Z3ZVSUx2UWZlbW1jdmdHV2dUYXV1dmtaanFvMUU2MDB4YU1QZG50TnFYRTE4U0g3WlpwNmNIWXRHY3h1V1dnZmlqaVZJTjh3blloeG92VlB1clZEdGlydjArNzAxYWg5emJFaU55TldjeENFTFJnRlppOUpDYkJjS0w1OHp6MzU2OVhuaWN6MjB2KzZhaDcwWTVZakxRMzdJbUo3NGtQc2dnaUx3QksrQ0ZkQVlRYjBMdWliWDlIQ1JrRy9McW81cDFnaGRxWjJpUDlZajlUd2FTOS9GTmlSRzVtcUVHZllTTUVkZm96Um1IM0pmTVVYNXNOOFJHWXZkZ0YzcDVreFloZCtwQmJKM2kvNmxCRzBjdW1uTndPZDJFVGp4ekNUdzYrTDBWOFNWUTd6blFlZ1NpRVZ0bm9zeTFmcWM0NjdIRmNyZWpKRDcwQmttRWlEMDRzaUoyTUhLTTBSeUpOekVhdlRsdHlGbGRvLzZxRGZsNWluZG1wTHpWcjdVdU1TSlhNOVNnUHlCUWlhUWU1ZzN3NWtoZ2Mwbys1NWVzVGJSR2IwN00rYnF1ai9hRUhyWDZFL1A3OXlsV3F6WW52aVEreUNDUnNBY2k4MEJjTjJmaThsNUFOS2NOZS9XVGVRQzdFQitySDdHK24xUVZhazlucTdiRWlGek4zd0FBQVAvL1g5TGxQd0FBQlBOSlJFRlU3VnE3amlOVkZCd2tKQkNzdEIwUUVleTJJR1NEenBhTURzbldNY2wyU0xDU0hSQnNOdjRBeERnaVFuTC93WFJBUGkzeEFUYjhnUDBIMjM4d1ZMVlBtZG9yejROeDBHM0pWNm81OTlZNTUvcFV6WjFaYVRVWHQ3ZTNGMC9GQmRhM0wvTUNXQU8zaGcva21lZkNmbVk1MXEyQUxITFZQYmtzYW5YM2xuMUFrZlJVY1ZkdGZCUGM3S242MlBka2M5aU1ZZDdaUUJKQjhUbUg0OExlaDA3Tm9kRE83dGdidCt2ZWZ3Tm91TzVmSExoM0cxeHFYSTYrZkVpRFdodWNBcTZBL21VY0VQR1FPVFNCZ2lZQTd5WG1RQlZSQmpIbUFlY204WmswV2Z5TTNKQUdOVEhNQnJIa01GellaMEFiT1EzTHdYdnpFUG1kN3BKOEdiMnF2eS9XVVZ2YkhVMXdNK05hY2tNYTlCN0RYSElJTFp4TElCWHY1bFFIOHBYMTh5WGRaNDV5ZVh5V3pvd1pVQ1Q5ejRZMDZETVR4b0diWkRnT3ZRVDBjbWlPQzZJWkU5M0JpRFB2bVFLWHdCV3dBYnhIKzBYVWU3Ni9LK2w1UFpoQkpxakdVT21yb1pBcGE3aXdaNDNFTWRLY1lwZTkveXZxU21BRmVQK1dYZUQ4WHBubVhEbVlRUmp1eTJSb0NhQ1lYanhpRHF5VHVvL01RVzRDVUZScjRHdXNnRXoyWWI4RTlCbjRON2czaURYaTFzSE5qQ3NHTXlpRzJkZ3dGUDZXUEJmMkhMU3pQSVhRdkY0MFlnbHNBUW04S3k2c1p4bjFxL2lNM1B1RDQ3MjZLeHZhSUE2L0Fkd1lEdGpha0JyMmlnSzRrR09mK01mRU5lcjdWN203NGIrdnlUMTlUWEM5aVVNYjlGeWpZcWk3ak9ITG1saGRuWWpxRFFhWHN3WXhBOTRBUzhETjY1alRQWXJnK0NwVlY1SVBic0g5b0FiRk1EOWhJSDZITmFUSEpmaTlLT3hUYy9hdmluZWxDL1VsUUlOMVozdWdwclY4eVR6TzVBcnV4MkJRYlFOS3lBMjRrZ055WWM5WHdhR1ZaNno2NUM1ZjRkeEVEZVBFY2dYT2J0SytqelhSbzN0bndmV1IrekVZVkdKSURYaU5mY25CdEhDZUFKM1Y3TTBCbHdHcGNicXJZWjczSVBJTzhWdmRIVG52bndkWE1uSU5iaENId1BDL0FEbjNXamlYZ0E5UGdYd0pGV3NRYWM0YWtQQkRzV1l0RitwdXJOWmZtSDlHRmJYUEdMbEdZZEJ1bEY1RUFSRUxZR3RpSkh3RnJtQXRZbW9PalpzQ2VVVDFNSmJSVTJFdmZrR09DMXhyZk5tVDltVTBCbUhJZjJ4UUNXSHN4V3RtbkduaTJtcVo3NDJ6bXBubEcvSTQ1OGExVnJzMXZoU3ZPQ2FEU2h1VXhtd0F2b3BNdzJJL0FUcEFCdTdOQWNkK3IyV3VyN04rOVhVSE9PWStGNjg0R29NNEVBYjhEYmdDQ2cwWVBNVzNnQVF5dWpsMTVGeTQxK2R4ejc3ZjdoWDNON2wwamNvZ0h3NkNDNEEvS3VzUUx5R01LeUJuUFNKclBOZS9JbkJ1VUlZem9ibzJldWZHdlNLWHJ0RVpoSUZmQVZzYlhLSVkrV3FtRW9GOWxkVE5tUVBuWm53SWJtSzFUWERyNEJZOEgxcWpNNGhEWXVoVStBYmNKZEMvanFpWmhUZ2FSeXdsRVB1NTVlcW9yNDFqYng3bmEvVWRpcU0wS0FUOURBSDhmZlRHQjhjNUF4cEF4cVRtRkVtdWpKN09lSm96Qi9panVqZmRQMGY3MFJxa0FSVXBKRVM1ME5RYzFtd0JtZGUvRHB3WHhqWFlzKzVQUnQxL1Z4eTlRUkR4QXZnZDZBQUpWNXhLR0hJVXZiYWFUWENGY2V6amkvcFJmUS9GMFJ0RUFSQ1VBemVBak9FK2x6anNhVUpuZWY0eUo1Y0JhK04veGY0TDlUMG1ub1JCRWdKeHI0SHZkV2JFZVFiSU9FWTNwNDBjdWVrM0wxNSs0cjJQMlorVVFTNElncjhDL2dnRFpOQUdaNzJjdjdDL0J0NEN6NzMzLyt4UDFpQ0poSGorR1AwQWZBZDhHdmhhK1dQallBWWQ4OEduMG52VS81V2Npc2hqNWp3YjlNQ2YvNXdOT2h2MDlEOFE0NC9tK1FXZFg5QnhMK2hmVXdUWXlSQ2FyWjhBQUFBQVNVVk9SSzVDWUlJPSIKICAgICAgfSwKICAgICAgInN0YXR1c1JlcG9ydHMiOiBbCiAgICAgICAgewogICAgICAgICAgInN0YXR1cyI6ICJOT1RfRklET19DRVJUSUZJRUQiLAogICAgICAgICAgImVmZmVjdGl2ZURhdGUiOiAiMjAxOC0wNS0xOSIKICAgICAgICB9CiAgICAgIF0sCiAgICAgICJ0aW1lT2ZMYXN0U3RhdHVzQ2hhbmdlIjogIjIwMTgtMDUtMTkiCiAgICB9");
			mc.validate();
			assert.isTrue(mc.entryList.has("4e4e#4005"), "added entry 4e4e#4005");
			var entry = mc.entryList.get("4e4e#4005");

			// check that TOC data was copied to new entry:
			// schema
			assert.strictEqual(entry.schema, 3);
			// timeOfLastStatusChange
			assert.strictEqual(entry.timeOfLastStatusChange, "2018-05-19");
			// hash
			assert.isUndefined(entry.hash);

			let tocHash = crypto.createHash("sha256");
			tocHash.update(jsObjectToB64(entry.raw));
			tocHash = tocHash.digest().toString("base64");
			
			assert.strictEqual(tocHash, "KuTk5OTMPHkbY7bREv6ocsu8J739llB9u6ya1JPnqW4=");
			// id
			assert.strictEqual(entry.aaid, "4e4e#4005");
			assert.isUndefined(entry.aaguid);
			assert.isUndefined(entry.attestationCertificateKeyIdentifiers);
			// statusReports
			assert.isArray(entry.statusReports);
			assert.strictEqual(entry.statusReports.length, 1);

			// check the entry data was copied to new entry:
			// description
			assert.strictEqual(entry.description, "Touch ID, Face ID, or Passcode");
			// authenticatorVersion
			assert.strictEqual(entry.authenticatorVersion, 256);
			// protocolFamily
			assert.strictEqual(entry.protocolFamily, "uaf");
			assert.deepEqual(entry.upv, [
				{
					major: 1,
					minor: 0,
				},
				{
					major: 1,
					minor: 1,
				},
			]);
			// authenticationAlgorithms
			assert.deepEqual(entry.authenticationAlgorithms, [ "rsa_emsa_pkcs1_sha256_raw" ]);
			// publicKeyAlgAndEncoding
			assert.deepEqual(entry.publicKeyAlgAndEncodings, [ "rsa_2048_raw" ]);
			// attestationTypes
			assert.deepEqual(entry.attestationTypes, [ "basic_surrogate" ]);
			// userVerificationDetails
			assert.strictEqual(entry.userVerificationDetails.length, 2);
			assert.deepEqual(
				entry.userVerificationDetails[0],
				[
					{
						base: 10,
						blockSlowdown: 60,
						maxRetries: 5,
						minLength: 4,
						type: "code",
						userVerification: "passcode",
					},
				]
			);
			assert.deepEqual(
				entry.userVerificationDetails[1],
				[
					{
						blockSlowdown: 0,
						maxRetries: 5,
						maxTemplates: 0,
						selfAttestedFAR: 0,
						selfAttestedFRR: 0,
						type: "biometric",
						userVerification: "fingerprint",
					},
				]
			);
			// keyProtection
			assert.deepEqual(entry.keyProtection, [ "hardware", "tee" ]);
			// matcherProtection
			assert.deepEqual(entry.matcherProtection, [ "tee" ]);
			// attachmentHint
			assert.deepEqual(entry.attachmentHint, [ "internal" ]);
			// tcDisplay
			assert.deepEqual(entry.tcDisplay, [ "any" ]);
			// tcDisplayContentType
			assert.strictEqual(entry.tcDisplayContentType, "text/plain");
			// attestationRootCertificates
			assert.deepEqual(entry.attestationRootCertificates, []);
			// icon
			assert.isString(entry.icon);
			// raw
			assert.isString(entry.raw);
			// collection
			assert.instanceOf(entry.collection, MdsCollection);
		});

		it("adds MDS3 FIDO2 entry", async function() {
			await mc.addToc(fs.readFileSync("./test/mdsV3.jwt", "utf8"));
			mc.addEntry("ewogICAgICAiYWFndWlkIjogImM1ZWY1NWZmLWFkOWEtNGI5Zi1iNTgwLWFkZWJhZmUwMjZkMCIsCiAgICAgICJtZXRhZGF0YVN0YXRlbWVudCI6IHsKICAgICAgICAibGVnYWxIZWFkZXIiOiAiaHR0cHM6Ly9maWRvYWxsaWFuY2Uub3JnL21ldGFkYXRhL21ldGFkYXRhLXN0YXRlbWVudC1sZWdhbC1oZWFkZXIvIiwKICAgICAgICAiYWFndWlkIjogImM1ZWY1NWZmLWFkOWEtNGI5Zi1iNTgwLWFkZWJhZmUwMjZkMCIsCiAgICAgICAgImRlc2NyaXB0aW9uIjogIll1YmlLZXkgNUNpIiwKICAgICAgICAiYXV0aGVudGljYXRvclZlcnNpb24iOiA1MDIwMCwKICAgICAgICAicHJvdG9jb2xGYW1pbHkiOiAiZmlkbzIiLAogICAgICAgICJzY2hlbWEiOiAzLAogICAgICAgICJ1cHYiOiBbCiAgICAgICAgICB7CiAgICAgICAgICAgICJtYWpvciI6IDEsCiAgICAgICAgICAgICJtaW5vciI6IDAKICAgICAgICAgIH0KICAgICAgICBdLAogICAgICAgICJhdXRoZW50aWNhdGlvbkFsZ29yaXRobXMiOiBbCiAgICAgICAgICAiZWQyNTUxOV9lZGRzYV9zaGE1MTJfcmF3IiwKICAgICAgICAgICJzZWNwMjU2cjFfZWNkc2Ffc2hhMjU2X3JhdyIKICAgICAgICBdLAogICAgICAgICJwdWJsaWNLZXlBbGdBbmRFbmNvZGluZ3MiOiBbCiAgICAgICAgICAiY29zZSIKICAgICAgICBdLAogICAgICAgICJhdHRlc3RhdGlvblR5cGVzIjogWwogICAgICAgICAgImJhc2ljX2Z1bGwiCiAgICAgICAgXSwKICAgICAgICAidXNlclZlcmlmaWNhdGlvbkRldGFpbHMiOiBbCiAgICAgICAgICBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAidXNlclZlcmlmaWNhdGlvbk1ldGhvZCI6ICJwcmVzZW5jZV9pbnRlcm5hbCIKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICJ1c2VyVmVyaWZpY2F0aW9uTWV0aG9kIjogInBhc3Njb2RlX2ludGVybmFsIiwKICAgICAgICAgICAgICAiY2FEZXNjIjogewogICAgICAgICAgICAgICAgImJhc2UiOiA2NCwKICAgICAgICAgICAgICAgICJtaW5MZW5ndGgiOiA0LAogICAgICAgICAgICAgICAgIm1heFJldHJpZXMiOiA4LAogICAgICAgICAgICAgICAgImJsb2NrU2xvd2Rvd24iOiAwCiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9LAogICAgICAgICAgICB7CiAgICAgICAgICAgICAgInVzZXJWZXJpZmljYXRpb25NZXRob2QiOiAibm9uZSIKICAgICAgICAgICAgfQogICAgICAgICAgXQogICAgICAgIF0sCiAgICAgICAgImtleVByb3RlY3Rpb24iOiBbCiAgICAgICAgICAiaGFyZHdhcmUiLAogICAgICAgICAgInNlY3VyZV9lbGVtZW50IgogICAgICAgIF0sCiAgICAgICAgIm1hdGNoZXJQcm90ZWN0aW9uIjogWwogICAgICAgICAgIm9uX2NoaXAiCiAgICAgICAgXSwKICAgICAgICAiY3J5cHRvU3RyZW5ndGgiOiAxMjgsCiAgICAgICAgImF0dGFjaG1lbnRIaW50IjogWwogICAgICAgICAgImV4dGVybmFsIiwKICAgICAgICAgICJ3aXJlZCIKICAgICAgICBdLAogICAgICAgICJ0Y0Rpc3BsYXkiOiBbXSwKICAgICAgICAiYXR0ZXN0YXRpb25Sb290Q2VydGlmaWNhdGVzIjogWwogICAgICAgICAgIk1JSURIakNDQWdhZ0F3SUJBZ0lFRzBCVDl6QU5CZ2txaGtpRzl3MEJBUXNGQURBdU1Td3dLZ1lEVlFRREV5TlpkV0pwWTI4Z1ZUSkdJRkp2YjNRZ1EwRWdVMlZ5YVdGc0lEUTFOekl3TURZek1UQWdGdzB4TkRBNE1ERXdNREF3TURCYUdBOHlNRFV3TURrd05EQXdNREF3TUZvd0xqRXNNQ29HQTFVRUF4TWpXWFZpYVdOdklGVXlSaUJTYjI5MElFTkJJRk5sY21saGJDQTBOVGN5TURBMk16RXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDL2p3WXVoQlZscWFpWVdFTXNyV0Zpc2dKK1B0TTkxZVNycEk0VEs3VTUzbXdDSWF3U0RIeTh2VW1rNU4yS0FqOWFidlQ5TlA1U01TMWhRaTN1c3hvWUdvblhRZ2ZPNlpYeVVBOWErS0FrcWRGbkJubHl1Z1NlQ09lcDhFZFpGZnNhUkZ0TWprd3o1R2N6MlB5NHZJWXZDZE1IUHR3YXowYlZ1em5ldWVJRXo2VG5RakU2M1JkdDJ6YnduZWJ3VEc1WnliZVdTd2J6eStCSjM0WkhjVWhQQVk4OXlKUVh1RTBJek1aRmNFQmJQTlJiV0VDUktnanEvL3FUOW5tRE9GVmxTUkN0MndpcVBTemx1d24rditzdVFFQnNValRHTUVkMjV0S1hYVGtOVzIxd0lXYnhlU3lVb1RYd0x2R1M2eGx3UVNnTnBrMnFYWXdmOGlYZzdWV1pBZ01CQUFHalFqQkFNQjBHQTFVZERnUVdCQlFnSXZ6MGJOR0poamdwVG9rc3lLcFA5eHY5b0RBUEJnTlZIUk1FQ0RBR0FRSC9BZ0VBTUE0R0ExVWREd0VCL3dRRUF3SUJCakFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBanZqdU9NRFNhK0pYRkNMeUJLc3ljWHRCVlpzSjRVZTNMYmFFc1BZNE1ZTi9oSVE1Wk01cDdFamZjbk1HNEN0WWtOc2ZOSGMwQWhCTGRxNDVyblQ4N3EvNk8zdlVFdE5NYWZiaFU2a3RoWDdZKzlYRk45TnBtWXhyK2VrVlk1eE94aThoOUpESWdvTVA0VkIxdVMwYXVuTDFJR3FyTm9vTDltbUZuTDJrTFZWZWU2L1ZSNkM1K0tTVENNQ1dwcE11SklaSUkydjlvNGRrb1o4WTdRUmpRbExmWXpkM3FHdEtidzd4YUYxVXNHLzV4VWIvQnR3YjJYMmc0SW5waUIveXQvM0NwUVhwaVdYL0s0bUJ2VUtpR24wNVpzcWVZMWd4NGcweExCcWNVOXBzbXlQeksrVnNndzJqZVJRNUpsS0R5cUUwaGViZkMxdHZGdTBDQ3JKRmN3PT0iCiAgICAgICAgXSwKICAgICAgICAiaWNvbiI6ICJkYXRhOmltYWdlL3BuZztiYXNlNjQsaVZCT1J3MEtHZ29BQUFBTlNVaEVVZ0FBQUNBQUFBQWZDQVlBQUFDR1ZzK01BQUFBQVhOU1IwSUFyczRjNlFBQUFBUm5RVTFCQUFDeGp3djhZUVVBQUFBSmNFaFpjd0FBSFlZQUFCMkdBVjJpRTRFQUFBYk5TVVJCVkZoSHBWZDdUTlYxRkQvM2Q1OXdlUVNJZ1M5QVFBWGNGTEFRWmk5ZnBlVnoxdFkvV1RacjVXeHBjN1c1a25MYTVqSTNaODVzclMybk0yc2p0V3daUzdJVUg0SDR4Q25FUXg0REFaRjc0Vjd1czg4NXY5L2xJbkJ2VkovQjRQdjludS81bnUvNW52TTU1NmZ6QS9RdjBIYi9JclgzVkZLUG80NWNubTRpblVJV1l3TEZSbVpRVXV3akZHL04xaVJIaDFFWjBOUlZSdWRxdDFCZCsyblNLeVMvT2h5czArbGszZS8za1E5cXZENFpVdGE0VlZTVXVZMGVpcHlpVGhBZm9jb09SVmdEdXV3M3FLUmlBZDNyYmNFdGpUallJb2Y2V2FIc0NtelZQV0NNeCtjZ2g4dExxV01LYU1Xc1VqTHFvMlJ0SklRMG9Pem1lcnBRdTRlc1pnc09Oa0d4SDdkMGtkdlRUMTdzNE9NVTdWSThaaGpnR2FNK0FxOWlFTnU4UGlmMXVkejA3TXd2S1dmOEdsVm9DRVkwNFBDNVdkVGFYWUZiUjh2TnZMNSszS2dmYjV4Tk15YTlSYW1KaXluYU1sR1RWdEZscjZiYTl1K3BxbkVYNHVNdVJSZ2pTWUVock43dXRGRmU2bHFhbDdOZmt3NWltQUdIeW5QcGJrOFZtWTB4c3RucHRsRkNWQ1l0elR1Qk44M1FwTUxqVHRldmRQelNVbko3ZThta2p4WjM5ZlhiS0RmbGRacWJ2VStUVWdHbkJWRjZmUTJpUEhnNFcxNlVXVXd2emJrMTZzTVpFK1BuMHB2ejdKU2V1QXllczhsY3BDbWFLdW8vcCtxV3IyVWN3SUFIV3J2UDBZRXpoWEF0TEFic3NIaHA3aUdhbXZ5aWpQOHJ5cXJYVVdYOVhvb3d4eUF1Zk5CcnA0M1BPQkZYWmxrZjhNRFJpcWNweW93QXdwdXoyeCtmV3Z6L0R0ZGU5c21zenlndGNSNkMxd2JkekJsNk9scTVXTllZNG9HYXRoSk1ya1RFeDBqQVJTSEFWcys1cllrUU5YYitRZ2ZQTHNRNmdYeUluc3JlUWZtcG03UlZGWWZMODZuMWZpVU9rWXZTaGtVUHh2YnVrem95NksxaWhNMWhvM1h6VzZFdlNmWEErZHBpV0dhV2QrZG9Yekx6bUd3S1lGTENBc1JBbFBCQWhNbENGWFU3dEJVVlByOEhnVmNKSFdxK0YwMHBscitETVRkclA0enZ4WTExa05NaHhUK1NlVEdnK2Q0VjVMUUppdHlVR0pOQjhWRlpzamdZQlpNL0lJL1hDVGtqMHF5RE9wRjJBVlExN0NJalVwL0RuVDFVa0w1RjVnZGorc1Mxd2cxZ0UzZ2lnbTYwZkNYelNuUFhieUFQYklYditJRHBFMTZUaGFISVM5c2t5aGxtTUU1RjNjZnFBS2hxMkMwRTVQSDFnWWFYYUxQRGtaRzBIREpPbktXSHA1MUkwejVTT3V4OGUxV0F1WnpkSFFyVGtwOFRtalhvSStsYTB3R1pzenVicWJPM2lmUTZBL1c3dlZTWXNWM21SMEpLd2tLYzRXSGlCa21SOEkzQ0NnSTg3b09MNHF6VDVQK1JVSkJlakVPZ0FQSzhoWVB6YXRNK2VJVHAySU85eVRRbWVyb21QUnh4MXF4QWNzaWxlL3ViU2VFYmNXUUdZRUNnaGNMWTJIeUtqb2dqSDI1aE1wanBVdjFPdWdsaTRlaDJlUncwTzMyYkpqa3l1Q2dOemcwdnpsWU1TaVNzMHVvbzRNRzdoTU9qQ0VhWDF5RkUwblN2akJ6dVRuRXBLODZaOElvcUZBSXVidzhrZzlBckVhUkVXU1pJK2pINFhicDZnOUU5RW5KVDNvYVJ6RE4rTVVKQlFESG41NmE4b1VtRUJ1c094QnMvTjUrdEpFYlBrQUZEajhVR3ZPcy9JV3ZjU2dsR0JodlM3L0ZUWWZwV0dZZERZOGZQQXhXU0EzNXNUQzRwNCtMbTRBYXFJb1BlUXRmdWZLNkpoMFpoeGxic1VYT1NtWE5pZkQ1WlRBa3lEb2ZiYmNjbHhuQThXTkFxeENiUk55a2hYeFFwYUR3NjdmWFVZYnNpRzBLaHR2Mm9lSXZoOHJoUU1ZT2NFQXFYRy9lSSt6bmdPYzV5eHI4cTgySUFNMWMvRkxGT3BscXU1ZUZRWHJNWnpHY1ZDalliTFdHNUk0QlQxZXVScmxieHROT3RNaXREREVoTFhJSXluQUF2dU9FV0UzWDNOZEFmdDk0VmdhRzQyWElRdDBaWDZQZUNFL3FRRmU5cks2SHg3WVU1MEt2SDdmVzRmUytxN0tLQkp4c2dnQlg1cFNBR2gxaklyVmg1elE2dzNSZmFhaEJYbS9hQ2JDWlRqQ1VGVVR5V1pxVzlwNjJNakpQWFZxT3JQZ01PNE52NzRHa2Yrb3dmdE5WQkRRbmpGSnFIU3cxN3BYdmhXVzVLWnFlL1E0OU4vVVNUQ0FWV29RWEZJSEJIWFhlM0ZQclVEc3VHRG10Ri9oSEtUSHBla3hoaUFPUEkrU0pxNlM2SEY0STlZV3prQkpUbzQ2aVVNeldwOFBpci9SaWR1THhLWXNTa3NWOHZMbE9RdmhHWDJZbFIwT0JoQmpDK3UvZ0VjdlkwQXBLN1lrNDFOeGpQU1FuV0ZIVEY2NlVyamdldkI4Q3U1YStsMnZZU1JQdHVWRG83M2hoZE1TSG5VWDd0VGpzVlpHeEFsL1dwdGlPSUVRMWduTDI5bVg2L3RSMXRtbGtZajhXNFgrQ1NqV2NVREdZMU5wUy9DN2hTS3FpTUxNL2wyUW1TV1o3M0RkeitnaW84QkNFTllQUTQ2cW5rendYVWJxdkJreGpVUXNXZlpGZ2J1bzNyQWYrd043ak9POTAreW54NFBpM0wrMG5ZTDFTY2hEVWdBUDRnUFYvN0lkMXErMUhTaG11R2tJcVdSUGd5eE1GcVA4SGZqVG5qWHdZNWJRZmJKY3Q2T0l6S2dNSG90Ri9IZTFlZ3NheEhTcUc2d2ZkbVE1eDhOeVRGRnFCY3AyaVNvd0hSM3lrNSszNmhGN3ZYQUFBQUFFbEZUa1N1UW1DQyIsCiAgICAgICAgImF1dGhlbnRpY2F0b3JHZXRJbmZvIjogewogICAgICAgICAgInZlcnNpb25zIjogWwogICAgICAgICAgICAiVTJGX1YyIiwKICAgICAgICAgICAgIkZJRE9fMl8wIiwKICAgICAgICAgICAgIkZJRE9fMl8xX1BSRSIKICAgICAgICAgIF0sCiAgICAgICAgICAiZXh0ZW5zaW9ucyI6IFsKICAgICAgICAgICAgImNyZWRQcm90ZWN0IiwKICAgICAgICAgICAgImhtYWMtc2VjcmV0IgogICAgICAgICAgXSwKICAgICAgICAgICJhYWd1aWQiOiAiYzVlZjU1ZmZhZDlhNGI5ZmI1ODBhZGViYWZlMDI2ZDAiLAogICAgICAgICAgIm9wdGlvbnMiOiB7CiAgICAgICAgICAgICJwbGF0IjogZmFsc2UsCiAgICAgICAgICAgICJyayI6IHRydWUsCiAgICAgICAgICAgICJjbGllbnRQaW4iOiB0cnVlLAogICAgICAgICAgICAidXAiOiB0cnVlLAogICAgICAgICAgICAiY3JlZGVudGlhbE1nbXRQcmV2aWV3IjogdHJ1ZQogICAgICAgICAgfSwKICAgICAgICAgICJtYXhNc2dTaXplIjogMTIwMCwKICAgICAgICAgICJwaW5VdkF1dGhQcm90b2NvbHMiOiBbCiAgICAgICAgICAgIDIsCiAgICAgICAgICAgIDEKICAgICAgICAgIF0sCiAgICAgICAgICAibWF4Q3JlZGVudGlhbENvdW50SW5MaXN0IjogOCwKICAgICAgICAgICJtYXhDcmVkZW50aWFsSWRMZW5ndGgiOiAxMjgsCiAgICAgICAgICAidHJhbnNwb3J0cyI6IFsKICAgICAgICAgICAgInVzYiIsCiAgICAgICAgICAgICJsaWdodG5pbmciCiAgICAgICAgICBdLAogICAgICAgICAgImFsZ29yaXRobXMiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAidHlwZSI6ICJwdWJsaWMta2V5IiwKICAgICAgICAgICAgICAiYWxnIjogLTcKICAgICAgICAgICAgfSwKICAgICAgICAgICAgewogICAgICAgICAgICAgICJ0eXBlIjogInB1YmxpYy1rZXkiLAogICAgICAgICAgICAgICJhbGciOiAtOAogICAgICAgICAgICB9CiAgICAgICAgICBdLAogICAgICAgICAgIm1pblBJTkxlbmd0aCI6IDQsCiAgICAgICAgICAiZmlybXdhcmVWZXJzaW9uIjogMzI4NzA2CiAgICAgICAgfQogICAgICB9LAogICAgICAic3RhdHVzUmVwb3J0cyI6IFsKICAgICAgICB7CiAgICAgICAgICAic3RhdHVzIjogIkZJRE9fQ0VSVElGSUVEX0wxIiwKICAgICAgICAgICJlZmZlY3RpdmVEYXRlIjogIjIwMjAtMDUtMTIiLAogICAgICAgICAgImNlcnRpZmljYXRpb25EZXNjcmlwdG9yIjogIll1YmlLZXkgNUNpIiwKICAgICAgICAgICJjZXJ0aWZpY2F0ZU51bWJlciI6ICJGSURPMjAwMjAxOTEwMTcwMDMiLAogICAgICAgICAgImNlcnRpZmljYXRpb25Qb2xpY3lWZXJzaW9uIjogIjEuMS4xIiwKICAgICAgICAgICJjZXJ0aWZpY2F0aW9uUmVxdWlyZW1lbnRzVmVyc2lvbiI6ICIxLjMiCiAgICAgICAgfQogICAgICBdLAogICAgICAidGltZU9mTGFzdFN0YXR1c0NoYW5nZSI6ICIyMDIwLTA1LTEyIgogICAgfQ==");
			mc.validate();

			var entry = mc.findEntry("c5ef55ff-ad9a-4b9f-b580-adebafe026d0");
			assert.isDefined(entry, "added entry c5ef55ff-ad9a-4b9f-b580-adebafe026d0");

			// check that TOC data was copied to new entry:
			// schema
			assert.strictEqual(entry.schema, 3);
			// timeOfLastStatusChange
			assert.strictEqual(entry.timeOfLastStatusChange, "2020-05-12");
			// hash
			assert.isUndefined(entry.hash);

			let tocHash = crypto.createHash("sha256");
			tocHash.update(jsObjectToB64(entry.raw));
			tocHash = tocHash.digest().toString("base64");
			
			assert.strictEqual(tocHash, "cYyOrPCsXMBUvX03jMqmRZ9PRrW07WPwnVi1Dke9ze8=");
			// id
			assert.strictEqual(entry.aaguid, "c5ef55ff-ad9a-4b9f-b580-adebafe026d0");
			assert.isUndefined(entry.aaid);
			assert.isUndefined(entry.attestationCertificateKeyIdentifiers);
			// statusReports
			assert.isArray(entry.statusReports);
			assert.strictEqual(entry.statusReports.length, 1);

			// check the entry data was copied to new entry:
			// description
			assert.strictEqual(entry.description, "YubiKey 5Ci");
			// authenticatorVersion
			assert.strictEqual(entry.authenticatorVersion, 50200);
			// protocolFamily
			assert.strictEqual(entry.protocolFamily, "fido2");
			assert.deepEqual(entry.upv, [
				{
					major: 1,
					minor: 0,
				},
			]);
			// authenticationAlgorithms
			assert.deepEqual(entry.authenticationAlgorithms, [ "ed25519_eddsa_sha512_raw", "secp256r1_ecdsa_sha256_raw" ]);
			// publicKeyAlgAndEncoding
			assert.deepEqual(entry.publicKeyAlgAndEncodings, [ "cose" ]);
			// attestationTypes
			assert.deepEqual(entry.attestationTypes, [ "basic_full" ]);
			// userVerificationDetails
			assert.strictEqual(entry.userVerificationDetails.length, 1);
			assert.deepEqual(
				entry.userVerificationDetails[0],
				[
					{
						userVerification: "presence",
					},
					{
						userVerification: "passcode",
						base: 64,
						blockSlowdown: 0,
						maxRetries: 8,
						minLength: 4,
						type: "code",
					},
					{
						userVerification: "none",
					},
				]
			);
			// keyProtection
			assert.deepEqual(entry.keyProtection, [ "hardware", "secure_element" ]);
			// matcherProtection
			assert.deepEqual(entry.matcherProtection, [ "on_chip" ]);
			// cryptoStrength
			assert.strictEqual(entry.cryptoStrength, 128);
			// attachmentHint
			assert.deepEqual(entry.attachmentHint, [ "external", "wired" ]);
			// tcDisplay
			assert.deepEqual(entry.tcDisplay, [ ]);
			// tcDisplayContentType
			assert.isUndefined(entry.tcDisplayContentType);
			// attestationRootCertificates
			assert.deepEqual(entry.attestationRootCertificates, [ "MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbwnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXwLvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJhjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kthX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2kLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1UsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqcU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==" ]);
			// icon
			assert.isString(entry.icon);
			// authenticatorGetInfo
			const { authenticatorGetInfo } = entry;
			assert.isDefined(authenticatorGetInfo);

			// versions
			assert.deepEqual(authenticatorGetInfo.versions, [ "U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE" ]);
			// extensions
			assert.deepEqual(authenticatorGetInfo.extensions, [ "credProtect", "hmac-secret" ]);
			// aaguid
			assert.strictEqual(authenticatorGetInfo.aaguid, "c5ef55ffad9a4b9fb580adebafe026d0");
			// options
			assert.deepEqual(authenticatorGetInfo.options, {
				plat: false,
				rk: true,
				clientPin: true,
				up: true,
				credentialMgmtPreview: true,
			});
			// maxMsgSize
			assert.strictEqual(authenticatorGetInfo.maxMsgSize, 1200);
			// pinUvAuthProtocols
			assert.deepEqual(authenticatorGetInfo.pinUvAuthProtocols, [ 2, 1 ]);
			// maxCredentialCountInList
			assert.strictEqual(authenticatorGetInfo.maxCredentialCountInList, 8);
			// maxCredentialIdLength
			assert.strictEqual(authenticatorGetInfo.maxCredentialIdLength, 128);
			// transports
			assert.deepEqual(authenticatorGetInfo.transports, [ "usb", "lightning" ]);
			// algorithms
			assert.deepEqual(authenticatorGetInfo.algorithms, [ 
				{
					type: "public-key",
					alg: -7,
				},
				{
					type: "public-key",
					alg: -8,
				}, 
			]);
			// minPINLength
			assert.strictEqual(authenticatorGetInfo.minPINLength, 4);
			// raw
			assert.isString(entry.raw);
			// collection
			assert.instanceOf(entry.collection, MdsCollection);
		});
	

		it("adds MDS3 U2F entry", async function() {
			await mc.addToc(fs.readFileSync("./test/mdsV3.jwt", "utf8"));
			mc.addEntry("ewogICAgICAiYXR0ZXN0YXRpb25DZXJ0aWZpY2F0ZUtleUlkZW50aWZpZXJzIjogWwogICAgICAgICJiZjdiY2FhMGQwYzYxODdhOGM2YWJiZGQxNmExNTY0MGU3YzdiZGUyIiwKICAgICAgICAiNzUzMzAwZDY1ZGNjNzNhMzlhN2RiMzFlZjMwOGRiOWZhMGI1NjZhZSIsCiAgICAgICAgImI3NTNhMGU0NjBmYjJkYzdjN2M0ODdlMzVmMjRjZjYzYjA2NTM0N2MiLAogICAgICAgICJiNmQ0NGE0YjhkNGIwNDA3ODcyOTY5YjFmNmIyMjYzMDIxYmU2MjdlIiwKICAgICAgICAiNmQ0OTFmMjIzYWY3M2NkZjgxNzg0YTZjMDg5MGY4YTFkNTI3YTEyYyIKICAgICAgXSwKICAgICAgIm1ldGFkYXRhU3RhdGVtZW50IjogewogICAgICAgICJsZWdhbEhlYWRlciI6ICJodHRwczovL2ZpZG9hbGxpYW5jZS5vcmcvbWV0YWRhdGEvbWV0YWRhdGEtc3RhdGVtZW50LWxlZ2FsLWhlYWRlci8iLAogICAgICAgICJhdHRlc3RhdGlvbkNlcnRpZmljYXRlS2V5SWRlbnRpZmllcnMiOiBbCiAgICAgICAgICAiYmY3YmNhYTBkMGM2MTg3YThjNmFiYmRkMTZhMTU2NDBlN2M3YmRlMiIsCiAgICAgICAgICAiNzUzMzAwZDY1ZGNjNzNhMzlhN2RiMzFlZjMwOGRiOWZhMGI1NjZhZSIsCiAgICAgICAgICAiYjc1M2EwZTQ2MGZiMmRjN2M3YzQ4N2UzNWYyNGNmNjNiMDY1MzQ3YyIsCiAgICAgICAgICAiYjZkNDRhNGI4ZDRiMDQwNzg3Mjk2OWIxZjZiMjI2MzAyMWJlNjI3ZSIsCiAgICAgICAgICAiNmQ0OTFmMjIzYWY3M2NkZjgxNzg0YTZjMDg5MGY4YTFkNTI3YTEyYyIKICAgICAgICBdLAogICAgICAgICJkZXNjcmlwdGlvbiI6ICJZdWJpS2V5IDVDaSIsCiAgICAgICAgImF1dGhlbnRpY2F0b3JWZXJzaW9uIjogMiwKICAgICAgICAicHJvdG9jb2xGYW1pbHkiOiAidTJmIiwKICAgICAgICAic2NoZW1hIjogMywKICAgICAgICAidXB2IjogWwogICAgICAgICAgewogICAgICAgICAgICAibWFqb3IiOiAxLAogICAgICAgICAgICAibWlub3IiOiAxCiAgICAgICAgICB9CiAgICAgICAgXSwKICAgICAgICAiYXV0aGVudGljYXRpb25BbGdvcml0aG1zIjogWwogICAgICAgICAgInNlY3AyNTZyMV9lY2RzYV9zaGEyNTZfcmF3IgogICAgICAgIF0sCiAgICAgICAgInB1YmxpY0tleUFsZ0FuZEVuY29kaW5ncyI6IFsKICAgICAgICAgICJlY2NfeDk2Ml9yYXciCiAgICAgICAgXSwKICAgICAgICAiYXR0ZXN0YXRpb25UeXBlcyI6IFsKICAgICAgICAgICJiYXNpY19mdWxsIgogICAgICAgIF0sCiAgICAgICAgInVzZXJWZXJpZmljYXRpb25EZXRhaWxzIjogWwogICAgICAgICAgWwogICAgICAgICAgICB7CiAgICAgICAgICAgICAgInVzZXJWZXJpZmljYXRpb25NZXRob2QiOiAicHJlc2VuY2VfaW50ZXJuYWwiCiAgICAgICAgICAgIH0KICAgICAgICAgIF0KICAgICAgICBdLAogICAgICAgICJrZXlQcm90ZWN0aW9uIjogWwogICAgICAgICAgImhhcmR3YXJlIiwKICAgICAgICAgICJzZWN1cmVfZWxlbWVudCIsCiAgICAgICAgICAicmVtb3RlX2hhbmRsZSIKICAgICAgICBdLAogICAgICAgICJtYXRjaGVyUHJvdGVjdGlvbiI6IFsKICAgICAgICAgICJvbl9jaGlwIgogICAgICAgIF0sCiAgICAgICAgImNyeXB0b1N0cmVuZ3RoIjogMTI4LAogICAgICAgICJhdHRhY2htZW50SGludCI6IFsKICAgICAgICAgICJleHRlcm5hbCIsCiAgICAgICAgICAid2lyZWQiCiAgICAgICAgXSwKICAgICAgICAidGNEaXNwbGF5IjogW10sCiAgICAgICAgImF0dGVzdGF0aW9uUm9vdENlcnRpZmljYXRlcyI6IFsKICAgICAgICAgICJNSUlESGpDQ0FnYWdBd0lCQWdJRUcwQlQ5ekFOQmdrcWhraUc5dzBCQVFzRkFEQXVNU3d3S2dZRFZRUURFeU5aZFdKcFkyOGdWVEpHSUZKdmIzUWdRMEVnVTJWeWFXRnNJRFExTnpJd01EWXpNVEFnRncweE5EQTRNREV3TURBd01EQmFHQTh5TURVd01Ea3dOREF3TURBd01Gb3dMakVzTUNvR0ExVUVBeE1qV1hWaWFXTnZJRlV5UmlCU2IyOTBJRU5CSUZObGNtbGhiQ0EwTlRjeU1EQTJNekV3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQy9qd1l1aEJWbHFhaVlXRU1zcldGaXNnSitQdE05MWVTcnBJNFRLN1U1M213Q0lhd1NESHk4dlVtazVOMktBajlhYnZUOU5QNVNNUzFoUWkzdXN4b1lHb25YUWdmTzZaWHlVQTlhK0tBa3FkRm5Cbmx5dWdTZUNPZXA4RWRaRmZzYVJGdE1qa3d6NUdjejJQeTR2SVl2Q2RNSFB0d2F6MGJWdXpuZXVlSUV6NlRuUWpFNjNSZHQyemJ3bmVid1RHNVp5YmVXU3dienkrQkozNFpIY1VoUEFZODl5SlFYdUUwSXpNWkZjRUJiUE5SYldFQ1JLZ2pxLy9xVDlubURPRlZsU1JDdDJ3aXFQU3psdXduK3Yrc3VRRUJzVWpUR01FZDI1dEtYWFRrTlcyMXdJV2J4ZVN5VW9UWHdMdkdTNnhsd1FTZ05wazJxWFl3ZjhpWGc3VldaQWdNQkFBR2pRakJBTUIwR0ExVWREZ1FXQkJRZ0l2ejBiTkdKaGpncFRva3N5S3BQOXh2OW9EQVBCZ05WSFJNRUNEQUdBUUgvQWdFQU1BNEdBMVVkRHdFQi93UUVBd0lCQmpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQWp2anVPTURTYStKWEZDTHlCS3N5Y1h0QlZac0o0VWUzTGJhRXNQWTRNWU4vaElRNVpNNXA3RWpmY25NRzRDdFlrTnNmTkhjMEFoQkxkcTQ1cm5UODdxLzZPM3ZVRXROTWFmYmhVNmt0aFg3WSs5WEZOOU5wbVl4citla1ZZNXhPeGk4aDlKRElnb01QNFZCMXVTMGF1bkwxSUdxck5vb0w5bW1Gbkwya0xWVmVlNi9WUjZDNStLU1RDTUNXcHBNdUpJWklJMnY5bzRka29aOFk3UVJqUWxMZll6ZDNxR3RLYnc3eGFGMVVzRy81eFViL0J0d2IyWDJnNElucGlCL3l0LzNDcFFYcGlXWC9LNG1CdlVLaUduMDVac3FlWTFneDRnMHhMQnFjVTlwc215UHpLK1ZzZ3cyamVSUTVKbEtEeXFFMGhlYmZDMXR2RnUwQ0NySkZjdz09IgogICAgICAgIF0sCiAgICAgICAgImljb24iOiAiZGF0YTppbWFnZS9wbmc7YmFzZTY0LGlWQk9SdzBLR2dvQUFBQU5TVWhFVWdBQUFDQUFBQUFmQ0FZQUFBQ0dWcytNQUFBQUFYTlNSMElBcnM0YzZRQUFBQVJuUVUxQkFBQ3hqd3Y4WVFVQUFBQUpjRWhaY3dBQUhZWUFBQjJHQVYyaUU0RUFBQWJOU1VSQlZGaEhwVmQ3VE5WMUZELzNkNTl3ZVFTSWdTOUFRQVhjRkxBUVppOWZwZVZ6MXRZL1dUWnI1V3hwYzdXNWtuTGE1akkzWjg1c3JTMm5NMnNqdFd3WlM3SVVINEg0eENuRVF4NERBWkY3NFY3dXM4ODV2OS9sSW5CdlZKL0I0UHY5bnUvNW51LzVudk01NTZmekEvUXYwSGIvSXJYM1ZGS1BvNDVjbm00aW5VSVdZd0xGUm1aUVV1d2pGRy9OMWlSSGgxRVowTlJWUnVkcXQxQmQrMm5TS3lTL09oeXMwK2xrM2UvM2tROXF2RDRaVXRhNFZWU1V1WTBlaXB5aVRoQWZvY29PUlZnRHV1dzNxS1JpQWQzcmJjRXRqVGpZSW9mNldhSHNDbXpWUFdDTXgrY2doOHRMcVdNS2FNV3NVakxxbzJSdEpJUTBvT3ptZXJwUXU0ZXNaZ3NPTmtHeEg3ZDBrZHZUVDE3czRPTVU3Vkk4WmhqZ0dhTStBcTlpRU51OFBpZjF1ZHowN013dktXZjhHbFZvQ0VZMDRQQzVXZFRhWFlGYlI4dk52TDUrM0tnZmI1eE5NeWE5UmFtSml5bmFNbEdUVnRGbHI2YmE5dStwcW5FWDR1TXVSUmdqU1lFaHJON3V0RkZlNmxxYWw3TmZrdzVpbUFHSHluUHBiazhWbVkweHN0bnB0bEZDVkNZdHpUdUJOODNRcE1MalR0ZXZkUHpTVW5KN2U4bWtqeFozOWZYYktEZmxkWnFidlUrVFVnR25CVkY2ZlEyaVBIZzRXMTZVV1V3dnpiazE2c01aRStQbjBwdno3SlNldUF5ZXM4bGNwQ21hS3VvL3ArcVdyMlVjd0lBSFdydlAwWUV6aFhBdExBYnNzSGhwN2lHYW12eWlqUDhyeXFyWFVXWDlYb293eHlBdWZOQnJwNDNQT0JGWFpsa2Y4TURSaXFjcHlvd0F3cHV6MngrZld2ei9EdGRlOXNtc3p5Z3RjUjZDMXdiZHpCbDZPbHE1V05ZWTRvR2F0aEpNcmtURXgwakFSU0hBVnMrNXJZa1FOWGIrUWdmUExzUTZnWHlJbnNyZVFmbXBtN1JWRllmTDg2bjFmaVVPa1l2U2hrVVB4dmJ1a3pveTZLMWloTTFobzNYelc2RXZTZlhBK2RwaVdHYVdkK2RvWHpMem1Hd0tZRkxDQXNSQWxQQkFoTWxDRlhVN3RCVVZQcjhIZ1ZjSkhXcStGMDBwbHIrRE1UZHJQNHp2eFkxMWtOTWh4VCtTZVRHZytkNFY1TFFKaXR5VUdKTkI4VkZac2pnWUJaTS9JSS9YQ1RrajBxeURPcEYyQVZRMTdDSWpVcC9EblQxVWtMNUY1Z2RqK3NTMXdnMWdFM2dpZ202MGZDWHpTblBYYnlBUGJJWHYrSURwRTE2VGhhSElTOXNreWhsbU1FNUYzY2ZxQUtocTJDMEU1UEgxZ1lhWGFMUERrWkcwSERKT25LV0hwNTFJMHo1U091eDhlMVdBdVp6ZEhRclRrcDhUbWpYb0krbGEwd0dac3p1YnFiTzNpZlE2QS9XN3ZWU1lzVjNtUjBKS3drS2M0V0hpQmttUjhJM0NDZ0k4N29PTDRxelQ1UCtSVUpCZWpFT2dBUEs4aFlQemF0TStlSVRwMklPOXlUUW1lcm9tUFJ4eDFxeEFjc2lsZS91YlNlRWJjV1FHWUVDZ2hjTFkySHlLam9nakgyNWhNcGpwVXYxT3VnbGk0ZWgyZVJ3ME8zMmJKamt5dUNnTnpnMHZ6bFlNU2lTczB1b280TUc3aE1PakNFYVgxeUZFMG5TdmpCenVUbkVwSzg2WjhJb3FGQUl1Ync4a2c5QXJFYVJFV1NaSStqSDRYYnA2ZzlFOUVuSlQzb2FSekROK01VSkJRREhuNTZhOG9VbUVCdXNPeEJzL041K3RKRWJQa0FGRGo4VUd2T3MvSVd2Y1NnbEdCaHZTNy9GVFlmcFdHWWREWThmUEF4V1NBMzVzVEM0cDQrTG00QWFxSW9QZVF0ZnVmSzZKaDBaaHhsYnNVWE9TbVhOaWZENVpUQWt5RG9mYmJjY2x4bkE4V05BcXhDYlJOeWtoWHhRcGFEdzY3ZlhVWWJzaUcwS2h0djJvZUl2aDhyaFFNWU9jRUFxWEcvZUkrem5nT2M1eXhyOHE4MklBTTFjL0ZMRk9wbHF1NWVGUVhyTVp6R2NWQ2pZYkxXRzVJNEJUMWV1UnJsYnh0Tk90TWl0RERFaExYSUl5bkFBdnVPRVdFM1gzTmRBZnQ5NFZnYUc0MlhJUXQwWlg2UGVDRS9xUUZlOXJLNkh4N1lVNTBLdkg3Zlc0ZlMrcTdLS0JKeHNnZ0JYNXBTQUdoMWpJclZoNXpRNnczUmZhYWhCWG0vYUNiQ1pUakNVRlVUeVdacVc5cDYyTWpKUFhWcU9yUGdNTzROdjc0R2tmK293ZnROVkJEUW5qRkpxSFN3MTdwWHZoV1c1S1pxZS9RNDlOL1VTVENBVldvUVhGSUhCSFhYZTNGUHJVRHN1R0RtdEYvaEhLVEhwZWt4aGlBT1BJK1NKcTZTNkhGNEk5WVd6a0JKVG80NmlVTXpXcDhQaXIvUmlkdUx4S1lzU2tzVjh2TGxPUXZoR1gyWWxSME9CaEJqQyt1L2dFY3ZZMEFwSzdZazQxTnhqUFNRbldGSFRGNjZVcmpnZXZCOEN1NWErbDJ2WVNSUHR1VkRvNzNoaGRNU0huVVg3dFRqc1ZaR3hBbC9XcHRpT0lFUTFnbkwyOW1YNi90UjF0bWxrWWo4VzRYK0NTaldjVURHWTFOcFMvQzdoU0txaU1MTS9sMlFtU1daNzNEZHorZ2lvOEJDRU5ZUFE0NnFua3p3WFVicXZCa3hqVVFzV2ZaRmdidW8zckFmK3dON2pPTzkwK3lueDRQaTNMKzBuWUwxU2NoRFVnQVA0Z1BWLzdJZDFxKzFIU2htdUdrSXFXUlBneXhNRnFQOEhmalRualh3WTViUWZiSmN0Nk9JektnTUhvdEYvSGUxZWdzYXhIU3FHNndmZG1RNXg4TnlURkZxQmNwMmlTb3dIUjN5azUrMzZoRjd2WEFBQUFBRWxGVGtTdVFtQ0MiCiAgICAgIH0sCiAgICAgICJzdGF0dXNSZXBvcnRzIjogWwogICAgICAgIHsKICAgICAgICAgICJzdGF0dXMiOiAiRklET19DRVJUSUZJRURfTDEiLAogICAgICAgICAgImVmZmVjdGl2ZURhdGUiOiAiMjAyMC0wNS0xMiIsCiAgICAgICAgICAiY2VydGlmaWNhdGlvbkRlc2NyaXB0b3IiOiAiWXViaUtleSA1Q2kiLAogICAgICAgICAgImNlcnRpZmljYXRlTnVtYmVyIjogIlUyRjExMDAyMDE5MTAxNzAwNyIsCiAgICAgICAgICAiY2VydGlmaWNhdGlvblBvbGljeVZlcnNpb24iOiAiMS4xLjEiLAogICAgICAgICAgImNlcnRpZmljYXRpb25SZXF1aXJlbWVudHNWZXJzaW9uIjogIjEuMyIKICAgICAgICB9CiAgICAgIF0sCiAgICAgICJ0aW1lT2ZMYXN0U3RhdHVzQ2hhbmdlIjogIjIwMjAtMDUtMTIiCiAgICB9");
			mc.validate();

			var entry = mc.findEntry("bf7bcaa0d0c6187a8c6abbdd16a15640e7c7bde2");
			assert.isDefined(entry, "added entry bf7bcaa0d0c6187a8c6abbdd16a15640e7c7bde2");

			// check that TOC data was copied to new entry:
			// schema
			assert.strictEqual(entry.schema, 3);
			// timeOfLastStatusChange
			assert.strictEqual(entry.timeOfLastStatusChange, "2020-05-12");
			// hash
			assert.isUndefined(entry.hash);

			let tocHash = crypto.createHash("sha256");
			tocHash.update(jsObjectToB64(entry.raw));
			tocHash = tocHash.digest().toString("base64");
			
			assert.strictEqual(tocHash, "QaFyj/U7FwUCdztfF5Evz7VU2e+paGqlVyVNw1DpVws=");
			// id
			assert.isUndefined(entry.aaguid);
			assert.isUndefined(entry.aaid);
			// statusReports
			assert.isArray(entry.statusReports);
			assert.strictEqual(entry.statusReports.length, 1);
			// attestationCertificateKeyIdentifiers
			assert.isArray(entry.attestationCertificateKeyIdentifiers);
			assert.isTrue(entry.attestationCertificateKeyIdentifiers.includes("bf7bcaa0d0c6187a8c6abbdd16a15640e7c7bde2"), "Identifier bf7bcaa0d0c6187a8c6abbdd16a15640e7c7bde2 found");

			// check the entry data was copied to new entry:
			// description
			assert.strictEqual(entry.description, "YubiKey 5Ci");
			// authenticatorVersion
			assert.strictEqual(entry.authenticatorVersion, 2);
			// protocolFamily
			assert.strictEqual(entry.protocolFamily, "u2f");
			assert.deepEqual(entry.upv, [
				{
					major: 1,
					minor: 1,
				},
			]);
			// authenticationAlgorithms
			assert.deepEqual(entry.authenticationAlgorithms, [ "secp256r1_ecdsa_sha256_raw" ]);
			// publicKeyAlgAndEncoding
			assert.deepEqual(entry.publicKeyAlgAndEncodings, [ "ecc_x962_raw" ]);
			// attestationTypes
			assert.deepEqual(entry.attestationTypes, [ "basic_full" ]);
			// userVerificationDetails
			assert.strictEqual(entry.userVerificationDetails.length, 1);
			assert.deepEqual(
				entry.userVerificationDetails[0],
				[
					{
						userVerification: "presence",
					},
				]
			);
			// keyProtection
			assert.deepEqual(entry.keyProtection, [ "hardware", "secure_element", "remote_handle" ]);
			// matcherProtection
			assert.deepEqual(entry.matcherProtection, [ "on_chip" ]);
			// cryptoStrength
			assert.strictEqual(entry.cryptoStrength, 128);
			// attachmentHint
			assert.deepEqual(entry.attachmentHint, [ "external", "wired" ]);
			// tcDisplay
			assert.deepEqual(entry.tcDisplay, [ ]);
			// tcDisplayContentType
			assert.isUndefined(entry.tcDisplayContentType);
			// attestationRootCertificates
			assert.deepEqual(entry.attestationRootCertificates, [ "MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbwnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXwLvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJhjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kthX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2kLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1UsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqcU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==" ]);
			// icon
			assert.isString(entry.icon);
			// raw
			assert.isString(entry.raw);
			// collection
			assert.instanceOf(entry.collection, MdsCollection);
		});
	});

	describe("findEntry", function() {
		var mc;
		before(async function() {
			mc = new MdsCollection("test");
			await mc.addToc(h.mds.mds2TocJwt);
			mc.addEntry(h.mds.mds2UafEntry);
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
