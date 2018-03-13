const validator = require("../lib/validator");
const parser = require("../lib/parser");
var assert = require("chai").assert;
const h = require("fido2-helpers");
const {
    printHex
} = h.functions;

describe("bad clientData", function() {
    it("zero length ArrayBuffer");
    it("ArrayBuffer full of random bytes");
    it("string, but not base64");
    it("malformed JSON");
    it("missing challenge");
    it("challenge isn't bytes");
    it("missing origin");
    it("origin isn't string");
    it("missing type");
    it("type isn't string");
    it("missing malformed tokenBinding");
    it("has hashAlgorithm (removed in WD-08)");
    it("has clientExtensions (removed in WD-08)");
    it("has authenticatorExtensions (removed in WD-08)");
    it("has tokenBindingId (removed in WD-07)");
});

describe("bad attestationObject", function() {
    it("zero length ArrayBuffer");
    it("ArrayBuffer full of random bytes");
    it("string, but not base64");
    it("malformed CBOR");
    it("missing fmt");
    it("fmt not string");
    it("missing attStmt");
    it("malformed attStmt");
    it("missing authData");
});

describe("bad authenticatorData", function() {
    it("zero length ArrayBuffer");
    it("ArrayBuffer full of random bytes");
    it("string, but not base64");
    it("malformed CBOR");
    it("AT flag set, but no attestation data"); // priority
    it("ED flag set, but no extension data"); // priority
    it("AT flag set, but random data"); // priority
    it("ED flag set, but random data"); // priority
    it("RFU1 set");
    it("RFU3 set");
    it("RFU4 set");
    it("RFU5 set");
    it("publicKey is random bytes"); // priority
});

describe("bad signature", function() {
    it("zero length ArrayBuffer");
    it("string, but not base64");
    it("random bytes");
    it("off by one byte"); // priority
});

describe("bad attestation statements", function() {
    it("u2f");
    it("none");
    it("tpm");
});