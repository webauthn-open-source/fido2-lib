"use strict";

const parser = require("../lib/parser");
var assert = require("chai").assert;
const h = require("fido2-helpers");
const { arrayBufferEquals } = h.functions;

describe("parseAuthnrAssertionResponse", function() {
  it("parser is object", function() {
    assert.isObject(parser);
  });

  it("parses assertion correctly", function() {
    var ret = parser.parseAuthnrAssertionResponse(h.lib.assertionResponse);
    assert.instanceOf(ret, Map);
    assert.strictEqual(ret.size, 6);
    // rpid
    var rpIdHash = ret.get("rpIdHash");
    assert.instanceOf(rpIdHash, ArrayBuffer);
    var expectedRpIdHash = new Uint8Array([
      0x49,
      0x96,
      0x0d,
      0xe5,
      0x88,
      0x0e,
      0x8c,
      0x68,
      0x74,
      0x34,
      0x17,
      0x0f,
      0x64,
      0x76,
      0x60,
      0x5b,
      0x8f,
      0xe4,
      0xae,
      0xb9,
      0xa2,
      0x86,
      0x32,
      0xc7,
      0x99,
      0x5c,
      0xf3,
      0xba,
      0x83,
      0x1d,
      0x97,
      0x63
    ]).buffer;
    assert(arrayBufferEquals(rpIdHash, expectedRpIdHash), "correct rpIdHash");
    // flags
    var flags = ret.get("flags");
    assert.instanceOf(flags, Set);
    assert.strictEqual(flags.size, 1);
    assert.isTrue(flags.has("UP"));
    // counter
    assert.strictEqual(ret.get("counter"), 363);
    // sig
    var sig = ret.get("sig");
    assert.instanceOf(sig, ArrayBuffer);
    var expectedSig = new Uint8Array([
      0x30,
      0x46,
      0x02,
      0x21,
      0x00,
      0xfa,
      0x74,
      0x5d,
      0xc1,
      0xd1,
      0x9a,
      0x1a,
      0x2c,
      0x0d,
      0x2b,
      0xef,
      0xca,
      0x32,
      0x45,
      0xda,
      0x0c,
      0x35,
      0x1d,
      0x1b,
      0x37,
      0xdd,
      0xd9,
      0x8b,
      0x87,
      0x05,
      0xff,
      0xbe,
      0x61,
      0x14,
      0x01,
      0xfa,
      0xa5,
      0x02,
      0x21,
      0x00,
      0xb6,
      0x34,
      0x50,
      0x8b,
      0x2b,
      0x87,
      0x4d,
      0xee,
      0xfd,
      0xfe,
      0x32,
      0x28,
      0xec,
      0x33,
      0xc0,
      0x3e,
      0x82,
      0x8f,
      0x7f,
      0xc6,
      0x58,
      0xb2,
      0x62,
      0x8a,
      0x84,
      0xd3,
      0xf7,
      0x9f,
      0x34,
      0xb3,
      0x56,
      0xbb
    ]).buffer;
    assert(arrayBufferEquals(sig, expectedSig), "correct signature buffer");
    // userHandle
    var userHandle = ret.get("userHandle");
    assert.isUndefined(userHandle);
    // authRawData
    var rawAuthnrData = ret.get("rawAuthnrData");
    assert.instanceOf(rawAuthnrData, ArrayBuffer);
    var expectedAuthnrRawData = new Uint8Array([
      0x49,
      0x96,
      0x0d,
      0xe5,
      0x88,
      0x0e,
      0x8c,
      0x68,
      0x74,
      0x34,
      0x17,
      0x0f,
      0x64,
      0x76,
      0x60,
      0x5b,
      0x8f,
      0xe4,
      0xae,
      0xb9,
      0xa2,
      0x86,
      0x32,
      0xc7,
      0x99,
      0x5c,
      0xf3,
      0xba,
      0x83,
      0x1d,
      0x97,
      0x63,
      0x01,
      0x00,
      0x00,
      0x01,
      0x6b
    ]).buffer;
    assert(
      arrayBufferEquals(rawAuthnrData, expectedAuthnrRawData),
      "correct rawAuthnrData"
    );
  });

  it("throws if response is not an object");
});

const crypto = require("crypto");

describe("validate signature", function() {
  function abToBuf(ab) {
    return Buffer.from(new Uint8Array(ab));
  }

  it("works", function() {
    var sig = h.lib.assertionResponse.response.signature;
    var pk = h.lib.assnPublicKey;
    var authnrData = h.lib.assertionResponse.response.authenticatorData;
    var clientData = h.lib.assertionResponse.response.clientDataJSON;

    const hash = crypto.createHash("sha256");
    hash.update(abToBuf(clientData));
    var clientDataHashBuf = hash.digest();
    var clientDataHash = new Uint8Array(clientDataHashBuf).buffer;

    const verify = crypto.createVerify("SHA256");
    verify.write(abToBuf(authnrData));
    verify.write(abToBuf(clientDataHash));
    verify.end();
    verify.verify(pk, abToBuf(sig));
  });
});
