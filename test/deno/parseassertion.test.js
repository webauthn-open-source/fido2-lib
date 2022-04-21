// Testing lib
import { assertEquals } from "./common/deps.js";

// Helpers
import { abEqual, abToBuf, appendBuffer } from "../../lib/common/utils.js";
import * as h from "../helpers/fido2-helpers.js";
import { ToolBox } from "../../lib/deno/toolbox.js";

// Test subject
import * as parser from "../../lib/common/parser.js";

Deno.test("parser is object", function () {
  assertEquals(typeof parser, "object");
});

Deno.test("parses assertion correctly", async function () {
  var ret = await parser.parseAuthnrAssertionResponse(
    h.lib.assertionResponse,
  );
  assertEquals(ret instanceof Map, true);
  assertEquals(ret.size, 6);
  // rpid
  var rpIdHash = ret.get("rpIdHash");
  assertEquals(rpIdHash instanceof ArrayBuffer, true);
  var expectedRpIdHash = new Uint8Array([
    0x49,
    0x96,
    0x0D,
    0xE5,
    0x88,
    0x0E,
    0x8C,
    0x68,
    0x74,
    0x34,
    0x17,
    0x0F,
    0x64,
    0x76,
    0x60,
    0x5B,
    0x8F,
    0xE4,
    0xAE,
    0xB9,
    0xA2,
    0x86,
    0x32,
    0xC7,
    0x99,
    0x5C,
    0xF3,
    0xBA,
    0x83,
    0x1D,
    0x97,
    0x63,
  ]).buffer;
  assertEquals(abEqual(rpIdHash, expectedRpIdHash), true);
  // flags
  var flags = ret.get("flags");
  assertEquals(flags instanceof Set, true);
  assertEquals(flags.size, 1);
  assertEquals(flags.has("UP"), true);
  // counter
  assertEquals(ret.get("counter"), 363);
  // sig
  var sig = ret.get("sig");
  assertEquals(sig instanceof ArrayBuffer, true);
  var expectedSig = new Uint8Array([
    0x30,
    0x46,
    0x02,
    0x21,
    0x00,
    0xFA,
    0x74,
    0x5D,
    0xC1,
    0xD1,
    0x9A,
    0x1A,
    0x2C,
    0x0D,
    0x2B,
    0xEF,
    0xCA,
    0x32,
    0x45,
    0xDA,
    0x0C,
    0x35,
    0x1D,
    0x1B,
    0x37,
    0xDD,
    0xD9,
    0x8B,
    0x87,
    0x05,
    0xFF,
    0xBE,
    0x61,
    0x14,
    0x01,
    0xFA,
    0xA5,
    0x02,
    0x21,
    0x00,
    0xB6,
    0x34,
    0x50,
    0x8B,
    0x2B,
    0x87,
    0x4D,
    0xEE,
    0xFD,
    0xFE,
    0x32,
    0x28,
    0xEC,
    0x33,
    0xC0,
    0x3E,
    0x82,
    0x8F,
    0x7F,
    0xC6,
    0x58,
    0xB2,
    0x62,
    0x8A,
    0x84,
    0xD3,
    0xF7,
    0x9F,
    0x34,
    0xB3,
    0x56,
    0xBB,
  ]).buffer;
  assertEquals(abEqual(sig, expectedSig), true);
  // userHandle
  var userHandle = ret.get("userHandle");
  assertEquals(typeof userHandle, "undefined");
  // authRawData
  var rawAuthnrData = ret.get("rawAuthnrData");
  assertEquals(rawAuthnrData instanceof ArrayBuffer, true);
  var expectedAuthnrRawData = new Uint8Array([
    0x49,
    0x96,
    0x0D,
    0xE5,
    0x88,
    0x0E,
    0x8C,
    0x68,
    0x74,
    0x34,
    0x17,
    0x0F,
    0x64,
    0x76,
    0x60,
    0x5B,
    0x8F,
    0xE4,
    0xAE,
    0xB9,
    0xA2,
    0x86,
    0x32,
    0xC7,
    0x99,
    0x5C,
    0xF3,
    0xBA,
    0x83,
    0x1D,
    0x97,
    0x63,
    0x01,
    0x00,
    0x00,
    0x01,
    0x6B,
  ]).buffer;
  assertEquals(abEqual(rawAuthnrData, expectedAuthnrRawData), true);
});

Deno.test("works", async function () {
  var sig = h.lib.assertionResponse.response.signature;
  var pk = h.lib.assnPublicKey;
  var authnrData = h.lib.assertionResponse.response.authenticatorData;
  var clientData = h.lib.assertionResponse.response.clientDataJSON;

  const hash = await ToolBox.hashDigest(clientData);
  var clientDataHash = new Uint8Array(hash).buffer;

  const res = await ToolBox.verifySignature(
    pk,
    abToBuf(sig),
    appendBuffer(abToBuf(authnrData), abToBuf(clientDataHash)),
  );
  assertEquals(res, true);
});
