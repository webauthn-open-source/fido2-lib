// Testing lib
import { assertEquals } from "./common/deps.js";

// Helpers
import { ToolBox } from "../../lib/deno/toolbox.js";

// Test subject
import * as parser from "../../lib/common/parser.js";

Deno.test("Dummy test", async () => {
  let exp = {
    origin: "https://webauthn.bin.coffee",
    challenge:
      "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg",
  };
  let ret = parser.parseExpectations(exp, ToolBox);
  assertEquals(ret instanceof Map, true);
  assertEquals(ret.size, 2);
  assertEquals(ret.get("origin"), exp.origin);
  assertEquals(ret.get("challenge"), exp.challenge);
});
Deno.test("coerces Array challenge to base64url", function () {
  let exp = {
    origin: "https://webauthn.bin.coffee",
    challenge: [
      0xe0,
      0x14,
      0xb5,
      0x60,
      0x92,
      0x91,
      0x09,
      0xe0,
      0x95,
      0xa0,
      0xb7,
      0x5f,
      0x1b,
      0xf6,
      0xfa,
      0xe8,
      0x1b,
      0x92,
      0x43,
      0xe2,
      0x36,
      0x9f,
      0x7e,
      0x16,
      0xb0,
      0xb1,
      0x6f,
      0xcb,
      0xad,
      0x9f,
      0xa4,
      0x85,
      0x45,
      0x8e,
      0xb9,
      0xb7,
      0xdb,
      0xfb,
      0x45,
      0x45,
      0x08,
      0xb1,
      0x5f,
      0xd5,
      0x3c,
      0x10,
      0x15,
      0x53,
      0xae,
      0x24,
      0xe4,
      0xad,
      0xe0,
      0x29,
      0xfb,
      0x59,
      0xc3,
      0xbd,
      0x86,
      0xe8,
      0x44,
      0xaf,
      0x56,
      0x16,
    ],
  };
  let base64UrlChallenge =
    "4BS1YJKRCeCVoLdfG_b66BuSQ-I2n34WsLFvy62fpIVFjrm32_tFRQixX9U8EBVTriTkreAp-1nDvYboRK9WFg";
  let ret = parser.parseExpectations(exp, ToolBox);
  assertEquals(ret instanceof Map, true);
  assertEquals(ret.size, 2);
  assertEquals(ret.get("origin"), exp.origin);
  assertEquals(ret.get("challenge"), base64UrlChallenge);
});
