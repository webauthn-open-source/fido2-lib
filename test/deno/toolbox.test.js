// Testing lib
import { assertEquals, assertThrows } from "./common/deps.js";

// Helpers
import { base64 } from "../../lib/common/utils.js";

// Test subject
import { ToolBox } from "../../lib/deno/toolbox.js";

Deno.test("randomValues", async () => {
  const res32bytes = ToolBox.randomValues(32);
  assertEquals(res32bytes.length, 32);
});

Deno.test("checkUrl should throw on non public suffix", async () => {
  assertThrows(() => {
    ToolBox.checkUrl("asdf.ffsf");
  }, "origin is not a valid eTLD+1");
});

Deno.test("checkOrigin should throw on non public suffix", async () => {
  assertThrows(() => {
    ToolBox.checkOrigin("asdf.ffsf");
  }, "origin is not a valid eTLD+1");
});

Deno.test("hash", async () => {
  let hash = base64.fromArrayBuffer(
    await ToolBox.hashDigest(new TextEncoder().encode("Asd")),
  );
  assertEquals(hash, "I/N27AiwtvQxCPYb+qls0Wjz2sTl5cAhhaEHrZz/xdE=");
});
