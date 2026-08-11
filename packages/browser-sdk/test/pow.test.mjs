import test from "node:test";
import assert from "node:assert/strict";
import { leadingZeroBits } from "../dist/pow.js";

test("leadingZeroBits counts prefix bits", () => {
  assert.equal(leadingZeroBits(new Uint8Array([0x00, 0x0f])), 12);
  assert.equal(leadingZeroBits(new Uint8Array([0x80])), 0);
  assert.equal(leadingZeroBits(new Uint8Array([0x40])), 1);
});
