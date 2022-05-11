// Import base asserts
import { assertEquals, assertRejects, assertStrictEquals, assertThrows } from "std/testing/asserts.ts";

// Inject mocha equivalents in global
import { afterEach, beforeEach, describe, it } from "test_suite";
window.afterEach = afterEach;
window.beforeEach = beforeEach;
window.describe = describe;

// Do nothing when b (fn) is undefined
// Pass empty function as "done()" for now, tests are run in node anyways
window.it = Object.assign(
	(a, b, c, d) => {
		if (typeof b !== "undefined") {
			it(
				a,
				async () => {
					await b(() => {});
				},
				c,
				d,
			);
		}
	},
	{
		skip: () => {},
	},
);

// Generate chai-style asserts
const assert = Object.assign(() => {}, {
	equal: (a, b) => assertEquals(a, b),
	deepEqual: (a, b) => assertEquals(a, b),
	strictEqual: (a, b) => assertEquals(a, b),
	instanceOf: (a, b) => assertEquals(true, a instanceof b),
	typeOf: (a, b) => assertEqual(a, typeof b),
	ok: (a) => assertEqual(true, a),
	throws: (a, b, c, d) => assertThrows(a, b, c, d),
	isRejected: async (a, b, c, d) => { return await assertRejects(() => a, b, c, d); },
	isFunction: (a) => assertEquals(typeof a, "function"),
	isTrue: (a) => assertEquals(true, a),
	isObject: (a) => assertEquals(typeof a, "object"),
	isNumber: (a) => assertEquals(typeof a, "number"),
	isString: (a) => assertEquals(typeof a, "string"),
	isArray: (a) => assertEquals(Array.isArray(a), true),
	isBoolean: (a) => assertEquals(typeof a, "boolean"),
	isUndefined: (a) => assertEquals(typeof a, "undefined"),
	isNull: (a) => assertStrictEquals(a, null),
	isFalse: (a) => assertStrictEquals(a, false),
	isDefined: (a) => assertEquals(typeof a !== "undefined", true),
});

const use = () => {};

export { assert, use };
