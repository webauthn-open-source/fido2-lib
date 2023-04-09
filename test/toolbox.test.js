// Testing lib
import * as chai from "chai";

// Helpers
import { tools } from "../lib/main.js";
const assert = chai.assert;
const {
	checkOrigin,
	checkRpId,
	checkUrl,
	checkDomainOrUrl,
} = tools;

describe("toolbox", function() {
	describe("checkOrigin", function() {
		it("throws on invalid eTLD+1", function() {
			assert.throws(
				() => {
					checkOrigin("https://s3.dualstack.eu-west-1.amazonaws.com");
				},
				Error,
				"origin is not a valid eTLD+1",
			);
		});

		it("throws on undefined origin", function() {
			assert.throws(
				() => {
					checkOrigin(undefined);
				},
				Error,
				"Empty Origin",
			);
		});


		it("accepts android FacetID", function() {
			const androidFacetId = "android:apk-key-hash:addf120b430021c36c232c99ef8d926aea2acd6b";
			const androidOrigin = checkOrigin(androidFacetId);
			assert.strictEqual(androidFacetId, androidOrigin);
		});

		it("accepts ios FacetID", function() {
			const iOSFacetId = "ios:bundle-id:addf120b430021c36c232c99ef8d926aea2acd6b";
			const iOSOrigin = checkOrigin(iOSFacetId);
			assert.strictEqual(iOSFacetId, iOSOrigin);
		});

		it("throws invalid url", function() {
			assert.throws(
				() => {
					checkOrigin("qwertyasdf");
				},
				Error,
				"Invalid URL",
			);
		});

		it("allows localhost", function() {
			const ret = checkOrigin("https://localhost:8443");
			assert.strictEqual(ret, "https://localhost:8443");
		});

		it("throws on non-https", function() {
			assert.throws(
				() => {
					checkOrigin("http://webauthn.bin.coffee:8080");
				},
				Error,
				"origin should be https",
			);
		});

		it.skip("allows international domain", function() {
			const ret = checkOrigin("https://www.食狮.公司.cn:8080");
			assert.isTrue(ret);
		});

		it("throws error if origin contains URL path");
		it("returns true when origin contains port 443");
		it("throws when origin is just a domain");
		it("rejects invalid eTLD+1 international domain");
		it("allows punycoded domain");
		it("correctly compares punycoded and international domain");
	});

	describe("checkRpId", function() {
		it("throws on invalid eTLD+1", function() {
			assert.throws(
				() => {
					checkRpId("test");
				},
				Error,
				"rpId is not a valid eTLD+1/url",
			);
		});

		it("throws on undefined rpId", function() {
			assert.throws(
				() => {
					checkRpId(undefined);
				},
				Error,
				"rpId must be a string",
			);
		});

		it("allows localhost", function() {
			const ret = checkRpId("test.localhost");
			assert.strictEqual(ret, "test.localhost");
		});

		it("allows fully qualified urls", function() {
			const ret = checkRpId("https://test.com");
			assert.strictEqual(ret, "https://test.com");
		});

		it("rejects http urls", function() {
			assert.throws(
				() => {
					checkRpId("http://test.com");
				},
				Error,
				"rpId should be https",
			);
		});

		it("rejects urls that have pathes", function() {
			assert.throws(
				() => {
					checkRpId("https://test.com/foo/bar");
				},
				Error,
				"rpId should not include path in url",
			);

			assert.throws(
				() => {
					checkRpId("https://test.com/");
				},
				Error,
				"rpId should not include path in url",
			);
		});
	});

	describe("checkUrl", () => {
		it("exists", () => {
			assert.isFunction(checkUrl);
		});

		it("should throw when name param is not specified", () => {
			assert.throws(
				() => {
					checkUrl("https://test.com/");
				},
				Error,
				"name not specified in checkUrl",
			);
		});

		it("should throw when value is not string", () => {
			assert.throws(
				() => {
					checkUrl(123, "test");
				},
				Error,
				"test must be a string",
			);
		});

		it("should throw when value is not a valid url", () => {
			assert.throws(
				() => {
					checkUrl("test.com", "test");
				},
				Error,
				"test is not a valid eTLD+1/url",
			);
		});

		it("should throw when url is not http", () => {
			assert.throws(
				() => {
					checkUrl("file:///home/myuser/files/test.html", "test");
				},
				Error,
				"test must be http protocol",
			);
		});

		it("should throw when url is not https", () => {
			assert.throws(
				() => {
					checkUrl("http://www.test.com", "test");
				},
				Error,
				"test should be https",
			);
		});

		it("should throw when url has path", () => {
			assert.throws(
				() => {
					checkUrl("https://www.test.com/", "test");
				},
				Error,
				"test should not include path in url",
			);

			assert.throws(
				() => {
					checkUrl("https://www.test.com/foo/bar", "test");
				},
				Error,
				"test should not include path in url",
			);
		});

		it("should throw when url has hash", () => {
			assert.throws(
				() => {
					checkUrl("https://www.test.com#foo", "test");
				},
				Error,
				"test should not include hash in url",
			);
		});

		it("should throw when url has credentials", () => {
			assert.throws(
				() => {
					checkUrl("https://user:pass@www.test.com", "test");
				},
				Error,
				"test should not include credentials in url",
			);
		});

		it("should throw when url has query string", () => {
			assert.throws(
				() => {
					checkUrl("https://www.test.com?foo=bar", "test");
				},
				Error,
				"test should not include query string in url",
			);
		});

		it("should return value when value is valid url", () => {
			const ret = checkUrl("https://www.test.com", "test");
			assert.strictEqual(ret, "https://www.test.com");
		});

		it("should allow http when specified in rules", () => {
			const ret = checkUrl("http://www.test.com", "test", {
				allowHttp: true,
			});
			assert.strictEqual(ret, "http://www.test.com");
		});

		it("should allow path when specified in rules", () => {
			let ret = checkUrl("https://www.test.com/", "test", {
				allowPath: true,
			});
			assert.strictEqual(ret, "https://www.test.com/");

			ret = checkUrl("https://www.test.com/foo/bar", "test", {
				allowPath: true,
			});
			assert.strictEqual(ret, "https://www.test.com/foo/bar");
		});

		it("should allow hash when specified in rules", () => {
			const ret = checkUrl("https://www.test.com#foo", "test", {
				allowHash: true,
			});
			assert.strictEqual(ret, "https://www.test.com#foo");
		});

		it("should allow credentials when specified in rules", () => {
			const ret = checkUrl("https://user:pass@www.test.com", "test", {
				allowCred: true,
			});
			assert.strictEqual(ret, "https://user:pass@www.test.com");
		});

		it("should allow query string when specified in rules", () => {
			const ret = checkUrl("https://www.test.com?foo=bar", "test", {
				allowQuery: true,
			});
			assert.strictEqual(ret, "https://www.test.com?foo=bar");
		});
	});

	describe("checkDomainOrUrl", () => {
		it("exists", () => {
			assert.isFunction(checkDomainOrUrl);
		});

		it("should throw when name param is not specified", () => {
			assert.throws(
				() => {
					checkDomainOrUrl("https://test.com/");
				},
				Error,
				"name not specified in checkDomainOrUrl",
			);
		});

		it("should throw when value is not string", () => {
			assert.throws(
				() => {
					checkDomainOrUrl(123, "test");
				},
				Error,
				"test must be a string",
			);
		});

		it("should throw when value is not a valid domain or url", () => {
			assert.throws(
				() => {
					checkDomainOrUrl("test", "test");
				},
				Error,
				"test is not a valid eTLD+1/url",
			);
		});

		it("should return value when value is valid domain", () => {
			const ret = checkDomainOrUrl("test.com", "test");
			assert.strictEqual(ret, "test.com");
		});

		it("should return value when value is valid url", () => {
			const ret = checkDomainOrUrl("https://www.test.com", "test");
			assert.strictEqual(ret, "https://www.test.com");
		});
	});
});
