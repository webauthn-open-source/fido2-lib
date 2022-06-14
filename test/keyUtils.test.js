// Testing lib
import { assert, use } from "chai";
import * as chaiAsPromised from "chai-as-promised";

// Helpers
import { PublicKey, coseAlgToHashStr, coseAlgToStr, tools } from "../lib/main.js";

import * as h from "./helpers/fido2-helpers.js";
import { cosePublicKey } from "./fixtures/cosePublicKey.js";

import { rsaPublicKey } from "./fixtures/rsaPublicKey.js";

use(chaiAsPromised.default);

describe("key utils", function() {
	describe("PublicKey", function() {
		describe("constructor", function() {
			let key;
			it("can create empty key", function() {
				key = new PublicKey();
				assert.instanceOf(key, PublicKey);
			});

			it("throws if trying to export empty key", () => {
				return assert.isRejected(key.toPem(), Error, "Key data not available");
			});

			it("throws if invalid argument is passed as key", function() {
				assert.throws(
					() => {
						const k = new PublicKey();
						k.fromCryptoKey({ foo: "bar" });
					},
					TypeError,
					"Invalid argument passed to fromCryptoKey, should be instance of CryptoKey with type public",
				);
			});

			it("throws if trying to get non existant key", function() {
				assert.throws(
					() => {
						const k = new PublicKey();
						k.getKey();
					},
					Error,
					"Key data not available",
				);
			});

			describe("rsa spki (base64 part only only)", function() {
				const k = new PublicKey();
				it("throws", () => {
					return assert.isRejected(
						k.fromPem(cosePublicKey.examplePemBase64Only),
						Error,
						"Supplied key is not in PEM format",
					);
				});
			});

			describe("rsa spki 2048 bits", function() {
				const k = new PublicKey();
				it("can import", async () => {
					await k.fromPem(rsaPublicKey.pem2048);
				});
			});

			describe("rsa spki 2048 bits without trailing newline", function() {
				const k = new PublicKey();
				it("can import", async () => {
					await k.fromPem(rsaPublicKey.pem2048noTrailingN);
				});
			});

			describe("rsa spki 4096 bits", function() {
				const k = new PublicKey();
				it("can import", async () => {
					await k.fromPem(rsaPublicKey.pem4096, "SHA-384");
				});

				it("has key data", () => {
					assert.isDefined(k.getKey());
				});

				it("correctly identifies algorithm as RSASSA-PKCS1-v1_5 with and uses overriden hash algorithm SHA-384", () => {
					const alg = k.getAlgorithm();
					assert.equal(alg.name, "RSASSA-PKCS1-v1_5");
					assert.equal(alg.hash.name, "SHA-384");
				});
			});

			describe("rsa spki", function() {
				const k = new PublicKey();
				it("can import", async () => {
					await k.fromPem(h.lib.assnPublicKey);
				});
				it("has key data", () => {
					assert.isDefined(k.getKey());
				});
				it("correctly identifies algorithm as EDCDSA P-256", () => {
					const alg = k.getAlgorithm();
					assert.instanceOf(alg, Object);
					assert.equal(alg.name, "ECDSA");
					assert.equal(alg.namedCurve, "P-256");
				});
				it("can re-export to identical PEM (using original pem)", async () => {
					const pem = await k.toPem();
					assert.equal(pem, h.lib.assnPublicKey);
				});
				it("throws on exporting to jwk", () => {
					assert.throws(
						() => {
							k.toJwk();
						},
						Error,
						"No usable key information available",
					);
				});

				it("throws on exporting to cose", () => {
					assert.throws(
						() => {
							k.toCose();
						},
						Error,
						"No usable key information available",
					);
				});
			});

			describe("can import ecdsa spki", function() {
				const k = new PublicKey();
				it("can import", async () => {
					await k.fromPem(h.lib.assnPublicKeyWindowsHello);
				});
				it("has key data", () => {
					assert.isDefined(k.getKey());
				});
				it("correctly identifies algorithm as RSASSA-PKCS1-v1_5 with and defaults to SHA-256 signature hash algorithm", () => {
					const alg = k.getAlgorithm();
					assert.equal(alg.name, "RSASSA-PKCS1-v1_5");
					assert.equal(alg.hash.name, "SHA-256");
				});
				it("can re-export to identical PEM (using original pem)", async () => {
					const pem = await k.toPem();
					assert.equal(pem, h.lib.assnPublicKeyWindowsHello);
				});
			});

			describe("can import cose public key", function() {
				const k = new PublicKey();
				it("can import", async () => {
					await k.fromCose(tools.base64.toArrayBuffer(cosePublicKey.exampleBase64));
				});
				it("has key data", () => {
					assert.isDefined(k.getKey());
				});
				it("correctly identifies algorithm as ECDSA P-256 with SHA-256 hash", () => {
					const alg = k.getAlgorithm();
					assert.equal(alg.name, "ECDSA");
					assert.equal(alg.hash.name, "SHA-256");
					assert.equal(alg.namedCurve, "P-256");
				});
				it("can export to jwk", () => {
					const jwk = k.toJwk();
					assert.equal(jwk.alg, "ES256");
					assert.equal(jwk.crv, "P-256");
				});
				it("can export to PEM", async () => {
					const pem = await k.toPem();
					assert.equal(pem, cosePublicKey.examplePem);
				});
			});

			describe("throws on invalid cose data 1", function() {
				const k = new PublicKey();
				return assert.isRejected(
					k.fromCose(tools.base64.toArrayBuffer(cosePublicKey.exampleInvalidBase64)),
					Error,
					"couldn't parse authenticator.authData.attestationData CBOR: Error:",
				);
			});
		});
	});
	describe("coseAlgToHashStr", () => {
		it("Returns SHA1 for -65535", () => {
			assert.equal("SHA-1", coseAlgToHashStr(-65535));
		});
		it("Returns SHA1 for RSASSA-PKCS1-v1_5_w_SHA384", () => {
			assert.equal("SHA-384", coseAlgToHashStr("RSASSA-PKCS1-v1_5_w_SHA384"));
		});
		it("Throws on undef", () => {
			assert.throws(() => {
				coseAlgToHashStr();
			}, Error, "'alg' is not a string or a valid COSE algorithm number");
		});		
		it("Throws on invalid data type", () => {
			assert.throws(() => {
				coseAlgToHashStr(new Date());
			}, Error, "'alg' is not a string or a valid COSE algorithm number");
		});
		it("Throws on invalid numeric id", () => {
			assert.throws(() => {
				coseAlgToHashStr(-3123123);
			}, Error, "'alg' is not a valid COSE algorithm number");
		});
		it("Throws on invalid string id", () => {
			assert.throws(() => {
				coseAlgToHashStr("FOOBAR");
			}, Error, "'alg' is not a valid COSE algorithm");
		});
	});
	describe("coseAlgToStr", () => {
		it("Returns SHA1 for -65535", () => {
			assert.equal("RSASSA-PKCS1-v1_5_w_SHA1", coseAlgToStr(-65535));
		});
		it("Throws on string representation", () => {
			assert.throws(() => {
				assert.equal("SHA-384", coseAlgToStr("RSASSA-PKCS1-v1_5_w_SHA384"));
			}, Error, "expected 'alg' to be a number, got: RSASSA-PKCS1-v1_5_w_SHA384");
		});
		it("Throws on undef", () => {
			assert.throws(() => {
				coseAlgToStr();
			}, Error, "expected 'alg' to be a number, got: undefined");
		});		
		it("Throws on invalid data type", () => {
			assert.throws(() => {
				coseAlgToStr(null);
			}, Error, "expected 'alg' to be a number, got: null");
		});
		it("Throws on invalid numeric id", () => {
			assert.throws(() => {
				coseAlgToStr(-3123123);
			}, Error, "'alg' is not a valid COSE algorithm number");
		});
	});
});
