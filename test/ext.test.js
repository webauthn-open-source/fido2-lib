// Testing lib
import * as chai from "chai";

// Helpers
import { Stub } from "./helpers/stub.js";
import { Fido2Lib } from "../lib/main.js";

const assert = chai.assert;

describe("Fido2Lib extensions", function() {
	afterEach(function() {
		Fido2Lib.deleteAllExtensions();
	});

	it("exist", function() {
		assert.isFunction(Fido2Lib.addExtension);
		assert.isFunction(Fido2Lib.deleteAllExtensions);
		assert.isFunction(Fido2Lib.parseExtensionResult);
		assert.isFunction(Fido2Lib.validateExtensionResult);
		const mc = new Fido2Lib();
		assert.isFunction(mc.generateExtensionOptions);
		assert.isFunction(mc.enableExtension);
		assert.isFunction(mc.disableExtension);
		assert.isFunction(mc.setExtensionOptions);
	});

	describe("addExtension", function() {
		function fn() {}

		it("throws if extName is not a string", function() {
			assert.throws(function() {
				Fido2Lib.addExtension(undefined, fn, fn, fn);
			}, Error, "expected 'extName' to be String, got: undefined");
		});

		it("throws if optionGeneratorFn isn't a function", function() {
			assert.throws(function() {
				Fido2Lib.addExtension("test", undefined, fn, fn);
			}, Error, "expected 'optionGeneratorFn' to be a Function, got: undefined");
		});

		it("throws if resultParserFn isn't a function", function() {
			assert.throws(function() {
				Fido2Lib.addExtension("test", fn, undefined, fn);
			}, Error, "expected 'resultParserFn' to be a Function, got: undefined");
		});

		it("throws if resultValidatorFn isn't a function", function() {
			assert.throws(function() {
				Fido2Lib.addExtension("test", fn, fn, undefined);
			}, Error, "expected 'resultValidatorFn' to be a Function, got: undefined");
		});

		it("adds the new extension", function() {
			Fido2Lib.addExtension("test", fn, fn, fn);
		});

		it("throws if name is already set", function() {
			Fido2Lib.addExtension("test", fn, fn, fn);

			assert.throws(function() {
				Fido2Lib.addExtension("test", fn, fn, fn);
			}, Error, "the extension 'test' has already been added");
		});
	});

	describe("generateExtensionOptions", function() {
		let mc;

		function fn() {}

		beforeEach(function() {
			mc = new Fido2Lib();
		});

		it("throws if extName isn't a string", function() {
			assert.throws(
				function() {
					mc.generateExtensionOptions(undefined, "attestation");
				},
				Error,
				"expected 'extName' to be String, got: undefined",
			);
		});

		it("throws if extName isn't found", function() {
			assert.throws(
				function() {
					mc.generateExtensionOptions("test", "attestation");
				},
				Error,
				"valid extension for 'test' not found",
			);
		});

		it("throws if type isn't 'attestation' or 'assertion'", function() {
			assert.throws(
				function() {
					mc.generateExtensionOptions("test", "foo");
				},
				Error,
				"expected 'type' to be 'attestation' or 'assertion', got: foo",
			);
		});

		it("can generate for attestation", function(done) {
			function generateFn(name, type, options) {
				assert.strictEqual(name, "test");
				assert.strictEqual(type, "attestation");
				assert.isUndefined(options);
				done();
			}

			Fido2Lib.addExtension("test", generateFn, fn, fn);
			mc.generateExtensionOptions("test", "attestation");
		});

		it("can generate for assertion", function(done) {
			function generateFn(name, type, options) {
				assert.strictEqual(name, "test");
				assert.strictEqual(type, "assertion");
				assert.isUndefined(options);
				done();
			}

			Fido2Lib.addExtension("test", generateFn, fn, fn);
			mc.generateExtensionOptions("test", "assertion");
		});

		it("passes through options", function(done) {
			const opts = {
				foo: "bar",
			};

			function generateFn(name, type, options) {
				assert.strictEqual(name, "test");
				assert.strictEqual(type, "assertion");
				assert.strictEqual(options, opts);
				done();
			}

			Fido2Lib.addExtension("test", generateFn, fn, fn);
			mc.generateExtensionOptions("test", "assertion", opts);
		});
	});

	describe("parseExtensionResult", function() {
		it("throws if extName isn't a string");
		it("throws if extName isn't found");
		it("throws if return value isn't valid");
		it("returns parsed value");
	});

	describe("validateExtensionResult", function() {
		it("throws if extName isn't a string");
		it("throws if extName isn't found");
		it("throws if return value isn't true");
		it("sets audit info");
	});

	describe("enableExtension", function() {
		let mc;
		function fn() {}
		beforeEach(function() {
			mc = new Fido2Lib();
		});

		it("throws if extName isn't a string", function() {
			assert.throws(
				function() {
					mc.enableExtension(undefined);
				},
				Error,
				"expected 'extName' to be String, got: undefined",
			);
		});

		it("throws if extName isn't found", function() {
			assert.throws(
				function() {
					mc.enableExtension("test");
				},
				Error,
				"valid extension for 'test' not found",
			);
		});

		it("is disabled by default", function() {
			assert.isFalse(mc.extSet.has("test"));
			assert.isFalse(mc.extSet.has("test2"));
			Fido2Lib.addExtension("test", fn, fn, fn);
			Fido2Lib.addExtension("test2", fn, fn, fn);
			assert.isFalse(mc.extSet.has("test"));
			assert.isFalse(mc.extSet.has("test2"));
			mc = new Fido2Lib();
			assert.isFalse(mc.extSet.has("test"));
			assert.isFalse(mc.extSet.has("test2"));
		});

		it("sets extension to true", function() {
			Fido2Lib.addExtension("test", fn, fn, fn);
			mc = new Fido2Lib();
			assert.isFalse(mc.extSet.has("test"));
			mc.enableExtension("test");
			assert.isTrue(mc.extSet.has("test"));
		});
	});

	describe("disableExtension", function() {
		let mc;
		function fn() {}
		beforeEach(function() {
			mc = new Fido2Lib();
		});

		it("throws if extName isn't a string", function() {
			assert.throws(
				function() {
					mc.disableExtension(undefined);
				},
				Error,
				"expected 'extName' to be String, got: undefined",
			);
		});

		it("throws if extName isn't found", function() {
			assert.throws(
				function() {
					mc.disableExtension("test");
				},
				Error,
				"valid extension for 'test' not found",
			);
		});

		it("sets extension to false", function() {
			Fido2Lib.addExtension("test", fn, fn, fn);
			mc = new Fido2Lib();
			assert.isFalse(mc.extSet.has("test"));
			mc.enableExtension("test");
			assert.isTrue(mc.extSet.has("test"));
			mc.disableExtension("test");
			assert.isFalse(mc.extSet.has("test"));
		});
	});

	describe("setExtensionOptions", function() {
		let mc;
		function fn() {}
		beforeEach(function() {
			mc = new Fido2Lib();
		});

		it("throws if extName isn't a string", function() {
			assert.throws(
				function() {
					mc.setExtensionOptions(undefined);
				},
				Error,
				"expected 'extName' to be String, got: undefined",
			);
		});

		it("throws if extName isn't found", function() {
			assert.throws(
				function() {
					mc.setExtensionOptions("test");
				},
				Error,
				"valid extension for 'test' not found",
			);
		});

		it("sets options", function() {
			const opts = {
				foo: "bar",
			};

			Fido2Lib.addExtension("test", fn, fn, fn);
			mc.setExtensionOptions("test", opts);
			assert.isTrue(mc.extOptMap.has("test"));
			assert.strictEqual(mc.extOptMap.get("test"), opts);
		});
	});

	describe("attestationOptions", function() {
		let mc;
		function fn() {}
		beforeEach(function() {
			mc = new Fido2Lib();
		});

		it("calls generator", function() {
			const genSpy = new Stub();
			const extVal = {
				beer: "good",
			};
			genSpy.return(extVal);

			Fido2Lib.addExtension("test", genSpy.stub(),fn, fn);
			mc.enableExtension("test");
			return mc.attestationOptions()
				.then((opts) => {
					assert.isObject(opts.extensions);
					assert.isObject(opts.extensions.test);
					assert.strictEqual(opts.extensions.test, extVal);
				});
		});

		it("calls all generators", function() {
			const genSpy1 = new Stub();
			const extVal1 = {
				beer: "good",
			};
			genSpy1.return(extVal1);
			const genSpy2 = new Stub();
			const extVal2 = false;
			genSpy2.return(extVal2);

			Fido2Lib.addExtension("test1", genSpy1.stub(),fn, fn);
			Fido2Lib.addExtension("test2", genSpy2.stub(),fn, fn);
			mc.enableExtension("test1");
			mc.enableExtension("test2");
			return mc.attestationOptions()
				.then((opts) => {
					assert.isObject(opts.extensions);
					assert.isObject(opts.extensions.test1);
					assert.strictEqual(opts.extensions.test1, extVal1);
					assert.isFalse(opts.extensions.test2);
				});
		});

		it("calls all enabled generators", function() {
			const genSpy1 = new Stub();
			const extVal1 = {
				beer: "good",
			};
			genSpy1.return(extVal1);
			const genSpy2 = new Stub();
			const extVal2 = false;
			genSpy2.return(extVal2);

			Fido2Lib.addExtension("test1", genSpy1.stub(),fn, fn);
			Fido2Lib.addExtension("test2", genSpy2.stub(),fn, fn);
			mc.enableExtension("test1");
			mc.disableExtension("test2");
			return mc.attestationOptions()
				.then((opts) => {
					assert.isObject(opts.extensions);
					assert.isObject(opts.extensions.test1);
					assert.strictEqual(opts.extensions.test1, extVal1);
					assert.isUndefined(opts.extensions.test2);
				});
		});

		it("passes through default options", function() {
			const genSpy1 = new Stub();
			const extVal1 = {
				beer: "good",
			};
			const extOpt1 = {
				foo: "bar",
			};
			genSpy1.return(extVal1);
			const genSpy2 = new Stub();
			const extVal2 = false;
			const extOpt2 = null;
			genSpy2.return(extVal2);

			Fido2Lib.addExtension("test1", genSpy1.stub(),fn, fn);
			Fido2Lib.addExtension("test2", genSpy2.stub(),fn, fn);
			mc.enableExtension("test1");
			mc.setExtensionOptions("test1", extOpt1);
			mc.enableExtension("test2");
			mc.setExtensionOptions("test2", extOpt2);
			return mc.attestationOptions()
				.then((opts) => {
					assert.isObject(opts.extensions);
					assert.isObject(opts.extensions.test1);
					assert.strictEqual(opts.extensions.test1, extVal1);
					assert.isFalse(opts.extensions.test2);
					assert.isTrue(genSpy1.calledWithExactly("test1", "attestation", extOpt1));
					assert.isTrue(genSpy2.calledWithExactly("test2", "attestation", extOpt2));
				});
		});

		it("passes through passed-in options", function() {
			const genSpy1 = new Stub();
			const extVal1 = {
				beer: "good",
			};
			const extOpt1 = {
				foo: "bar",
			};
			genSpy1.return(extVal1);
			const genSpy2 = new Stub();
			const extVal2 = false;
			const extOpt2 = null;
			genSpy2.return(extVal2);

			Fido2Lib.addExtension("test1", genSpy1.stub(),fn, fn);
			Fido2Lib.addExtension("test2", genSpy2.stub(),fn, fn);
			mc.enableExtension("test1");
			mc.enableExtension("test2");
			return mc.attestationOptions({
				extensionOptions: {
					test1: extOpt1,
					test2: extOpt2,
				},
			})
				.then((opts) => {
					assert.isObject(opts.extensions);
					assert.isObject(opts.extensions.test1);
					assert.strictEqual(opts.extensions.test1, extVal1);
					assert.isFalse(opts.extensions.test2);
					assert.isTrue(genSpy1.calledWithExactly("test1", "attestation", extOpt1));
					assert.isTrue(genSpy2.calledWithExactly("test2", "attestation", extOpt2));
				});
		});
	});

	describe("assertionOptions", function() {
		let mc;
		function fn() {}
		beforeEach(function() {
			mc = new Fido2Lib();
		});

		it("calls generator", function() {
			const genSpy = new Stub();
			const extVal = {
				beer: "good",
			};
			genSpy.return(extVal);

			Fido2Lib.addExtension("test", genSpy.stub(),fn, fn);
			mc.enableExtension("test");
			return mc.assertionOptions()
				.then((opts) => {
					assert.isObject(opts.extensions);
					assert.isObject(opts.extensions.test);
					assert.strictEqual(opts.extensions.test, extVal);
				});
		});

		it("calls all generators", function() {
			const genSpy1 = new Stub();
			const extVal1 = {
				beer: "good",
			};
			genSpy1.return(extVal1);
			const genSpy2 = new Stub();
			const extVal2 = false;
			genSpy2.return(extVal2);

			Fido2Lib.addExtension("test1", genSpy1.stub(),fn, fn);
			Fido2Lib.addExtension("test2", genSpy2.stub(),fn, fn);
			mc.enableExtension("test1");
			mc.enableExtension("test2");
			return mc.assertionOptions()
				.then((opts) => {
					assert.isObject(opts.extensions);
					assert.isObject(opts.extensions.test1);
					assert.strictEqual(opts.extensions.test1, extVal1);
					assert.isFalse(opts.extensions.test2);
				});
		});

		it("calls all enabled generators", function() {
			const genSpy1 = new Stub();
			const extVal1 = {
				beer: "good",
			};
			genSpy1.return(extVal1);
			const genSpy2 = new Stub();
			const extVal2 = false;
			genSpy2.return(extVal2);

			Fido2Lib.addExtension("test1", genSpy1.stub(),fn, fn);
			Fido2Lib.addExtension("test2", genSpy2.stub(),fn, fn);
			mc.enableExtension("test1");
			mc.disableExtension("test2");
			return mc.assertionOptions()
				.then((opts) => {
					assert.isObject(opts.extensions);
					assert.isObject(opts.extensions.test1);
					assert.strictEqual(opts.extensions.test1, extVal1);
					assert.isUndefined(opts.extensions.test2);
				});
		});

		it("passes through default options", function() {
			const genSpy1 = new Stub();
			const extVal1 = {
				beer: "good",
			};
			const extOpt1 = {
				foo: "bar",
			};
			genSpy1.return(extVal1);
			const genSpy2 = new Stub();
			const extVal2 = false;
			const extOpt2 = null;
			genSpy2.return(extVal2);

			Fido2Lib.addExtension("test1", genSpy1.stub(),fn, fn);
			Fido2Lib.addExtension("test2", genSpy2.stub(),fn, fn);
			mc.enableExtension("test1");
			mc.setExtensionOptions("test1", extOpt1);
			mc.enableExtension("test2");
			mc.setExtensionOptions("test2", extOpt2);
			return mc.assertionOptions()
				.then((opts) => {
					assert.isObject(opts.extensions);
					assert.isObject(opts.extensions.test1);
					assert.strictEqual(opts.extensions.test1, extVal1);
					assert.isFalse(opts.extensions.test2);
					assert.isTrue(genSpy1.calledWithExactly("test1", "assertion", extOpt1));
					assert.isTrue(genSpy2.calledWithExactly("test2", "assertion", extOpt2));
				});
		});

		it("passes through passed-in options", function() {
			const genSpy1 = new Stub();
			const extVal1 = {
				beer: "good",
			};
			const extOpt1 = {
				foo: "bar",
			};
			genSpy1.return(extVal1);
			const genSpy2 = new Stub();
			const extVal2 = false;
			const extOpt2 = null;
			genSpy2.return(extVal2);

			Fido2Lib.addExtension("test1", genSpy1.stub(),fn, fn);
			Fido2Lib.addExtension("test2", genSpy2.stub(),fn, fn);
			mc.enableExtension("test1");
			mc.enableExtension("test2");
			return mc.assertionOptions({
				extensionOptions: {
					test1: extOpt1,
					test2: extOpt2,
				},
			})
				.then((opts) => {
					assert.isObject(opts.extensions);
					assert.isObject(opts.extensions.test1);
					assert.strictEqual(opts.extensions.test1, extVal1);
					assert.isFalse(opts.extensions.test2);
					assert.isTrue(genSpy1.calledWithExactly("test1", "assertion", extOpt1));
					assert.isTrue(genSpy2.calledWithExactly("test2", "assertion", extOpt2));
				});
		});
	});
});
