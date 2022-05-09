export default [
	{
		input: "lib/main.js",
		output: {
			file: "dist/main.cjs",
			format: "cjs",
		},
	},
	{
		input: [
			"test/certUtilsTest.js",
			"test/extAppIdTest.js",
			"test/extTest.js",
			"test/keyUtilsTest.js",
			"test/mainTest.js",
			"test/mdsTest.js",
			"test/parseAndroidSafetyNetAttestationDataTest.js",
			"test/parseAssertionTest.js",
			"test/parseBadDataTest.js",
			"test/parseClientDataTest.js",
			"test/parseExpectationsTest.js",
			"test/parseNoneAttestationDataTest.js",
			"test/parsePackedAttestationDataTest.js",
			"test/parsePackedSelfAttestationDataTest.js",
			"test/parseTpmAttestationDataTest.js",
			"test/parseU2fAttestationDataTest.js",
			"test/responseTest.js",
			"test/toolboxTest.js",
			"test/utilsTest.js",
			"test/validatorTest.js",
		],
		output: {
			dir: "test/dist/",
			format: "cjs",
		},
	},
];