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
			"test/certUtils.test.js",
			"test/extAppId.test.js",
			"test/ext.test.js",
			"test/keyUtils.test.js",
			"test/main.test.js",
			"test/mds.test.js",
			"test/parseAndroidSafetyNetAttestationData.test.js",
			"test/parseAssertion.test.js",
			"test/parseBadData.test.js",
			"test/parseClientData.test.js",
			"test/parseExpectations.test.js",
			"test/parseNoneAttestationData.test.js",
			"test/parsePackedAttestationData.test.js",
			"test/parsePackedSelfAttestationData.test.js",
			"test/parseTpmAttestationData.test.js",
			"test/parseU2fAttestationData.test.js",
			"test/response.test.js",
			"test/toolbox.test.js",
			"test/utils.test.js",
			"test/validator.test.js",
		],
		output: {
			dir: "test/dist/",
			entryFileName: "[name].js",
			format: "cjs",
		},
	},
];