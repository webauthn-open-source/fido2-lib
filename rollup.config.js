const devExternals = [
	"chai",
	"chai-as-promised",
	"sinon",
];
const externals = [
	"@hexagon/base64",
	"url",
	"tldts",
	"punycode",
	"jose",
	"pkijs",
	"asn1js",
	"cbor-x",
	"crypto",
	"@peculiar/webcrypto",
];
const tests = [
	"test/asn1.test.js",
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
	"test/parseNoneAttestationDataExtensions.test.js",
	"test/parsePackedAttestationData.test.js",
	"test/parsePackedSelfAttestationData.test.js",
	"test/parseTpmAttestationData.test.js",
	"test/parseU2fAttestationData.test.js",
	"test/parseJustExtensions.test.js",
	"test/parseAppleAttestationData.test.js",
	"test/response.test.js",
	"test/toolbox.test.js",
	"test/utils.test.js",
	"test/validator.test.js",
];

function surpressWarnings(message, warn) {
	if (message.code === "CIRCULAR_DEPENDENCY") return;
	warn(message);
}

export default [
	{
		input: "lib/main.js",
		external: [...externals],
		output: {
			file: "dist/main.cjs",
			format: "cjs",
		},
		onwarn: surpressWarnings,
	},
	{
		input: [...tests],
		external: [...externals,...devExternals],
		output: {
			dir: "test/dist/",
			format: "cjs",
		},
		onwarn: surpressWarnings,
	},
];