export default [
	{
		input: "./lib/node/main.js",
		output: {
			file: "dist/node/main.cjs",
			format: "cjs",
			exports: "named",
		},
	},
];
