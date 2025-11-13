export default [
	{
		ignores: ["dist/*", "test/dist/*"],
	},
	{
		languageOptions: {
			ecmaVersion: 13,
			sourceType: "module",
			globals: {
				// Node.js globals
				console: "readonly",
				process: "readonly",
				Buffer: "readonly",
				__dirname: "readonly",
				__filename: "readonly",
				exports: "writable",
				module: "readonly",
				require: "readonly",
				global: "readonly",
				setTimeout: "readonly",
				clearTimeout: "readonly",
				setInterval: "readonly",
				clearInterval: "readonly",
				setImmediate: "readonly",
				clearImmediate: "readonly",
			},
		},
		rules: {
			"space-before-function-paren": [
				"error",
				{
					anonymous: "never",
					named: "never",
					asyncArrow: "always",
				},
			],
			"no-mixed-spaces-and-tabs": "error",
			quotes: [
				"error",
				"double",
				{
					avoidEscape: true,
				},
			],
			"comma-dangle": [
				"error",
				{
					arrays: "always-multiline",
					objects: "always-multiline",
					imports: "never",
					exports: "never",
					functions: "ignore",
				},
			],
			indent: [
				"error",
				"tab",
				{
					SwitchCase: 1,
				},
			],
			semi: ["error", "always"],
			"no-multiple-empty-lines": [
				"error",
				{
					max: 2,
					maxEOF: 1,
				},
			],
			"no-var": ["error"],
		},
	},
	{
		files: ["**/__tests__/*.{j,t}s?(x)"],
		languageOptions: {
			globals: {
				// Mocha globals
				describe: "readonly",
				it: "readonly",
				before: "readonly",
				after: "readonly",
				beforeEach: "readonly",
				afterEach: "readonly",
			},
		},
	},
];
