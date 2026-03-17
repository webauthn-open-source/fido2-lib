const eddsaPublicKey = {
	exampleBase64: "pAEBAycgBiFYIBOMu8jXst8kG4yReJ4hZXejtUscCj3biIs0eAU1ykwv",
	examplePem:
		"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAE4y7yNey3yQbjJF4niFld6O1SxwKPduIizR4BTXKTC8=\n-----END PUBLIC KEY-----\n",
	exampleJWK: {
		crv: "Ed25519",
		x: "E4y7yNey3yQbjJF4niFld6O1SxwKPduIizR4BTXKTC8",
		kty: "OKP",
	},
	testData: "dGVzdCBkYXRhIGZvciBFZERTQSB2ZXJpZmljYXRpb24",
	testSignature: "CPVCn9Kz6riieElzHPgPotCVMPMcL7V-BMrFe_WZG45c7gwHpHL0XAMAN70vd-GaTLsysL6wkWsHBhuvoTp4Bw",
};

export { eddsaPublicKey };
