const { Fido2Lib } = require("./index.js");
const mdsCollection = Fido2Lib.createMdsCollection("FIDO MDS 1");
const axios = require("axios");
const base64url = require("base64url");
const fs = require("fs");

//axios.get("https://mds.fidoalliance.org").then(async (response) => {
mdsCollection.addToc(fs.readFileSync("./test/mdsV3.jwt", "utf8")).then((tocObj) => {
	tocObj.entries.forEach((entry) => {
		mdsCollection.addEntry(base64url.encode(JSON.stringify(entry)));
	});
    
	Fido2Lib.addMdsCollection(mdsCollection);
});

    
//})