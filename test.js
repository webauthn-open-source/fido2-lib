const { Fido2Lib } = require("./index.js")
const mdsCollection = Fido2Lib.createMdsCollection("FIDO MDS 1")
const axios = require("axios")
const base64url = require('base64url');

axios.get("https://mds.fidoalliance.org").then(async (response) => {
    const tocObj = await mdsCollection.addToc(response.data);

    tocObj.entries.forEach((entry) => {
        mdsCollection.addEntry(base64url.encode(JSON.stringify(entry)));
    });

    Fido2Lib.addMdsCollection(mdsCollection);
})