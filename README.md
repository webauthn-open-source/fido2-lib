[![CI](https://github.com/webauthn-open-source/fido2-lib/actions/workflows/test.yml/badge.svg)](https://github.com/webauthn-open-source/fido2-lib/actions/workflows/test.yml)
[![Code Coverage](https://codecov.io/gh/webauthn-open-source/fido2-lib/branch/master/graph/badge.svg)](https://codecov.io/gh/webauthn-open-source/fido2-lib)
[![Known Vulnerabilities](https://snyk.io/test/github/webauthn-open-source/fido2-lib/badge.svg?targetFile=package.json)](https://snyk.io/test/github/webauthn-open-source/fido2-lib?targetFile=package.json)

## Install

``` bash
npm install fido2-lib
```

[![npm version](https://badge.fury.io/js/fido2-lib.svg)](https://badge.fury.io/js/fido2-lib)

## Overview
A library for performing FIDO 2.0 / WebAuthn server functionality

This library contains all the functionality necessary for implementing a full FIDO2 / WebAuthn server. It intentionally does not implement any kind of networking protocol (e.g. - REST endpoints) so that it can remain independent of any messaging protocols.

There are four primary functions:
1. [attestationOptions](https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html#attestationOptions) - creates the challenge that will be sent to the client (e.g. - browser) for the credential create call. Note that the library does not keep track of sessions or context, so the caller is expected to associate the resulting challenge with a session so that it can be appropriately matched with a response.
2. [attestationResult](https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html#attestationResult) - parses and validates the response from the client
3. [assertionOptions](https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html#assertionOptions) - creates the challenge that will be sent to the client for credential assertion.
4. [assertionResult](https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html#assertionResult) - parses and validates the response from the client

There is also an extension point for adding new attestation formats.

Full documentation can be found [here](https://webauthn-open-source.github.io/fido2-lib/).

For working examples see [OWASP Single Sign-On](https://github.com/OWASP/SSO_Project) and / or [webauthn.io](https://webauthn.io/)

## Features

* Works with Windows Hello
* Attestation formats: packed, tpm, android-safetynet, fido-u2f, none
* Convenient API for adding more attestation formats
* Convenient API for adding extensions
* Metadata service (MDS) support enables authenticator root of trust and authenticator metadata
* Support for multiple simultaneous metadata services (e.g. FIDO MDS 1 & 2)
* Crypto families: ECDSA, RSA
* x509 cert parsing, support for FIDO-related extensions, and NIST Public Key Interoperability Test Suite (PKITS) chain validation (from [pki.js](https://github.com/PeculiarVentures/PKI.js/))
* Returns parsed and validated data, along with extra audit data for risk engines

## Example

**Instantiate Library (Simple):**
``` js
const { Fido2Lib } = require("fido2-lib");

// create a new instance of the library
var f2l = new Fido2Lib();
```

**Instantiate Library (Complex):**
``` js
// could also use one or more of the options below,
// which just makes the options calls easier later on:
var f2l = new Fido2Lib({
    timeout: 42,
    rpId: "example.com",
    rpName: "ACME",
    rpIcon: "https://example.com/logo.png",
    challengeSize: 128,
    attestation: "none",
    cryptoParams: [-7, -257],
    authenticatorAttachment: "platform",
    authenticatorRequireResidentKey: false,
    authenticatorUserVerification: "required"
});
```

**Registration:**
``` js
var registrationOptions = await f2l.attestationOptions();

// make sure to add registrationOptions.user.id
// save the challenge in the session information...
// send registrationOptions to client and pass them in to `navigator.credentials.create()`...
// get response back from client (clientAttestationResponse)

var attestationExpectations = {
    challenge: "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
    origin: "https://localhost:8443",
    factor: "either"
};
var regResult = await f2l.attestationResult(clientAttestationResponse, attestationExpectations); // will throw on error

// registration complete!
// save publicKey and counter from regResult to user's info for future authentication calls
```

**Authentication:**
``` js
var authnOptions = await f2l.assertionOptions();

// add allowCredentials to limit the number of allowed credential for the authentication process. For further details refer to webauthn specs: (https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials).
// save the challenge in the session information...
// send authnOptions to client and pass them in to `navigator.credentials.get()`...
// get response back from client (clientAssertionResponse)

var assertionExpectations = {
    // Remove the following comment if allowCredentials has been added into authnOptions so the credential received will be validate against allowCredentials array.
    // allowCredentials: [{
    //     id: "lTqW8H/lHJ4yT0nLOvsvKgcyJCeO8LdUjG5vkXpgO2b0XfyjLMejRvW5oslZtA4B/GgkO/qhTgoBWSlDqCng4Q==",
    //     type: "public-key",
    //     transports: ["usb"]
    // }],
    challenge: "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
    origin: "https://localhost:8443",
    factor: "either",
    publicKey: "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERez9aO2wBAWO54MuGbEqSdWahSnG\n" +
        "MAg35BCNkaE3j8Q+O/ZhhKqTeIKm7El70EG6ejt4sg1ZaoQ5ELg8k3ywTg==\n" +
        "-----END PUBLIC KEY-----\n",
    prevCounter: 362
};
var authnResult = await f2l.assertionResult(clientAssertionResponse, assertionExpectations); // will throw on error

// authentication complete!
```

**U2F migrated credentials flow example:**
```js
const { Fido2Lib } = require("fido2-lib")
const { coerceToArrayBuffer, coerceToBase64Url } = require("fido2-lib/lib/utils")

// STEP 1: Add the extension for app id like specified in https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/Migrating_from_U2F.html
const optionGeneratorFn = (extName, type, value) => value
const resultParserFn = () => {}
const resultValidatorFn = () => {}
Fido2Lib.addExtension("appid", optionGeneratorFn, resultParserFn, resultValidatorFn)

// STEP 2: Create fido2 instance and enable the extension appid
const f2l = new Fido2Lib({
  rpId: "example.com",
  rpName: "ACME",
  authenticatorAttachment: 'cross-platform',
  authenticatorUserVerification: 'preferred',
  cryptoParams: [-7]
})
f2l.enableExtension("appid")

// STEP 3: Generate authentication challenge
const authnOptions = await f2l.assertionOptions({
  extensionOptions: {
    appid: "https://www.example.com" // notice lowercase i in appid
  }
})
// encode challenge in format supported for data transfer
authnOptions.challenge = coerceToBase64Url(authOpts.challenge, "challenge")

const authnChallenge = {
  allowCredentials: [ // force only specific credentials
    {
      id: "lTqW8H/lHJ4yT0nLOvsvKgcyJCeO8LdUjG5vkXpgO2b0XfyjLMejRvW5oslZtA4B/GgkO/qhTgoBWSlDqCng4Q==",
      type: "public-key"
    }
  ],
  ...authnOptions
}

const serverResponse = JSON.stringify(authnChallenge, null, 2) // send to client side
// example response
// {
//   "allowCredentials": [
//     {
//       "id": "lTqW8H/lHJ4yT0nLOvsvKgcyJCeO8LdUjG5vkXpgO2b0XfyjLMejRvW5oslZtA4B/GgkO/qhTgoBWSlDqCng4Q==",
//       "type": "public-key"
//     }
//   ],
//   "challenge": "hF6cDwH8Xy6uAkp2ivBIL9Fla4_HNptF5nbtxfHpz2sajVvU4GIHUzY43zIGnU2AGARQp0tD-aiaU3Zecw4ocA",
//   "timeout": 60000,
//   "rpId": "example.com",
//   "userVerification": "preferred",
//   "extensions": {
//     "appid": "https://www.example.com"
//   }
// }

// STEP 4: Verify response from client side
const expectedAuthn = {
  challenge: authnChallenge.challenge,
  origin: "https://www.example.com",
  rpId: authnChallenge.extensions.appid,
  factor: "either",
  publicKey: jwkToPem(coseToJwk(coerceToArrayBuffer("pQECAy...", "pkey"))), // parse public key from base64 encoded format, useful if you don't store them in PEM format
  prevCounter: 1234,
  userHandle: null
}

// example response
const authnResponse = {
  id: "lTqW8H/lHJ4yT0nLOvsvKgcyJCeO8LdUjG5vkXpgO2b0XfyjLMejRvW5oslZtA4B/GgkO/qhTgoBWSlDqCng4Q==",
  response: {
    authenticatorData: "lK8QzA8NSNiTPCRHJiqlEt4CmIbp1e_wbVZ04wfB8I0BAAAFlw",
    clientDataJSON: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaEY2Y0R3SDhYeTZ1QWtwMml2QklMOUZsYTRfSE5wdEY1bmJ0eGZIcHoyc2FqVnZVNEdJSFV6WTQzeklHblUyQUdBUlFwMHRELWFpYVUzWmVjdzRvY0EiLCJvcmlnaW4iOiJodHRwczovL3d3dy5zdGFnaW5nLmJpdGZpbmV4LmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
    signature: "MEQCIE_-3E2ZWKs7hdzoV4MqZhbdto4ipqiyHok5fYjxNTE6AiBI4rD6kV_nb4ETc935yCjY1LFCcphnEZtf6FnF3n_YMw"
  }
}
authnResponse.id = coerceToArrayBuffer(authnResponse.id, 'id') // convert base64url data to array buffer 

const authnResult = await f2l.assertionResult(authnResponse, expectedAuthn) // will throw on failure

const validResponse = authnResult.audit.complete && authnResult.audit.validRequest && authnResult.audit.validExpectations
const newCounter = authnResult.authnrData.get('counter')
const authenticated = validResponse && newCounter > expectedAuthn.prevCounter // double check also counter to make sure auth passed
```
For a real-life example, refer to [OWASP Single Sign-On](https://github.com/OWASP/SSO_Project).

## Sponsor

Work for this project was supported by [Adam Power](https://github.com/apowers313).
