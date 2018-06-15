[![Build Status](https://travis-ci.org/apowers313/fido2-lib.svg?branch=master)](https://travis-ci.org/apowers313/fido2-lib) [![Coverage Status](https://coveralls.io/repos/github/apowers313/fido2-lib/badge.svg?branch=master)](https://coveralls.io/github/apowers313/fido2-lib?branch=master) [![Known Vulnerabilities](https://snyk.io/test/github/apowers313/fido2-lib/badge.svg?targetFile=package.json)](https://snyk.io/test/github/apowers313/fido2-lib?targetFile=package.json)

## Install

``` bash
npm install fido2-lib
```

## Overview
A library for performing FIDO 2.0 / WebAuthn server functionality

This library contains all the functionality necessary for implementing a full FIDO2 / WebAuthn server. It intentionally does not implement any kind of networking protocol (e.g. - REST endpoints) so that it can remain independent of any messaging protocols.

There are four primary functions:
1. [attestationOptions](https://apowers313.github.io/fido2-lib/Fido2Lib.html#attestationOptions) - creates the challenge that will be sent to the client (e.g. - browser) for the credential create call. Note that the library does not keep track of sessions or context, so the caller is expected to associate the resulting challenge with a session so that it can be appropriately matched with a response.
2. [attestationResult](https://apowers313.github.io/fido2-lib/Fido2Lib.html#attestationResult) - parses and validates the response from the client
3. [assertionOptions](https://apowers313.github.io/fido2-lib/Fido2Lib.html#assertionOptions) - creates the challenge that will be sent to the client for credential assertion.
4. [assertionResult](https://apowers313.github.io/fido2-lib/Fido2Lib.html#assertionResult) - parses and validates the response from the client

There is also an extension point for adding new attestation formats.

Full documentation can be found [here](https://apowers313.github.io/fido2-lib/).

For working examples see [fido2-server-demo](https://github.com/apowers313/fido2-server-demo) and / or [webauthn.org](https://webauthn.org)

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

// save the challenge in the session information...
// send authnOptions to client and pass them in to `navigator.credentials.get()`...
// get response back from client (clientAssertionResponse)

var assertionExpectations = {
    challenge: "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ",
    origin: "https://localhost:8443",
    factor: "either",
    publicKey: "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERez9aO2wBAWO54MuGbEqSdWahSnG\n" +
        "MAg35BCNkaE3j8Q+O/ZhhKqTeIKm7El70EG6ejt4sg1ZaoQ5ELg8k3ywTg==\n" +
        "-----END PUBLIC KEY-----\n",
    prevCounter: 362
};
var authnResult = await f2l.attestationResult(clientAssertionResponse, assertionExpectations); // will throw on error

// authentication complete!
```

For a real-life example, refer to [component-fido2](https://github.com/apowers313/component-fido2).
