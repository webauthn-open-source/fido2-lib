[![Build Status](https://travis-ci.org/apowers313/fido2-lib.svg?branch=master)](https://travis-ci.org/apowers313/fido2-lib) [![Coverage Status](https://coveralls.io/repos/github/apowers313/fido2-lib/badge.svg?branch=master)](https://coveralls.io/github/apowers313/fido2-lib?branch=master) [![Known Vulnerabilities](https://snyk.io/test/github/apowers313/fido2-lib/badge.svg?targetFile=package.json)](https://snyk.io/test/github/apowers313/fido2-lib?targetFile=package.json)

## Install

``` bash
npm install fido2-lib
```

## Overview
A library for performing FIDO 2.0 / WebAuthn server functionality

This library contains all the functionality necessary for implementing a full FIDO2 / WebAuthn server. It intentionally does not implement any kind of networking protocol (e.g. - REST endpoints) so that it can remain independent of any messaging protocols.

There are four primary functions:
1. createCredentialChallenge - creates the challenge that will be sent to the client (e.g. - browser) for the credential create call. Note that the library does not keep track of sessions or context, so the caller is expected to associate the resulting challenge with a session so that it can be appropriately matched with a response.
2. createCredentialResponse - parses and validates the response from the client
3. createAssertionChallenge - creates the challenge that will be sent to the client for credential assertion. Essentially the same as `createCredentialChallenge`
4. createAsserationResponse - parses and validates the response from the client

There is also an extension point for adding new attestation formats.

Full documentation can be found here (coming soon).
