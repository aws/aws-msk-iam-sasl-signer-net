# Changelog

## 1.1.0 (2025-07-29)

* Bump all dependency versions
  * Factor in credential expiration into MSK token expiration
  * Add special expiration handling for `RefreshingAWSCredentials` to prevent short-lived MSK token issuance
* Allow for custom MSK token expiry

## 1.0.2 (2025-02-28)

* Resolve issue with intermittent auth failures when credentials are rotated (#16)

## 1.0.1 (2024-10-2)

* Adding sync methods to generate auth tokens.

## 1.0.0 (2023-11-8)

* First release.