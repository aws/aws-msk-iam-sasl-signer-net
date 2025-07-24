# Changelog

## 1.1.0-rc2025072301 (2025-07-23)

* Prerelease for migration from AWS SDK v3 to v4
* Bump all dependency versions
* Factor in credential expiration into token expiration
* Add special handling for `RefreshingAWSCredentials` to avoid short-lived MSK tokens

## 1.0.2 (2025-02-28)

* Resolve issue with intermittent auth failures when credentials are rotated (#16)

## 1.0.1 (2024-10-2)

* Adding sync methods to generate auth tokens.

## 1.0.0 (2023-11-8)

* First release.