# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.2] - 2021-11-18
### Adapted as a Trovo-specific Oauth2 strategy

- Defaults added in for authorizationURL tokenURL userInfoUrl
- Fixed flow to use necessary additional headers and data params
- Override oauth2 getOAuthAccessToken function, since it doesn't allow application/json data (!?)
- fetch and format userProfile


## [0.0.1] - 2021-11-17
### Initial
- Fork from https://github.com/jaredhanson/passport-oauth2

