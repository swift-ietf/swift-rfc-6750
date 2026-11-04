# swift-rfc-6750

Use this package when you send or accept OAuth 2.0 bearer tokens over HTTP: building or reading the `Authorization` header, the `access_token` form or query parameter, and the `WWW-Authenticate` challenge a resource server returns. Start from `RFC_6750.Bearer` for the token and `RFC_6750.Bearer.Challenge` for the challenge. Use `RFC_6750.Bearer.B64Token` when you need the token checked against the RFC's b64token grammar. For Basic credentials, use swift-rfc-7617.

## Laws

- `RFC_6750.Bearer.init(token:)` trims surrounding whitespace, then refuses an empty token or one with any non-ASCII or whitespace character. It does not check the b64token grammar, so a token such as `has!bang` is accepted.
- `RFC_6750.Bearer.B64Token` accepts only letters, digits and `-._~+/`, at least one of them, followed by any number of `=`. Padding anywhere else, as in `ab=cd`, is refused.
- `RFC_6750.Bearer.parse(from:)` trims the header, matches the `Bearer` scheme in any case, and keeps the rest as the token without the checks `RFC_6750.Bearer.init(token:)` makes.
- An `Authorization` header with another scheme, or with `Bearer` and no token, fails as `invalid_request`, as does a missing `access_token` parameter. An `access_token` parameter that is present but empty fails as `invalid_token`.
- `RFC_6750.Bearer.parse(fromQueryItems:)` takes the first item named `access_token`. An item with no value counts as missing.
- `RFC_6750.Bearer.Challenge.wwwAuthenticateHeaderValue()` writes only the parameters that are set, in the order realm, scope, error, error_description, each quoted with `"` and `\` escaped. A challenge with none is the bare word `Bearer`.
- `RFC_6750.Bearer.Challenge.parse(from:)` accepts parameters in any order, with or without quotes, and keeps commas inside quoted values. It ignores parameters it doesn't know, and an unknown error code leaves `error` nil. A written challenge parses back to an equal value.
