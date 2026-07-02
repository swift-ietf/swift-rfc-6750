# Swift RFC 6750

[![CI](https://github.com/swift-ietf/swift-rfc-6750/workflows/CI/badge.svg)](https://github.com/swift-ietf/swift-rfc-6750/actions/workflows/ci.yml)
![Development Status](https://img.shields.io/badge/status-active--development-blue.svg)

Swift implementation of RFC 6750: The OAuth 2.0 Authorization Framework - Bearer Token Usage.

## Overview

RFC 6750 defines how to use Bearer tokens in HTTP requests to access OAuth 2.0 protected resources. This package provides a pure Swift implementation of Bearer token handling, including all three transmission methods (Authorization header, form parameters, and query parameters), WWW-Authenticate challenge generation and parsing, and comprehensive error handling according to the RFC 6750 specification.

## Features

- **RFC Compliant**: Full implementation of RFC 6750 Bearer Token specification
- **Three Transmission Methods**: Support for Authorization header (recommended), form parameters, and query parameters
- **WWW-Authenticate Challenges**: Generation and parsing of authentication challenges
- **Error Handling**: Complete OAuth 2.0 error codes (invalid_request, invalid_token, insufficient_scope)
- **Type-Safe**: Validated token creation with proper error handling
- **Sendable**: Full Swift 6 concurrency support
- **Zero Dependencies**: Pure Swift implementation

## Installation

Add swift-rfc-6750 to your package dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/swift-ietf/swift-rfc-6750.git", from: "0.1.5")
]
```

Then add it to your target:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "RFC 6750", package: "swift-rfc-6750")
    ]
)
```

## Quick Start

### Creating Bearer Tokens

```swift
import RFC_6750

// Create a Bearer token
let bearer = try RFC_6750.Bearer(token: "mF_9.B5f-4.1JqM")

// Use in Authorization header (recommended method)
let headerValue = bearer.authorizationHeaderValue()
// Result: "Bearer mF_9.B5f-4.1JqM"
```

### Parsing Bearer Tokens from Requests

```swift
// Parse from Authorization header
let authHeader = "Bearer mF_9.B5f-4.1JqM"
let bearer = try RFC_6750.Bearer.parse(from: authHeader)
print(bearer.token)  // "mF_9.B5f-4.1JqM"

// Parse from form parameters
let formParams = ["access_token": "mF_9.B5f-4.1JqM"]
let bearerFromForm = try RFC_6750.Bearer.parse(fromFormParameters: formParams)

// Parse from query parameters
let queryItems = [URLQueryItem(name: "access_token", value: "mF_9.B5f-4.1JqM")]
let bearerFromQuery = try RFC_6750.Bearer.parse(fromQueryItems: queryItems)
```

### Generating WWW-Authenticate Challenges

```swift
// Create a challenge with error information
let challenge = RFC_6750.Bearer.Challenge(
    realm: "example",
    scope: "read write",
    error: .invalidToken,
    errorDescription: "The access token expired"
)

// Generate WWW-Authenticate header value
let headerValue = challenge.wwwAuthenticateHeaderValue()
// Result: Bearer, realm="example", scope="read write", error="invalid_token", error_description="The access token expired"
```

### Parsing WWW-Authenticate Challenges

```swift
let wwwAuth = "Bearer, realm=\"example\", error=\"invalid_token\""
let challenge = try RFC_6750.Bearer.Challenge.parse(from: wwwAuth)

print(challenge.realm)  // Optional("example")
print(challenge.error)  // Optional(RFC_6750.Bearer.ErrorCode.invalidToken)
```

### Error Handling

```swift
// Token validation errors
do {
    let bearer = try RFC_6750.Bearer(token: "")
} catch RFC_6750.Bearer.Error.invalidToken(let message) {
    print("Token error: \(message)")
}

// Parse errors
do {
    let bearer = try RFC_6750.Bearer.parse(from: "Invalid header")
} catch RFC_6750.Bearer.Error.invalidRequest(let message) {
    print("Request error: \(message)")
}

// Using error codes
let error = RFC_6750.Bearer.Error.insufficientScope("Requires admin access")
print(error.errorCode)  // ErrorCode.insufficientScope
print(error.localizedDescription)  // "Insufficient scope: Requires admin access"
```

## Usage

### Bearer Token Type

```swift
public struct Bearer: Codable, Hashable, Sendable {
    public let token: String

    init(token: String) throws
}
```

### Transmission Methods

```swift
// Authorization header (recommended)
func authorizationHeaderValue() -> String

// Form parameters
func formParameter() -> (name: String, value: String)

// Query parameters (not recommended for security reasons)
func queryParameter() -> (name: String, value: String)
```

### Challenge Type

```swift
public struct Challenge: Codable, Hashable, Sendable {
    public let realm: String?
    public let scope: String?
    public let error: ErrorCode?
    public let errorDescription: String?

    func wwwAuthenticateHeaderValue() -> String
    static func parse(from headerValue: String) throws -> Challenge
}
```

### Error Codes

```swift
public enum ErrorCode: String, CaseIterable {
    case invalidRequest = "invalid_request"
    case invalidToken = "invalid_token"
    case insufficientScope = "insufficient_scope"
}
```

### Error Type

```swift
public enum Error: Swift.Error {
    case invalidRequest(String)
    case invalidToken(String)
    case insufficientScope(String)

    var errorCode: ErrorCode { get }
    var localizedDescription: String { get }
}
```

## Related Packages

### Dependencies
- None - This is a pure Swift implementation

### Related Standards
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html) - The OAuth 2.0 Authorization Framework
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html) - JSON Web Token (JWT)

## Requirements

- Swift 6.0+
- macOS 13.0+ / iOS 16.0+ / tvOS 16.0+ / watchOS 9.0+

## License

This library is released under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
