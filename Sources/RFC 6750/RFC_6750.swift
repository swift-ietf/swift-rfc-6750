//
//  RFC_6750.swift
//  swift-rfc-6750
//
//  RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage
//

import ASCII_Primitives

/// Implementation of RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage
///
/// See: https://www.rfc-editor.org/rfc/rfc6750.html
public enum RFC_6750 {
    /// Represents an OAuth 2.0 Bearer Token according to RFC 6750
    public struct Bearer: Codable, Hashable, Sendable {
        public let token: String

        /// Creates a Bearer token
        /// - Parameter token: The access token string
        /// - Throws: `Error.invalidToken` if token is invalid
        public init(token: String) throws(Error) {
            let trimmed = String(token.trimming(where: { $0.isWhitespace }))
            guard !trimmed.isEmpty else {
                throw Error.invalidToken("Token cannot be empty")
            }
            guard trimmed.allSatisfy({ $0.isASCII && !$0.isWhitespace }) else {
                throw Error.invalidToken("Token must contain only ASCII non-whitespace characters")
            }
            self.token = trimmed
        }

        /// Creates a Bearer token without validation (for internal use)
        ///
        /// **Warning**: Bypasses RFC validation. Only use for:
        /// - Static constants
        /// - Pre-validated values
        /// - Internal construction after validation
        init(__unchecked: Void, token: String) {
            self.token = token
        }
    }
}

// MARK: - Query Item

extension RFC_6750 {
    /// A name-value pair representing a URI query parameter.
    ///
    /// Replaces Foundation's `URLQueryItem` for Foundation-free operation.
    public struct QueryItem: Sendable, Equatable, Hashable {
        /// The query parameter name
        public let name: String

        /// The query parameter value (nil if absent)
        public let value: String?

        /// Creates a query item
        /// - Parameters:
        ///   - name: The parameter name
        ///   - value: The parameter value
        public init(name: String, value: String?) {
            self.name = name
            self.value = value
        }
    }
}

// MARK: - Bearer Token Transmission Methods

extension RFC_6750.Bearer {
    /// Creates Authorization header value using Bearer scheme (recommended method)
    /// - Returns: Complete Authorization header value with "Bearer " prefix
    public func authorizationHeaderValue() -> String {
        return "Bearer \(token)"
    }

    /// Creates form parameter for request body transmission
    /// - Returns: Form parameter name-value pair
    /// - Note: Only use with application/x-www-form-urlencoded content type
    public func formParameter() -> (name: String, value: String) {
        return ("access_token", token)
    }

    /// Creates URI query parameter (not recommended)
    /// - Returns: Query parameter name-value pair
    /// - Warning: This method has security implications and should be avoided
    public func queryParameter() -> (name: String, value: String) {
        return ("access_token", token)
    }

    /// Parses Bearer token from Authorization header value
    /// - Parameter headerValue: The Authorization header value
    /// - Returns: Bearer token if valid
    /// - Throws: `Error` for invalid format
    public static func parse(from headerValue: String) throws(Error) -> RFC_6750.Bearer {
        let trimmed = String(headerValue.trimming(where: { $0.isWhitespace }))

        guard trimmed.lowercased().hasPrefix("bearer ") else {
            throw Error.invalidRequest("Authorization header must start with 'Bearer '")
        }

        let tokenString = String(trimmed.dropFirst(7))
        guard !tokenString.isEmpty else {
            throw Error.invalidToken("Bearer token cannot be empty")
        }

        return RFC_6750.Bearer(__unchecked: (), token: tokenString)
    }

    /// Parses Bearer token from form parameter
    /// - Parameter parameters: Form parameters dictionary
    /// - Returns: Bearer token if present and valid
    /// - Throws: `Error` for missing or invalid token
    public static func parse(
        fromFormParameters parameters: [String: String]
    ) throws(Error) -> RFC_6750.Bearer {
        guard let tokenString = parameters["access_token"] else {
            throw Error.invalidRequest("access_token parameter is required")
        }

        guard !tokenString.isEmpty else {
            throw Error.invalidToken("Bearer token cannot be empty")
        }

        return RFC_6750.Bearer(__unchecked: (), token: tokenString)
    }

    /// Parses Bearer token from URI query parameter
    /// - Parameter queryItems: Query items as name-value pairs
    /// - Returns: Bearer token if present and valid
    /// - Throws: `Error` for missing or invalid token
    public static func parse(
        fromQueryItems queryItems: [RFC_6750.QueryItem]
    ) throws(Error) -> RFC_6750.Bearer {
        guard let tokenItem = queryItems.first(where: { $0.name == "access_token" }),
            let tokenString = tokenItem.value
        else {
            throw Error.invalidRequest("access_token query parameter is required")
        }

        guard !tokenString.isEmpty else {
            throw Error.invalidToken("Bearer token cannot be empty")
        }

        return RFC_6750.Bearer(__unchecked: (), token: tokenString)
    }
}

// MARK: - WWW-Authenticate Challenge

extension RFC_6750.Bearer {
    /// Represents a Bearer token authentication challenge from WWW-Authenticate header
    public struct Challenge: Codable, Hashable, Sendable {
        public let realm: String?
        public let scope: String?
        public let error: ErrorCode?
        public let errorDescription: String?

        /// Creates a Bearer authentication challenge
        /// - Parameters:
        ///   - realm: Optional protection space identifier
        ///   - scope: Optional space-delimited list of required access scopes
        ///   - error: Optional error code for access denial
        ///   - errorDescription: Optional human-readable error explanation
        public init(
            realm: String? = nil,
            scope: String? = nil,
            error: ErrorCode? = nil,
            errorDescription: String? = nil
        ) {
            self.realm = realm
            self.scope = scope
            self.error = error
            self.errorDescription = errorDescription
        }

        /// Creates WWW-Authenticate header value
        /// - Returns: Complete WWW-Authenticate header value
        public func wwwAuthenticateHeaderValue() -> String {
            var components: [String] = ["Bearer"]

            if let realm = realm {
                components.append("realm=\"\(realm)\"")
            }

            if let scope = scope {
                components.append("scope=\"\(scope)\"")
            }

            if let error = error {
                components.append("error=\"\(error.rawValue)\"")
            }

            if let errorDescription = errorDescription {
                components.append("error_description=\"\(errorDescription)\"")
            }

            return components.joined(separator: ", ")
        }

        /// Parses Bearer challenge from WWW-Authenticate header
        /// - Parameter headerValue: The WWW-Authenticate header value
        /// - Returns: Bearer.Challenge if valid
        /// - Throws: `Error` for invalid format
        public static func parse(
            from headerValue: String
        ) throws(Error) -> RFC_6750.Bearer.Challenge {
            let trimmed = String(headerValue.trimming(where: { $0.isWhitespace }))

            guard trimmed.lowercased().hasPrefix("bearer") else {
                throw Error.invalidRequest("WWW-Authenticate header must start with 'Bearer'")
            }

            let parameters = String(trimmed.dropFirst(6)).trimming(where: { $0.isWhitespace })
            var realm: String?
            var scope: String?
            var error: ErrorCode?
            var errorDescription: String?

            if !parameters.isEmpty {
                let pBytes = Array(parameters.utf8)
                var segStart = 0
                var components: [String] = []
                for idx in 0..<pBytes.count {
                    if pBytes[idx] == 0x2C {  // ','
                        components.append(String(decoding: pBytes[segStart..<idx], as: UTF8.self))
                        segStart = idx &+ 1
                    }
                }
                components.append(String(decoding: pBytes[segStart..<pBytes.count], as: UTF8.self))

                for component in components {
                    let trimmedComponent = String(component.trimming(where: { $0.isWhitespace }))
                    if trimmedComponent.lowercased().hasPrefix("realm=") {
                        realm = extractQuotedValue(from: trimmedComponent, parameter: "realm")
                    } else if trimmedComponent.lowercased().hasPrefix("scope=") {
                        scope = extractQuotedValue(from: trimmedComponent, parameter: "scope")
                    } else if trimmedComponent.lowercased().hasPrefix("error=") {
                        if let errorValue = extractQuotedValue(
                            from: trimmedComponent,
                            parameter: "error"
                        ) {
                            error = ErrorCode(rawValue: errorValue)
                        }
                    } else if trimmedComponent.lowercased().hasPrefix("error_description=") {
                        errorDescription = extractQuotedValue(
                            from: trimmedComponent,
                            parameter: "error_description"
                        )
                    }
                }
            }

            return RFC_6750.Bearer.Challenge(
                realm: realm,
                scope: scope,
                error: error,
                errorDescription: errorDescription
            )
        }

        private static func extractQuotedValue(
            from component: String,
            parameter: String
        ) -> String? {
            let prefix = "\(parameter)="
            guard component.lowercased().hasPrefix(prefix.lowercased()) else { return nil }

            let value = String(component.dropFirst(prefix.count))
                .trimming(where: { $0.isWhitespace })
            if value.hasPrefix("\"") && value.hasSuffix("\"") {
                return String(value.dropFirst().dropLast())
            }
            return String(value)
        }
    }
}

// MARK: - Error Handling

extension RFC_6750.Bearer {
    /// OAuth 2.0 Bearer Token error codes according to RFC 6750
    public enum ErrorCode: String, Codable, Hashable, Sendable, CaseIterable {
        case invalidRequest = "invalid_request"
        case invalidToken = "invalid_token"
        case insufficientScope = "insufficient_scope"

        public var description: String {
            switch self {
            case .invalidRequest:
                return
                    "The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed."
            case .invalidToken:
                return
                    "The access token provided is expired, revoked, malformed, or invalid for other reasons."
            case .insufficientScope:
                return "The request requires higher privileges than provided by the access token."
            }
        }
    }

    /// Errors that can occur during Bearer token operations
    public enum Error: Swift.Error, Sendable, Equatable {
        case invalidRequest(String)
        case invalidToken(String)
        case insufficientScope(String)

        public var errorCode: ErrorCode {
            switch self {
            case .invalidRequest:
                return .invalidRequest
            case .invalidToken:
                return .invalidToken
            case .insufficientScope:
                return .insufficientScope
            }
        }
    }
}

extension RFC_6750.Bearer.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidRequest(let message):
            return "Invalid request: \(message)"
        case .invalidToken(let message):
            return "Invalid token: \(message)"
        case .insufficientScope(let message):
            return "Insufficient scope: \(message)"
        }
    }
}
