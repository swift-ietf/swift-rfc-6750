extension RFC_6750 {
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

        // swift-linter:disable:next unchecked call site
        // REASON: same-package extension-init internal use — `tokenString` was just validated non-empty above.
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

        // swift-linter:disable:next unchecked call site
        // REASON: same-package extension-init internal use — `tokenString` was just validated non-empty above.
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

        // swift-linter:disable:next unchecked call site
        // REASON: same-package extension-init internal use — `tokenString` was just validated non-empty above.
        return RFC_6750.Bearer(__unchecked: (), token: tokenString)
    }
}
