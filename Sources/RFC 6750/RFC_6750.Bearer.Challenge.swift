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
    }
}

extension RFC_6750.Bearer.Challenge {
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
            // swift-linter:disable:next raw value access
            // REASON: same-package implementation — `Bearer.Challenge` and `Bearer.ErrorCode` are both nested members of `RFC_6750.Bearer`.
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
    ) throws(RFC_6750.Bearer.Error) -> RFC_6750.Bearer.Challenge {
        let trimmed = String(headerValue.trimming(where: { $0.isWhitespace }))

        guard trimmed.lowercased().hasPrefix("bearer") else {
            throw RFC_6750.Bearer.Error.invalidRequest(
                "WWW-Authenticate header must start with 'Bearer'"
            )
        }

        let parameters = String(trimmed.dropFirst(6)).trimming(where: { $0.isWhitespace })
        var realm: String?
        var scope: String?
        var error: RFC_6750.Bearer.ErrorCode?
        var errorDescription: String?

        if !parameters.isEmpty {
            let pBytes = Array(parameters.utf8)
            var segStart = 0
            var components: [String] = []
            pBytes.indices.forEach { idx in
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
                        error = RFC_6750.Bearer.ErrorCode(rawValue: errorValue)
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
