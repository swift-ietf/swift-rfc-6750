extension RFC_6750.Bearer {

    public struct Challenge: Codable, Hashable, Sendable {
        public let realm: String?
        public let scope: String?
        public let error: ErrorCode?
        public let errorDescription: String?

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

    public func wwwAuthenticateHeaderValue() -> String {
        var components: [String] = []

        if let realm {
            components.append("realm=\(Self.quoted(realm))")
        }

        if let scope {
            components.append("scope=\(Self.quoted(scope))")
        }

        if let error {

            components.append("error=\(Self.quoted(error.rawValue))")
        }

        if let errorDescription {
            components.append("error_description=\(Self.quoted(errorDescription))")
        }

        return components.isEmpty ? "Bearer" : "Bearer " + components.joined(separator: ", ")
    }

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
            var inQuotes = false
            var escaped = false
            for idx in pBytes.indices {
                let byte = pBytes[idx]
                if escaped {
                    escaped = false
                } else if inQuotes && byte == 0x5C {
                    escaped = true
                } else if byte == 0x22 {
                    inQuotes.toggle()
                } else if byte == 0x2C && !inQuotes {
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
        if value.count >= 2, value.hasPrefix("\"") && value.hasSuffix("\"") {
            var unescaped = ""
            var escaped = false
            for character in value.dropFirst().dropLast() {
                if !escaped && character == "\\" {
                    escaped = true
                } else {
                    unescaped.append(character)
                    escaped = false
                }
            }
            return unescaped
        }
        return String(value)
    }
}

extension RFC_6750.Bearer.Challenge {

    fileprivate static func quoted(_ value: String) -> String {
        "\"" + value.replacing("\\", with: "\\\\").replacing("\"", with: "\\\"") + "\""
    }
}
