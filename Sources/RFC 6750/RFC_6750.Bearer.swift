extension RFC_6750 {

    public struct Bearer: Codable, Hashable, Sendable {
        public let token: String

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

        init(__unchecked: Void, token: String) {
            self.token = token
        }
    }
}

extension RFC_6750.Bearer {

    public func authorizationHeaderValue() -> String {
        return "Bearer \(token)"
    }

    public func formParameter() -> (name: String, value: String) {
        return ("access_token", token)
    }

    public func queryParameter() -> (name: String, value: String) {
        return ("access_token", token)
    }

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
