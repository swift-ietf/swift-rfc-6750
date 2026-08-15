// MARK: - Error Handling

extension RFC_6750.Bearer {
    /// OAuth 2.0 Bearer Token error codes according to RFC 6750
    public enum ErrorCode: String, Codable, Hashable, Sendable, CaseIterable {
        case invalidRequest = "invalid_request"
        case invalidToken = "invalid_token"
        case insufficientScope = "insufficient_scope"
    }
}

extension RFC_6750.Bearer.ErrorCode {
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
