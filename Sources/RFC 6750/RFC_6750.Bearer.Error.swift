extension RFC_6750.Bearer {
    /// Errors that can occur during Bearer token operations
    public enum Error: Swift.Error, Sendable, Equatable {
        case invalidRequest(String)
        case invalidToken(String)
        case insufficientScope(String)
    }
}

extension RFC_6750.Bearer.Error {
    public var errorCode: RFC_6750.Bearer.ErrorCode {
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
