//
//  RFC_6750.Bearer.B64Token.swift
//  swift-rfc-6750
//
//  RFC 6750 §2.1: b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
//

extension RFC_6750.Bearer {
    /// A `b64token` per RFC 6750 §2.1 — the grammar the `Authorization: Bearer`
    /// credential must satisfy on the wire.
    ///
    /// ## ABNF Grammar (RFC 6750 Section 2.1)
    ///
    /// ```
    /// credentials = "Bearer" 1*SP b64token
    /// b64token    = 1*( ALPHA / DIGIT /
    ///                   "-" / "." / "_" / "~" / "+" / "/" ) *"="
    /// ```
    ///
    /// Unlike `RFC_6750.Bearer.init(token:)` — which accepts any non-empty run of
    /// ASCII non-whitespace characters (the broad OAuth access-token value space) —
    /// this type enforces the strict header-credential grammar: a non-empty leading
    /// run of `b64token` characters followed only by `"="` padding.
    ///
    /// ## Example
    ///
    /// ```swift
    /// let token = try RFC_6750.Bearer.B64Token("mF_9.B5f-4.1JqM")
    /// let bearer = RFC_6750.Bearer(b64token: token)
    /// ```
    public struct B64Token: Hashable, Sendable {
        /// The validated `b64token` string.
        public let rawValue: String

        /// Creates a `b64token` WITHOUT validation.
        ///
        /// Private to ensure all public construction goes through grammar validation.
        init(__unchecked: Void, rawValue: String) {
            self.rawValue = rawValue
        }
    }
}

extension RFC_6750.Bearer.B64Token {
    /// Creates a `b64token`, validating `rawValue` against the RFC 6750 §2.1 grammar.
    ///
    /// - Parameter rawValue: The candidate token string.
    /// - Throws: `RFC_6750.Bearer.Error.invalidToken` if `rawValue` does not satisfy
    ///   `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`.
    public init(_ rawValue: String) throws(RFC_6750.Bearer.Error) {
        guard RFC_6750.Bearer.B64Token.isConformant(rawValue) else {
            throw RFC_6750.Bearer.Error.invalidToken(
                "Token does not conform to the RFC 6750 §2.1 b64token grammar"
            )
        }
        self.init(__unchecked: (), rawValue: rawValue)
    }

    /// Reports whether `string` conforms to the RFC 6750 §2.1 `b64token` grammar.
    ///
    /// - Parameter string: The candidate token.
    /// - Returns: `true` iff `string` is a non-empty run of `b64token` characters
    ///   followed only by `"="` padding.
    public static func isConformant(_ string: some StringProtocol) -> Bool {
        var sawTokenCharacter = false
        var sawPadding = false
        for byte in string.utf8 {
            if byte == 0x3D {  // "="
                sawPadding = true
                continue
            }
            if sawPadding { return false }  // grammar character after "=" padding
            guard RFC_6750.Bearer.B64Token.isCharacter(byte) else { return false }
            sawTokenCharacter = true
        }
        return sawTokenCharacter
    }

    /// Whether `byte` is a member of the `b64token` character class (RFC 6750 §2.1),
    /// i.e. `ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/"`.
    private static func isCharacter(_ byte: UInt8) -> Bool {
        return switch byte {
        case 0x41...0x5A: true  // A-Z
        case 0x61...0x7A: true  // a-z
        case 0x30...0x39: true  // 0-9
        case 0x2D: true  // "-"
        case 0x2E: true  // "."
        case 0x5F: true  // "_"
        case 0x7E: true  // "~"
        case 0x2B: true  // "+"
        case 0x2F: true  // "/"
        default: false
        }
    }
}

extension RFC_6750.Bearer {
    /// Creates a Bearer whose access token conforms to the RFC 6750 §2.1 `b64token`
    /// grammar — the strict form required of the `Authorization: Bearer` credential.
    ///
    /// - Parameter b64token: A grammar-validated ``B64Token``.
    public init(b64token: B64Token) {
        self.init(__unchecked: (), token: b64token.rawValue)
    }
}
