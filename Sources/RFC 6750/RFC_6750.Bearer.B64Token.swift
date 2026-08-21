extension RFC_6750.Bearer {

    public struct B64Token: Hashable, Sendable {

        public let rawValue: String

        init(__unchecked: Void, rawValue: String) {
            self.rawValue = rawValue
        }
    }
}

extension RFC_6750.Bearer.B64Token {

    public init(_ rawValue: String) throws(RFC_6750.Bearer.Error) {
        guard RFC_6750.Bearer.B64Token.isConformant(rawValue) else {
            throw RFC_6750.Bearer.Error.invalidToken(
                "Token does not conform to the RFC 6750 §2.1 b64token grammar"
            )
        }

        self.init(__unchecked: (), rawValue: rawValue)
    }

    public static func isConformant(_ string: some StringProtocol) -> Bool {
        var sawTokenCharacter = false
        var sawPadding = false
        for byte in string.utf8 {
            if byte == 0x3D {
                sawPadding = true
                continue
            }
            if sawPadding { return false }
            guard RFC_6750.Bearer.B64Token.isCharacter(byte) else { return false }
            sawTokenCharacter = true
        }
        return sawTokenCharacter
    }

    private static func isCharacter(_ byte: UInt8) -> Bool {
        return switch byte {
        case 0x41...0x5A: true
        case 0x61...0x7A: true
        case 0x30...0x39: true
        case 0x2D: true
        case 0x2E: true
        case 0x5F: true
        case 0x7E: true
        case 0x2B: true
        case 0x2F: true
        default: false
        }
    }
}

extension RFC_6750.Bearer {

    public init(b64token: B64Token) {

        self.init(__unchecked: (), token: b64token.rawValue)
    }
}
