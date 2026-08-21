import Testing

@testable import RFC_6750

@Suite
struct `Bearer B64Token Tests` {
    @Suite struct Unit {}
    @Suite struct `Edge Case` {}
    @Suite struct Integration {}
}

extension `Bearer B64Token Tests`.Unit {
    @Test
    func `Valid b64token strings conform`() {

        #expect(RFC_6750.Bearer.B64Token.isConformant("mF_9.B5f-4.1JqM"))
        #expect(RFC_6750.Bearer.B64Token.isConformant("abcXYZ0189-._~+/"))
        #expect(RFC_6750.Bearer.B64Token.isConformant("QWxhZGRpbg=="))
        #expect(RFC_6750.Bearer.B64Token.isConformant("a"))
        #expect(RFC_6750.Bearer.B64Token.isConformant("a="))
    }

    @Test
    func `Invalid b64token strings do not conform`() {
        #expect(!RFC_6750.Bearer.B64Token.isConformant(""))
        #expect(!RFC_6750.Bearer.B64Token.isConformant("="))
        #expect(!RFC_6750.Bearer.B64Token.isConformant("=="))
        #expect(!RFC_6750.Bearer.B64Token.isConformant("ab=cd"))
        #expect(!RFC_6750.Bearer.B64Token.isConformant("token with spaces"))
        #expect(!RFC_6750.Bearer.B64Token.isConformant("has!bang"))
        #expect(!RFC_6750.Bearer.B64Token.isConformant("tökén"))
    }

    @Test
    func `B64Token validating init round-trips through Bearer`() throws {
        let token = try RFC_6750.Bearer.B64Token("mF_9.B5f-4.1JqM")

        #expect(token.rawValue == "mF_9.B5f-4.1JqM")

        let bearer = RFC_6750.Bearer(b64token: token)
        #expect(bearer.token == "mF_9.B5f-4.1JqM")
        #expect(bearer.authorizationHeaderValue() == "Bearer mF_9.B5f-4.1JqM")

        let parsed = try RFC_6750.Bearer.parse(from: bearer.authorizationHeaderValue())

        #expect(parsed.token == token.rawValue)
    }

    @Test
    func `B64Token validating init rejects non-grammar input`() {
        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.B64Token("has!bang")
        }
        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.B64Token("")
        }
        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.B64Token("ab=cd")
        }
    }
}
