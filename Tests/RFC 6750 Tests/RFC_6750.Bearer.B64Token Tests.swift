//
//  RFC_6750.Bearer.B64Token Tests.swift
//  RFC_6750 Tests
//

import Testing

@testable import RFC_6750

@Suite
struct `Bearer B64Token Tests` {

    @Test
    func `Valid b64token strings conform`() {
        // Grammar characters, with and without trailing "=" padding.
        #expect(RFC_6750.Bearer.B64Token.isConformant("mF_9.B5f-4.1JqM"))
        #expect(RFC_6750.Bearer.B64Token.isConformant("abcXYZ0189-._~+/"))
        #expect(RFC_6750.Bearer.B64Token.isConformant("QWxhZGRpbg=="))
        #expect(RFC_6750.Bearer.B64Token.isConformant("a"))
        #expect(RFC_6750.Bearer.B64Token.isConformant("a="))
    }

    @Test
    func `Invalid b64token strings do not conform`() {
        #expect(!RFC_6750.Bearer.B64Token.isConformant(""))  // empty (1* requires >= 1)
        #expect(!RFC_6750.Bearer.B64Token.isConformant("="))  // padding only, no grammar char
        #expect(!RFC_6750.Bearer.B64Token.isConformant("=="))  // padding only
        #expect(!RFC_6750.Bearer.B64Token.isConformant("ab=cd"))  // grammar char after padding
        #expect(!RFC_6750.Bearer.B64Token.isConformant("token with spaces"))  // SP not in class
        #expect(!RFC_6750.Bearer.B64Token.isConformant("has!bang"))  // "!" not in class
        #expect(!RFC_6750.Bearer.B64Token.isConformant("tökén"))  // non-ASCII
    }

    @Test
    func `B64Token validating init round-trips through Bearer`() throws {
        let token = try RFC_6750.Bearer.B64Token("mF_9.B5f-4.1JqM")
        #expect(token.rawValue == "mF_9.B5f-4.1JqM")

        let bearer = RFC_6750.Bearer(b64token: token)
        #expect(bearer.token == "mF_9.B5f-4.1JqM")
        #expect(bearer.authorizationHeaderValue() == "Bearer mF_9.B5f-4.1JqM")

        // Round-trip through the Authorization header parser.
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
