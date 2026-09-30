import Testing

@testable import RFC_6750

@Suite
struct `Bearer challenge quoting` {
    @Test
    func `a comma inside a quoted value survives a round trip`() throws {
        let challenge = RFC_6750.Bearer.Challenge(
            realm: "api, v2",
            error: .invalidToken,
            errorDescription: "The access token expired, renew it"
        )
        let parsed = try RFC_6750.Bearer.Challenge.parse(from: challenge.wwwAuthenticateHeaderValue())
        #expect(parsed == challenge)
    }

    @Test
    func `a quote or backslash in the realm is escaped and restored`() throws {
        let challenge = RFC_6750.Bearer.Challenge(realm: #"say "hi" \ bye"#)
        let header = challenge.wwwAuthenticateHeaderValue()

        #expect(header == #"Bearer realm="say \"hi\" \\ bye""#)
        #expect(try RFC_6750.Bearer.Challenge.parse(from: header) == challenge)
    }

    @Test
    func `parameters keep their order-independent meaning`() throws {
        let parsed = try RFC_6750.Bearer.Challenge.parse(
            from: #"Bearer error="invalid_token", realm="example", scope="read write""#
        )
        #expect(parsed == RFC_6750.Bearer.Challenge(realm: "example", scope: "read write", error: .invalidToken))
    }
}
