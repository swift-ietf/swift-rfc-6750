import Testing

@testable import RFC_6750

@Suite
struct `RFC 6750 Tests` {
    @Suite struct Unit {}
    @Suite struct `Edge Case` {}
    @Suite struct Integration {}
}

extension `RFC 6750 Tests`.Unit {
    @Test
    func `Bearer token creation and validation`() throws {
        let bearer = try RFC_6750.Bearer(token: "mF_9.B5f-4.1JqM")
        #expect(bearer.token == "mF_9.B5f-4.1JqM")

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer(token: "")
        }

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer(token: "   ")
        }

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer(token: "token with spaces")
        }

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer(token: "tökén")
        }
    }

    @Test
    func `Bearer token Authorization header method`() throws {
        let bearer = try RFC_6750.Bearer(token: "mF_9.B5f-4.1JqM")
        let headerValue = bearer.authorizationHeaderValue()
        #expect(headerValue == "Bearer mF_9.B5f-4.1JqM")
    }

    @Test
    func `Bearer token form parameter method`() throws {
        let bearer = try RFC_6750.Bearer(token: "mF_9.B5f-4.1JqM")
        let formParam = bearer.formParameter()
        #expect(formParam.name == "access_token")
        #expect(formParam.value == "mF_9.B5f-4.1JqM")
    }

    @Test
    func `Bearer token query parameter method`() throws {
        let bearer = try RFC_6750.Bearer(token: "mF_9.B5f-4.1JqM")
        let queryParam = bearer.queryParameter()
        #expect(queryParam.name == "access_token")
        #expect(queryParam.value == "mF_9.B5f-4.1JqM")
    }

    @Test
    func `Bearer token parsing from Authorization header`() throws {
        let headerValue = "Bearer mF_9.B5f-4.1JqM"
        let bearer = try RFC_6750.Bearer.parse(from: headerValue)
        #expect(bearer.token == "mF_9.B5f-4.1JqM")

        let headerWithSpaces = "  Bearer mF_9.B5f-4.1JqM  "
        let bearerWithSpaces = try RFC_6750.Bearer.parse(from: headerWithSpaces)
        #expect(bearerWithSpaces.token == "mF_9.B5f-4.1JqM")
    }

    @Test
    func `Bearer token parsing from Authorization header error cases`() {

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.parse(from: "Basic mF_9.B5f-4.1JqM")
        }

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.parse(from: "Bearer ")
        }

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.parse(from: "Bearer")
        }
    }

    @Test
    func `Bearer token parsing from form parameters`() throws {
        let parameters = ["access_token": "mF_9.B5f-4.1JqM", "other_param": "value"]
        let bearer = try RFC_6750.Bearer.parse(fromFormParameters: parameters)
        #expect(bearer.token == "mF_9.B5f-4.1JqM")
    }

    @Test
    func `Bearer token parsing from form parameters error cases`() {

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.parse(fromFormParameters: ["other_param": "value"])
        }

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.parse(fromFormParameters: ["access_token": ""])
        }
    }

    @Test
    func `Bearer token parsing from query items`() throws {
        let queryItems = [
            RFC_6750.QueryItem(name: "access_token", value: "mF_9.B5f-4.1JqM"),
            RFC_6750.QueryItem(name: "other_param", value: "value"),
        ]
        let bearer = try RFC_6750.Bearer.parse(fromQueryItems: queryItems)
        #expect(bearer.token == "mF_9.B5f-4.1JqM")
    }

    @Test
    func `Bearer token parsing from query items error cases`() {

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.parse(fromQueryItems: [
                RFC_6750.QueryItem(name: "other_param", value: "value")
            ])
        }

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.parse(fromQueryItems: [
                RFC_6750.QueryItem(name: "access_token", value: nil)
            ])
        }

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.parse(fromQueryItems: [
                RFC_6750.QueryItem(name: "access_token", value: "")
            ])
        }
    }

    @Test
    func `Bearer Challenge creation`() {
        let challenge = RFC_6750.Bearer.Challenge()
        #expect(challenge.realm == nil)
        #expect(challenge.scope == nil)
        #expect(challenge.error == nil)
        #expect(challenge.errorDescription == nil)

        let challengeWithParams = RFC_6750.Bearer.Challenge(
            realm: "example.com",
            scope: "read write",
            error: .invalidToken,
            errorDescription: "Token has expired"
        )
        #expect(challengeWithParams.realm == "example.com")
        #expect(challengeWithParams.scope == "read write")
        #expect(challengeWithParams.error == .invalidToken)
        #expect(challengeWithParams.errorDescription == "Token has expired")
    }

    @Test
    func `Bearer Challenge WWW-Authenticate header generation`() {
        let challenge = RFC_6750.Bearer.Challenge()
        let headerValue = challenge.wwwAuthenticateHeaderValue()
        #expect(headerValue == "Bearer")

        let challengeWithRealm = RFC_6750.Bearer.Challenge(realm: "example.com")
        let headerValueWithRealm = challengeWithRealm.wwwAuthenticateHeaderValue()
        #expect(headerValueWithRealm == "Bearer, realm=\"example.com\"")

        let fullChallenge = RFC_6750.Bearer.Challenge(
            realm: "example.com",
            scope: "read write",
            error: .invalidToken,
            errorDescription: "Token has expired"
        )
        let fullHeaderValue = fullChallenge.wwwAuthenticateHeaderValue()
        #expect(
            fullHeaderValue
                == "Bearer, realm=\"example.com\", scope=\"read write\", error=\"invalid_token\", error_description=\"Token has expired\""
        )
    }

    @Test
    func `Bearer Challenge parsing from WWW-Authenticate header`() throws {
        let headerValue = "Bearer"
        let challenge = try RFC_6750.Bearer.Challenge.parse(from: headerValue)
        #expect(challenge.realm == nil)
        #expect(challenge.scope == nil)
        #expect(challenge.error == nil)
        #expect(challenge.errorDescription == nil)

        let headerValueWithRealm = "Bearer realm=\"example.com\""
        let challengeWithRealm = try RFC_6750.Bearer.Challenge.parse(from: headerValueWithRealm)
        #expect(challengeWithRealm.realm == "example.com")

        let fullHeaderValue =
            "Bearer realm=\"example.com\", scope=\"read write\", error=\"invalid_token\", error_description=\"Token has expired\""
        let fullChallenge = try RFC_6750.Bearer.Challenge.parse(from: fullHeaderValue)
        #expect(fullChallenge.realm == "example.com")
        #expect(fullChallenge.scope == "read write")
        #expect(fullChallenge.error == .invalidToken)
        #expect(fullChallenge.errorDescription == "Token has expired")
    }

    @Test
    func `Bearer Challenge parsing with unquoted values`() throws {
        let headerValue = "Bearer realm=example.com, scope=read"
        let challenge = try RFC_6750.Bearer.Challenge.parse(from: headerValue)
        #expect(challenge.realm == "example.com")
        #expect(challenge.scope == "read")
    }

    @Test
    func `Bearer Challenge parsing error cases`() {

        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.Challenge.parse(from: "Basic realm=\"example.com\"")
        }
    }

    @Test
    func `ErrorCode descriptions`() {
        #expect(
            RFC_6750.Bearer.ErrorCode.invalidRequest.description.contains(
                "missing a required parameter"
            )
        )
        #expect(
            RFC_6750.Bearer.ErrorCode.invalidToken.description.contains(
                "expired, revoked, malformed"
            )
        )
        #expect(
            RFC_6750.Bearer.ErrorCode.insufficientScope.description.contains("higher privileges")
        )
    }

    @Test
    func `Bearer Error localized descriptions`() {
        let requestError = RFC_6750.Bearer.Error.invalidRequest("test message")
        #expect(requestError.description == "Invalid request: test message")
        #expect(requestError.errorCode == .invalidRequest)

        let tokenError = RFC_6750.Bearer.Error.invalidToken("test message")
        #expect(tokenError.description == "Invalid token: test message")
        #expect(tokenError.errorCode == .invalidToken)

        let scopeError = RFC_6750.Bearer.Error.insufficientScope("test message")
        #expect(scopeError.description == "Insufficient scope: test message")
        #expect(scopeError.errorCode == .insufficientScope)
    }

    @Test
    func `Edge case: token with special characters`() throws {
        let bearer = try RFC_6750.Bearer(token: "mF_9.B5f-4.1JqM~!@#$%^&*()+={}[]|\\:;\"'<>?")
        #expect(bearer.token == "mF_9.B5f-4.1JqM~!@#$%^&*()+={}[]|\\:;\"'<>?")

        let headerValue = bearer.authorizationHeaderValue()
        let parsed = try RFC_6750.Bearer.parse(from: headerValue)
        #expect(parsed.token == bearer.token)
    }

    @Test
    func `Edge case: very long token`() throws {
        let longToken = String(repeating: "a", count: 1000)
        let bearer = try RFC_6750.Bearer(token: longToken)
        #expect(bearer.token == longToken)

        let headerValue = bearer.authorizationHeaderValue()
        let parsed = try RFC_6750.Bearer.parse(from: headerValue)
        #expect(parsed.token == longToken)
    }
}
