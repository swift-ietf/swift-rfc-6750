//
//  ReadmeVerificationTests.swift
//  swift-rfc-6750
//
//  Verifies that README code examples actually work
//

import Foundation
import RFC_6750
import Testing

@Suite
struct `README Verification` {
    @Suite struct Unit {}
    @Suite struct `Edge Case` {}
    @Suite struct Integration {}
}

extension `README Verification`.Unit {
    @Test
    func `README Line 47-56: Creating Bearer Tokens`() throws {
        // Create a Bearer token
        let bearer = try RFC_6750.Bearer(token: "mF_9.B5f-4.1JqM")

        // Use in Authorization header (recommended method)
        let headerValue = bearer.authorizationHeaderValue()

        #expect(headerValue == "Bearer mF_9.B5f-4.1JqM")
    }

    @Test
    func `README Line 60-73: Parsing Bearer Tokens from Requests`() throws {
        // Parse from Authorization header
        let authHeader = "Bearer mF_9.B5f-4.1JqM"
        let bearer = try RFC_6750.Bearer.parse(from: authHeader)
        #expect(bearer.token == "mF_9.B5f-4.1JqM")

        // Parse from form parameters
        let formParams = ["access_token": "mF_9.B5f-4.1JqM"]
        let bearerFromForm = try RFC_6750.Bearer.parse(fromFormParameters: formParams)
        #expect(bearerFromForm.token == "mF_9.B5f-4.1JqM")

        // Parse from query parameters
        let queryItems = [RFC_6750.QueryItem(name: "access_token", value: "mF_9.B5f-4.1JqM")]
        let bearerFromQuery = try RFC_6750.Bearer.parse(fromQueryItems: queryItems)
        #expect(bearerFromQuery.token == "mF_9.B5f-4.1JqM")
    }

    @Test
    func `README Line 77-89: Generating WWW-Authenticate Challenges`() throws {
        // Create a challenge with error information
        let challenge = RFC_6750.Bearer.Challenge(
            realm: "example",
            scope: "read write",
            error: .invalidToken,
            errorDescription: "The access token expired"
        )

        // Generate WWW-Authenticate header value
        let headerValue = challenge.wwwAuthenticateHeaderValue()

        #expect(headerValue.contains("Bearer"))
        #expect(headerValue.contains("realm=\"example\""))
        #expect(headerValue.contains("scope=\"read write\""))
        #expect(headerValue.contains("error=\"invalid_token\""))
        #expect(headerValue.contains("error_description=\"The access token expired\""))
    }

    @Test
    func `README Line 93-99: Parsing WWW-Authenticate Challenges`() throws {
        let wwwAuth = "Bearer, realm=\"example\", error=\"invalid_token\""
        let challenge = try RFC_6750.Bearer.Challenge.parse(from: wwwAuth)

        #expect(challenge.realm == "example")
        #expect(challenge.error == .invalidToken)
    }

    @Test
    func `README Line 103-122: Error Handling`() throws {
        // Token validation errors
        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer(token: "")
        }

        // Parse errors
        #expect(throws: RFC_6750.Bearer.Error.self) {
            try RFC_6750.Bearer.parse(from: "Invalid header")
        }

        // Using error codes
        let error = RFC_6750.Bearer.Error.insufficientScope("Requires admin access")
        #expect(error.errorCode == .insufficientScope)
        #expect(error.description.contains("Insufficient scope"))
        #expect(error.description.contains("Requires admin access"))
    }

    @Test
    func `README Line 128-133: Bearer Token Type`() throws {
        let bearer = try RFC_6750.Bearer(token: "test_token")
        #expect(bearer.token == "test_token")

        // Test that it's Codable
        let encoder = JSONEncoder()
        let data = try encoder.encode(bearer)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(RFC_6750.Bearer.self, from: data)
        #expect(decoded.token == bearer.token)

        // Test that it's Hashable
        let set: Set<RFC_6750.Bearer> = [bearer]
        #expect(set.contains(bearer))
    }

    @Test
    func `README Line 137-147: Transmission Methods`() throws {
        let bearer = try RFC_6750.Bearer(token: "test_token")

        // Authorization header (recommended)
        let authHeader = bearer.authorizationHeaderValue()
        #expect(authHeader == "Bearer test_token")

        // Form parameters
        let formParam = bearer.formParameter()
        #expect(formParam.name == "access_token")
        #expect(formParam.value == "test_token")

        // Query parameters
        let queryParam = bearer.queryParameter()
        #expect(queryParam.name == "access_token")
        #expect(queryParam.value == "test_token")
    }

    @Test
    func `README Line 151-161: Challenge Type`() throws {
        let challenge = RFC_6750.Bearer.Challenge(
            realm: "test",
            scope: "read",
            error: .insufficientScope,
            errorDescription: "Not enough privileges"
        )

        let header = challenge.wwwAuthenticateHeaderValue()
        #expect(header.contains("Bearer"))

        // Test parsing
        let parsed = try RFC_6750.Bearer.Challenge.parse(from: header)
        #expect(parsed.realm == "test")
        #expect(parsed.scope == "read")
        #expect(parsed.error == .insufficientScope)
    }

    @Test
    func `README Line 165-171: Error Codes`() throws {
        #expect(RFC_6750.Bearer.ErrorCode.invalidRequest.rawValue == "invalid_request")
        #expect(RFC_6750.Bearer.ErrorCode.invalidToken.rawValue == "invalid_token")
        #expect(RFC_6750.Bearer.ErrorCode.insufficientScope.rawValue == "insufficient_scope")

        // Test that all cases exist
        let allCases = RFC_6750.Bearer.ErrorCode.allCases
        #expect(allCases.count == 3)
    }

    @Test
    func `README Line 175-184: Error Type`() throws {
        let invalidRequest = RFC_6750.Bearer.Error.invalidRequest("test")
        #expect(invalidRequest.errorCode == .invalidRequest)
        #expect(invalidRequest.description.contains("Invalid request"))

        let invalidToken = RFC_6750.Bearer.Error.invalidToken("test")
        #expect(invalidToken.errorCode == .invalidToken)
        #expect(invalidToken.description.contains("Invalid token"))

        let insufficientScope = RFC_6750.Bearer.Error.insufficientScope("test")
        #expect(insufficientScope.errorCode == .insufficientScope)
        #expect(insufficientScope.description.contains("Insufficient scope"))
    }
}
