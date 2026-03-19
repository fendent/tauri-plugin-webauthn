import Foundation
import AuthenticationServices
import UIKit

@available(iOS 15.0, *)
@MainActor
final class PasskeyHandler: NSObject {
    private var registrationContinuation: CheckedContinuation<ASAuthorization, Error>?
    private var assertionContinuation: CheckedContinuation<ASAuthorization, Error>?

    func register(
        domain: String, challenge: Data, username: String, userID: Data
    ) async throws -> ASAuthorization {
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
        let platformRequest = platformProvider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: username,
            userID: userID
        )

        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
        let securityKeyRequest = securityKeyProvider.createCredentialRegistrationRequest(
            challenge: challenge,
            displayName: username,
            name: username,
            userID: userID
        )
        securityKeyRequest.credentialParameters = [
            ASAuthorizationPublicKeyCredentialParameters(algorithm: .ES256)
        ]

        let controller = ASAuthorizationController(authorizationRequests: [platformRequest, securityKeyRequest])
        controller.delegate = self
        controller.presentationContextProvider = self

        return try await withCheckedThrowingContinuation { continuation in
            self.registrationContinuation = continuation
            controller.performRequests()
        }
    }

    func authenticate(
        domain: String, challenge: Data, allowCredentials: [Data]
    ) async throws -> ASAuthorization {
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
        let platformRequest = platformProvider.createCredentialAssertionRequest(challenge: challenge)

        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
        let securityKeyRequest = securityKeyProvider.createCredentialAssertionRequest(challenge: challenge)

        if !allowCredentials.isEmpty {
            platformRequest.allowedCredentials = allowCredentials.map {
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
            }
            securityKeyRequest.allowedCredentials = allowCredentials.map {
                ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                    credentialID: $0,
                    transports: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
                )
            }
        }

        let controller = ASAuthorizationController(authorizationRequests: [platformRequest, securityKeyRequest])
        controller.delegate = self
        controller.presentationContextProvider = self

        return try await withCheckedThrowingContinuation { continuation in
            self.assertionContinuation = continuation
            controller.performRequests()
        }
    }
}

// MARK: - ASAuthorizationControllerDelegate

@available(iOS 15.0, *)
extension PasskeyHandler: ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        let scene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }
        return scene?.windows.first(where: { $0.isKeyWindow })
            ?? scene?.windows.first
            ?? UIWindow()
    }

    func authorizationController(
        controller: ASAuthorizationController, didCompleteWithAuthorization auth: ASAuthorization
    ) {
        if auth.credential is ASAuthorizationPlatformPublicKeyCredentialRegistration
            || auth.credential is ASAuthorizationSecurityKeyPublicKeyCredentialRegistration {
            registrationContinuation?.resume(returning: auth)
            registrationContinuation = nil
        } else if auth.credential is ASAuthorizationPlatformPublicKeyCredentialAssertion
            || auth.credential is ASAuthorizationSecurityKeyPublicKeyCredentialAssertion {
            assertionContinuation?.resume(returning: auth)
            assertionContinuation = nil
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        registrationContinuation?.resume(throwing: error)
        registrationContinuation = nil
        assertionContinuation?.resume(throwing: error)
        assertionContinuation = nil
    }
}

// MARK: - Response Serialization

enum PasskeyHandlerError: LocalizedError {
    case unexpectedCredentialType

    var errorDescription: String? {
        "Unexpected credential type in authorization response"
    }
}

@available(iOS 15.0, *)
func registrationJSON(from auth: ASAuthorization) throws -> [String: Any] {
    guard let reg = auth.credential as? ASAuthorizationPublicKeyCredentialRegistration else {
        throw PasskeyHandlerError.unexpectedCredentialType
    }
    return [
        "id": reg.credentialID.base64URLEncodedString(),
        "rawId": reg.credentialID.base64URLEncodedString(),
        "type": "public-key",
        "response": [
            "attestationObject": (reg.rawAttestationObject ?? Data()).base64URLEncodedString(),
            "clientDataJSON": reg.rawClientDataJSON.base64URLEncodedString()
        ]
    ]
}

@available(iOS 15.0, *)
func assertionJSON(from auth: ASAuthorization) throws -> [String: Any] {
    guard let assertion = auth.credential as? ASAuthorizationPublicKeyCredentialAssertion else {
        throw PasskeyHandlerError.unexpectedCredentialType
    }
    return [
        "id": assertion.credentialID.base64URLEncodedString(),
        "rawId": assertion.credentialID.base64URLEncodedString(),
        "type": "public-key",
        "response": [
            "authenticatorData": assertion.rawAuthenticatorData.base64URLEncodedString(),
            "clientDataJSON": assertion.rawClientDataJSON.base64URLEncodedString(),
            "signature": assertion.signature.base64URLEncodedString(),
            "userHandle": assertion.userID.base64URLEncodedString()
        ]
    ]
}

// MARK: - Data Helpers

extension Data {
    func base64URLEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

func base64URLDecode(_ str: String) -> Data? {
    var base64 = str
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while base64.count % 4 != 0 {
        base64.append("=")
    }
    return Data(base64Encoded: base64)
}
