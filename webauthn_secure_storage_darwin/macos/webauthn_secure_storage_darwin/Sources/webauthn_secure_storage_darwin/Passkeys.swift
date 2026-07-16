import Foundation
import AuthenticationServices
import FlutterMacOS
import AppKit

// NOTE: base64UrlDecodedData() is intentionally duplicated between the iOS and macOS
// Swift packages. The two packages are separate SPM targets with independent source
// directories, so a single shared file cannot be referenced by both without restructuring
// the package layout (consistent with how BiometricStorageImpl.swift is also duplicated).
private extension String {
    func base64UrlDecodedData() -> Data? {
        var base64 = self
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let paddingLength = (4 - base64.count % 4) % 4
        base64.append(String(repeating: "=", count: paddingLength))
        return Data(base64Encoded: base64)
    }
}

extension Data {
    func base64UrlEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }
}

@available(macOS 12.0, *)
class PasskeyImplementation: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {

    private var result: ((Any?) -> Void)?

    private func passkeyFlutterError(code: String, message: String) -> FlutterError {
        FlutterError(code: code, message: message, details: nil)
    }

    private func passkeyFlutterError(from error: Error) -> FlutterError {
        let nsError = error as NSError
        let code: String
        if nsError.domain == ASAuthorizationError.errorDomain,
           nsError.code == ASAuthorizationError.canceled.rawValue {
            code = "AuthError:UserCanceled"
        } else {
            code = "AuthError:Canceled"
        }
        return passkeyFlutterError(code: code, message: error.localizedDescription)
    }

    private func complete(_ value: Any?) {
        result?(value)
        result = nil
    }

    func registerPasskey(options: [String: Any], result: @escaping (Any?) -> Void) {
        self.result = result
        guard let challengeString = options["challenge"] as? String,
              let challengeData = challengeString.base64UrlDecodedData(),
              let rpItem = options["rp"] as? [String: Any],
              let rpId = rpItem["id"] as? String,
              let userItem = options["user"] as? [String: Any],
              let userIdString = userItem["id"] as? String,
              let userId = userIdString.base64UrlDecodedData(),
              let userName = userItem["name"] as? String else {
            complete(passkeyFlutterError(
                code: "InvalidArguments",
                message: "Invalid options: challenge, rp.id, user.id, and user.name are required"
            ))
            return
        }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
        let request = provider.createCredentialRegistrationRequest(challenge: challengeData, name: userName, userID: userId)

        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }

    func authenticateWithPasskey(options: [String: Any], result: @escaping (Any?) -> Void) {
        self.result = result
        guard let challengeString = options["challenge"] as? String,
              let challengeData = challengeString.base64UrlDecodedData(),
              let rpId = options["rpId"] as? String else {
            complete(passkeyFlutterError(
                code: "InvalidArguments",
                message: "Invalid options: challenge and rpId are required"
            ))
            return
        }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
        let request = provider.createCredentialAssertionRequest(challenge: challengeData)

        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return NSApplication.shared.keyWindow ?? NSWindow()
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            let response: [String: Any] = [
                "id": credential.credentialID.base64UrlEncodedString(),
                "rawId": credential.credentialID.base64UrlEncodedString(),
                "type": "public-key",
                "response": [
                    "clientDataJSON": credential.rawClientDataJSON.base64UrlEncodedString(),
                    "attestationObject": credential.rawAttestationObject?.base64UrlEncodedString() ?? "",
                ],
            ]
            result?(response)
        } else if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            let response: [String: Any] = [
                "id": credential.credentialID.base64UrlEncodedString(),
                "rawId": credential.credentialID.base64UrlEncodedString(),
                "type": "public-key",
                "response": [
                    "clientDataJSON": credential.rawClientDataJSON.base64UrlEncodedString(),
                    "authenticatorData": credential.rawAuthenticatorData.base64UrlEncodedString(),
                    "signature": credential.signature.base64UrlEncodedString(),
                    "userHandle": credential.userID?.base64UrlEncodedString() ?? "",
                ],
            ]
            result?(response)
        } else {
            complete(passkeyFlutterError(code: "SecurityError", message: "Unknown credential"))
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        complete(passkeyFlutterError(from: error))
    }
}
