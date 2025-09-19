import CryptoKit
import Foundation

enum SecureEnclaveApiKeyStamper {

  static func stamp(
    payload: SHA256Digest,
    publicKeyHex: String,
    secureKeyData: Data
  ) throws -> String {
    let privateKey: SecureEnclave.P256.Signing.PrivateKey

    do {
      privateKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: secureKeyData)
    } catch {
      throw ApiKeyStampError.invalidPrivateKey
    }

    let derivedPublicKey = privateKey.publicKey.compressedRepresentation.toHexString()
    guard derivedPublicKey == publicKeyHex else {
      throw ApiKeyStampError.mismatchedPublicKey(expected: publicKeyHex, actual: derivedPublicKey)
    }

    guard let signature = try? privateKey.signature(for: payload) else {
      throw ApiKeyStampError.signatureFailed
    }

    let signatureHex = signature.derRepresentation.toHexString()
    let stamp: [String: Any] = [
      "publicKey": publicKeyHex,
      "scheme": "SIGNATURE_SCHEME_TK_API_P256",
      "signature": signatureHex,
    ]

    let jsonData = try JSONSerialization.data(withJSONObject: stamp, options: [])
    return jsonData.base64URLEncodedString()
  }
}
