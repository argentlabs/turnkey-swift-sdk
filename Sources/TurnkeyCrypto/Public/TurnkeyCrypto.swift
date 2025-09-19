import CryptoKit
import Foundation
import Security
import TurnkeyEncoding

public struct TurnkeyCrypto {

  /// Generates a new P-256 keypair and returns it in hex format.
  ///
  /// - Returns: A tuple containing:
  ///   - `publicKeyUncompressed`: The uncompressed public key in hex format.
  ///   - `publicKeyCompressed`: The compressed public key in hex format.
  ///   - `privateKey`: The raw private key in hex format.
  public static func generateP256KeyPair() -> (
    publicKeyUncompressed: String,
    publicKeyCompressed: String,
    privateKey: String
  ) {
    let priv = P256.Signing.PrivateKey()

    let pubHexUncompressed = priv.publicKey.x963Representation.toHexString()
    let pubHexCompressed = priv.publicKey.compressedRepresentation.toHexString()
    let privHex = priv.rawRepresentation.toHexString()

    return (
      publicKeyUncompressed: pubHexUncompressed,
      publicKeyCompressed: pubHexCompressed,
      privateKey: privHex
    )
  }

  /// Generates a new P-256 keypair. When `useSecureEnclave` is true, the private key remains inside the
  /// device Secure Enclave and the returned `privateKey` string encodes the key reference rather than the
  /// raw bytes. The stamp protocol remains unchanged because the Secure Enclave signer produces the same
  /// DER-encoded signatures as the software key.
  ///
  /// - Parameters:
  ///   - useSecureEnclave: If `true`, create the private key inside Secure Enclave.
  ///   - accessControl: Optional `SecAccessControl` configuration to apply to the Secure Enclave private key.
  ///     When omitted, a default of `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with `.privateKeyUsage`
  ///     is used.
  @available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
  public static func generateP256KeyPair(
    useSecureEnclave: Bool,
    accessControl: SecAccessControl? = nil
  ) throws -> (
    publicKeyUncompressed: String,
    publicKeyCompressed: String,
    privateKey: String
  ) {
    guard useSecureEnclave else { return generateP256KeyPair() }

    guard SecureEnclave.isAvailable else {
      throw CryptoError.secureEnclaveUnavailable
    }

    let configuredAccessControl = try accessControl ?? defaultSecureEnclaveAccessControl()
    let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: configuredAccessControl)

    let pubHexUncompressed = privateKey.publicKey.x963Representation.toHexString()
    let pubHexCompressed = privateKey.publicKey.compressedRepresentation.toHexString()

    let keyReference = privateKey.dataRepresentation
    let encodedReference = SecureEnclaveKeyEncoding.encode(keyReference)

    return (
      publicKeyUncompressed: pubHexUncompressed,
      publicKeyCompressed: pubHexCompressed,
      privateKey: encodedReference
    )
  }

  /// Decrypts a credential bundle using the provided ephemeral private key.
  ///
  /// - Parameters:
  ///   - encryptedBundle: The base58-encoded bundle string.
  ///   - ephemeralPrivateKey: The ephemeral private key used for HPKE decryption.
  /// - Returns: A tuple containing the decrypted signing private key and corresponding public key.
  /// - Throws: `CryptoError` if decryption or decoding fails.
  public static func decryptCredentialBundle(
    encryptedBundle: String,
    ephemeralPrivateKey: P256.KeyAgreement.PrivateKey
  ) throws -> (P256.Signing.PrivateKey, P256.Signing.PublicKey) {
    return try HpkeHelpers.decryptCredentialBundle(
      encryptedBundle: encryptedBundle,
      ephemeralPrivateKey: ephemeralPrivateKey
    )
  }

  /// Decrypts an export bundle and returns either a hex string or mnemonic depending on configuration.
  ///
  /// - Parameters:
  ///   - exportBundle: A signed and encrypted bundle from Turnkey's enclave.
  ///   - organizationId: The expected organization ID to verify against.
  ///   - embeddedPrivateKey: The raw embedded private key in hex format.
  ///   - dangerouslyOverrideSignerPublicKey: Optional override of the signer public key (for dev/test).
  ///   - keyFormat: The output format for Solana or other keys.
  ///   - returnMnemonic: If `true`, returns the plaintext as a UTF-8 encoded mnemonic.
  /// - Returns: The decrypted payload as either a mnemonic or hex string.
  /// - Throws: `CryptoError` if any validation, decoding, or decryption fails.
  public static func decryptExportBundle(
    exportBundle: String,
    organizationId: String,
    embeddedPrivateKey: String,
    dangerouslyOverrideSignerPublicKey: String? = nil,
    keyFormat: KeyFormat = .other,
    returnMnemonic: Bool = false
  ) throws -> String {
    guard let keyData = Data(hexString: embeddedPrivateKey) else {
      throw CryptoError.invalidHexString(embeddedPrivateKey)
    }

    let privateKey: P256.KeyAgreement.PrivateKey
    do {
      privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: keyData)
    } catch {
      throw CryptoError.invalidPrivateKey(error)
    }

    return try HpkeHelpers.decryptExportBundle(
      exportBundle: exportBundle,
      organizationId: organizationId,
      embeddedPrivateKey: privateKey,
      dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey,
      keyFormat: keyFormat,
      returnMnemonic: returnMnemonic
    )
  }

  /// Encrypts a mnemonic into a bundle using the import payload from the enclave.
  ///
  /// - Parameters:
  ///   - mnemonic: The plaintext mnemonic string to encrypt.
  ///   - importBundle: The enclave-generated bundle to use for encryption.
  ///   - userId: The expected user ID to verify against.
  ///   - organizationId: The expected organization ID to verify against.
  ///   - dangerouslyOverrideSignerPublicKey: Optional override of the signer public key (for dev/test).
  /// - Returns: The encrypted bundle as a JSON string.
  /// - Throws: `CryptoError` if validation or encryption fails.
  public static func encryptWalletToBundle(
    mnemonic: String,
    importBundle: String,
    userId: String,
    organizationId: String,
    dangerouslyOverrideSignerPublicKey: String? = nil
  ) throws -> String {
    return try HpkeHelpers.encryptWalletToBundle(
      mnemonic: mnemonic,
      importBundle: importBundle,
      userId: userId,
      organizationId: organizationId,
      dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey
    )
  }
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
private extension TurnkeyCrypto {
  static func defaultSecureEnclaveAccessControl() throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      nil,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage,
      &error
    ) else {
      let underlying = error?.takeRetainedValue()
      throw CryptoError.secureEnclaveAccessControlCreationFailed(underlying: underlying)
    }
    return access
  }
}
