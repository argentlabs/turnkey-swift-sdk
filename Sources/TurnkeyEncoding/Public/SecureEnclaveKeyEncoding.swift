import Foundation

public enum SecureEnclaveKeyEncoding {
  public static let prefix = "secure_enclave:"

  public static func encode(_ data: Data) -> String {
    prefix + data.base64EncodedString()
  }

  public static func decode(_ value: String) -> Data? {
    guard value.hasPrefix(prefix) else { return nil }
    let encoded = String(value.dropFirst(prefix.count))
    return Data(base64Encoded: encoded)
  }

  public static func isEncodedKey(_ value: String) -> Bool {
    value.hasPrefix(prefix)
  }
}
