// clean.swift — Swift fixture with safe implementations.
// Used by swift-fixtures.vitest.ts to verify the Swift scanner does NOT fire false positives.

import Foundation
import WebKit
import CryptoKit

class SafeNetworkService {

    private let allowedHosts: Set<String> = ["api.example.com", "cdn.example.com"]

    // Safe: URL validated against allowlist before request
    func fetchUserData(urlString: String) {
        guard let url = URL(string: urlString),
              let host = url.host,
              allowedHosts.contains(host) else { return }
        URLSession.shared.dataTask(with: URLRequest(url: url)) { data, _, _ in
            print(data as Any)
        }.resume()
    }

    // Safe: static URL literal — not user-controlled
    func fetchStaticResource() {
        URLSession.shared.dataTask(with: URL(string: "https://api.example.com/resource")!) { _, _, _ in }.resume()
    }

    // Safe: token stored in Keychain, not UserDefaults
    func storeTokenSecurely(token: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.example.app",
            kSecValueData as String: token.data(using: .utf8)!,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    // Safe: WKWebView configured without arbitrary loads
    func configureWebView() -> WKWebViewConfiguration {
        let config = WKWebViewConfiguration()
        // No allowsArbitraryLoads = true
        return config
    }

    // Safe: API key loaded from config, not hardcoded (placeholder)
    func loadApiKey() -> String {
        return ProcessInfo.processInfo.environment["API_KEY"] ?? ""
    }

    // Safe: SHA-256 for hashing
    func hashSHA256(data: Data) -> SHA256Digest {
        return SHA256.hash(data: data)
    }

    // Safe: AES-GCM encryption
    func encryptAES(data: Data) throws -> AES.GCM.SealedBox {
        let key = SymmetricKey(size: .bits256)
        return try AES.GCM.seal(data, using: key)
    }
}
