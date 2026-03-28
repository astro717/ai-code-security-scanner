// vulnerable.swift — Swift fixture with intentional security vulnerabilities.
// Used by swift-fixtures.vitest.ts to verify the Swift scanner detects all covered types.

import Foundation
import WebKit
import CommonCrypto
import CryptoKit

class VulnerableNetworkService {

    // SSRF — URLSession with user-controlled URL variable
    func fetchUserData(userUrl: URL) {
        URLSession.shared.dataTask(with: userUrl) { data, _, _ in
            print(data as Any)
        }.resume()
    }

    // SSRF — URLRequest constructed with user-controlled URL variable
    func makeRequest(userInput: URL) {
        let req = URLRequest(url: userInput)
        URLSession.shared.dataTask(with: req).resume()
    }

    // INSECURE_SHARED_PREFS — storing password in UserDefaults
    func cacheCredentials(password: String) {
        UserDefaults.standard.set(password, forKey: "password")
    }

    // INSECURE_SHARED_PREFS — storing token in UserDefaults
    func cacheToken(token: String) {
        UserDefaults.standard.setValue(token, forKey: "auth_token")
    }

    // UNSAFE_WEBVIEW — WKWebViewConfiguration.allowsArbitraryLoads directly set
    func configureWebView() -> WKWebViewConfiguration {
        let config = WKWebViewConfiguration()
        config.allowsArbitraryLoads = true
        return config
    }

    // SECRET_HARDCODED — hardcoded API key
    let apiKey: String = "sk-liveabcdef1234567890secretkey"

    // SECRET_HARDCODED — hardcoded token via pattern prefix
    let authToken = "sk_live_abcdef1234567890abcdef"

    // WEAK_CRYPTO — CommonCrypto MD5
    func hashMD5(data: Data) -> [UInt8] {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { bytes in
            CC_MD5(bytes.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest
    }

    // WEAK_CRYPTO — CommonCrypto SHA1
    func hashSHA1(data: Data) -> [UInt8] {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes { bytes in
            CC_SHA1(bytes.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest
    }

    // WEAK_CRYPTO — DES via CommonCrypto
    func encryptDES(data: Data, key: Data) -> Data? {
        var outLength = 0
        var outBytes = [UInt8](repeating: 0, count: data.count + kCCBlockSizeDES)
        CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES),
                CCOptions(kCCOptionPKCS7Padding),
                (key as NSData).bytes, kCCKeySizeDES,
                nil, (data as NSData).bytes, data.count, &outBytes, outBytes.count, &outLength)
        return Data(bytes: outBytes, count: outLength)
    }

    // WEAK_CRYPTO — CryptoKit Insecure.MD5
    func insecureHash(data: Data) -> Insecure.MD5Digest {
        return Insecure.MD5.hash(data: data)
    }
}
