// GitSafty Secure Enclave helper (macOS).
//
// Compiled once on the user's Mac by `gitsafty vault setup` (swiftc), so the
// npm package stays dependency-free and ships no prebuilt binary.
//
//   create            -> JSON {"blob","peer","secret"}  (no prompt)
//   unlock <reason>   -> reads {"blob","peer"} JSON on stdin, prints secret hex
//                        (macOS asks for Touch ID / Mac password first)
//   check             -> "ok" if the Secure Enclave can be used
//
// The private key is created INSIDE the Secure Enclave with
// .privateKeyUsage + .userPresence: it never leaves the chip, cannot be used
// on another Mac, and every use needs the person at the keyboard.
// The 32-byte vault secret is the ECDH shared secret between that key and a
// throw-away software key whose private half is discarded after setup.

import Foundation
import CryptoKit
import LocalAuthentication

func fail(_ message: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(code)
}

func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

func readStdinJSON() -> [String: String] {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: String] else {
        fail("invalid input")
    }
    return obj
}

func secretFrom(_ shared: SharedSecret) -> Data {
    // Raw ECDH output -> HKDF-SHA256 -> 32 bytes
    let key = shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: Data("gitsafty-vault-se".utf8),
        sharedInfo: Data("v2".utf8),
        outputByteCount: 32)
    return key.withUnsafeBytes { Data($0) }
}

let args = CommandLine.arguments
guard args.count >= 2 else { fail("usage: create | unlock <reason> | check") }

switch args[1] {
case "check":
    guard SecureEnclave.isAvailable else { fail("Secure Enclave not available", 2) }
    print("ok")

case "create":
    guard SecureEnclave.isAvailable else { fail("Secure Enclave not available", 2) }
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], nil)
    else { fail("could not create access control") }
    do {
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let peer = P256.KeyAgreement.PrivateKey()
        let shared = try peer.sharedSecretFromKeyAgreement(with: seKey.publicKey)
        let out: [String: String] = [
            "blob": seKey.dataRepresentation.base64EncodedString(),
            "peer": peer.publicKey.rawRepresentation.base64EncodedString(),
            "secret": hex(secretFrom(shared))
        ]
        let json = try JSONSerialization.data(withJSONObject: out)
        FileHandle.standardOutput.write(json)
    } catch {
        fail("create failed: \(error.localizedDescription)")
    }

case "unlock":
    let reason = args.count >= 3 ? args[2] : "unlock your GitHub login for git"
    let input = readStdinJSON()
    guard let blobB64 = input["blob"], let blob = Data(base64Encoded: blobB64),
          let peerB64 = input["peer"], let peerRaw = Data(base64Encoded: peerB64)
    else { fail("missing blob/peer") }
    let context = LAContext()
    context.localizedReason = reason
    do {
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blob, authenticationContext: context)
        let peer = try P256.KeyAgreement.PublicKey(rawRepresentation: peerRaw)
        let shared = try seKey.sharedSecretFromKeyAgreement(with: peer)  // prompts here
        print(hex(secretFrom(shared)))
    } catch {
        fail("unlock refused: \(error.localizedDescription)", 3)
    }

default:
    fail("unknown command")
}
