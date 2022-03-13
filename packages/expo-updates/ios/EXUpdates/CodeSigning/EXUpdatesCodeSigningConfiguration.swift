// Copyright 2015-present 650 Industries. All rights reserved.

import Foundation
import CommonCrypto
import ASN1Decoder

@objc public enum EXUpdatesCodeSigningConfigurationError : Int, Error {
  case CertificateParseError
  case CertificateValidityError
  case CertificateDigitalSignatureNotPresentError
  case CertificateMissingCodeSigningError
  case KeyIdMismatchError
  case SignatureEncodingError
  case SecurityFrameworkError
}

struct EXUpdatesCodeSigningMetadataFields {
  static let KeyIdFieldKey = "keyid"
  static let AlgorithmFieldKey = "alg"
}

@objc
public class EXUpdatesCodeSigningConfiguration : NSObject {
  private var embeddedCertificateString: String
  private var keyIdFromMetadata: String
  private var algorithmFromMetadata: EXUpdatesCodeSigningAlgorithm
  private var includeManifestResponseCertificateChain: Bool
  
  @objc
  public required init(embeddedCertificateString: String, metadata: [String: String], includeManifestResponseCertificateChain: Bool) throws {
    self.embeddedCertificateString = embeddedCertificateString
    self.keyIdFromMetadata = metadata[EXUpdatesCodeSigningMetadataFields.KeyIdFieldKey] ?? EXUpdatesSignatureHeaderInfo.DefaultKeyId
    self.algorithmFromMetadata = try parseCodeSigningAlgorithm(metadata[EXUpdatesCodeSigningMetadataFields.AlgorithmFieldKey])
    self.includeManifestResponseCertificateChain = includeManifestResponseCertificateChain
  }
  
  /**
   * String escaping is defined by https://www.rfc-editor.org/rfc/rfc8941.html#section-3.3.3
   */
  private static func escapeStructuredHeaderStringItem(_ str: String) -> String {
    return str.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
  }
  
  @objc
  public func createAcceptSignatureHeader() -> String {
    return "sig, keyid=\"\(EXUpdatesCodeSigningConfiguration.escapeStructuredHeaderStringItem(keyIdFromMetadata))\", alg=\"\(EXUpdatesCodeSigningConfiguration.escapeStructuredHeaderStringItem(algorithmFromMetadata.rawValue))\""
  }
  
  @objc
  public func validateSignature(signatureHeaderInfo: EXUpdatesSignatureHeaderInfo, signedData: Data, manifestResponseCertificateChain: String?) throws -> NSNumber {
    let certificateChain: EXUpdatesCertificateChain
    if (self.includeManifestResponseCertificateChain) {
      certificateChain = try EXUpdatesCertificateChain(
        certificateStrings: EXUpdatesCodeSigningConfiguration.separateCertificateChain(certificateChainInManifestResponse: manifestResponseCertificateChain ?? "") + [self.embeddedCertificateString]
      )
    } else {
      // check that the key used to sign the response is the same as the key in the code signing certificate
      if (signatureHeaderInfo.keyId != self.keyIdFromMetadata) {
        throw EXUpdatesCodeSigningConfigurationError.KeyIdMismatchError
      }

      // note that a mismatched algorithm doesn't fail early. it still tries to verify the signature with the
      // algorithm specified in the configuration
      if (signatureHeaderInfo.algorithm != self.algorithmFromMetadata) {
        NSLog("Key with alg=\(signatureHeaderInfo.algorithm) from signature does not match client configuration algorithm, continuing")
      }

      certificateChain = try EXUpdatesCertificateChain(certificateStrings: [embeddedCertificateString])
    }
    
    // For now only SHA256withRSA is supported. This technically should be `metadata.algorithm` but
    // it breaks down when metadata is for a different key than the signing key (the case where intermediate
    // certs are served alongside the manifest and the metadata is for the root embedded cert).
    // In the future if more methods are added we will need to be sure that we think about how to
    // specify what algorithm should be used in the chain case. One approach may be that in the case of
    // chains served alongside the manifest we fork the behavior to trust the `info.algorithm` while keeping
    // `metadata.algorithm` for the embedded case.
    let (secCertificate, _) = try certificateChain.codeSigningCertificate()
    
    guard let publicKey = SecCertificateCopyKey(secCertificate) else {
      throw EXUpdatesCodeSigningConfigurationError.CertificateParseError
    }
    
    guard let signatureData = Data(base64Encoded: signatureHeaderInfo.signature) else {
      throw EXUpdatesCodeSigningConfigurationError.SignatureEncodingError
    }
    
    let isValid = try self.verifyRSASHA256SignedData(signedData: signedData, signatureData: signatureData, publicKey: publicKey)
    return isValid ? NSNumber(booleanLiteral: true) : NSNumber(booleanLiteral: false)
  }
  
  private func sha256(data : Data) -> Data {
    var digest = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes { bytes in
      digest.withUnsafeMutableBytes { mutableBytes in
        _ = CC_SHA256(bytes.baseAddress, CC_LONG(data.count), mutableBytes.bindMemory(to: UInt8.self).baseAddress)
      }
    }
    return digest
  }
  
  private func verifyRSASHA256SignedData(signedData: Data, signatureData: Data, publicKey: SecKey) throws -> Bool {
    let hashBytes = self.sha256(data: signedData)
    var error: Unmanaged<CFError>?
    if SecKeyVerifySignature(publicKey, .rsaSignatureDigestPKCS1v15SHA256, hashBytes as CFData, signatureData as CFData, &error) {
      return true
    } else {
      if let error = error, (error.takeRetainedValue() as Error as NSError).code != errSecVerifyFailed {
        print(error.takeRetainedValue())
        throw EXUpdatesCodeSigningConfigurationError.SecurityFrameworkError
      }
      return false
    }
  }
  
  private static func separateCertificateChain(certificateChainInManifestResponse: String) -> [String] {
    let startDelimiter = "-----BEGIN CERTIFICATE-----"
    let endDelimiter = "-----END CERTIFICATE-----"
    var certificateStringList = [] as [String]
    
    var currStartIndex = certificateChainInManifestResponse.startIndex
    while (true) {
      let startIndex = certificateChainInManifestResponse.firstIndex(of: startDelimiter, startingAt: currStartIndex)
      let endIndex = certificateChainInManifestResponse.firstIndex(of: endDelimiter, startingAt: currStartIndex)
      
      if let startIndex = startIndex, let endIndex = endIndex {
        let newEndIndex = certificateChainInManifestResponse.index(endIndex, offsetBy: endDelimiter.count)
        certificateStringList.append(String(certificateChainInManifestResponse[startIndex...newEndIndex]))
        currStartIndex = newEndIndex
      } else {
        break
      }
    }

    return certificateStringList
  }
}

extension String {
  func firstIndex(of: String, startingAt: String.Index) -> String.Index? {
    return self[startingAt...].range(of: of)?.lowerBound
  }
}
