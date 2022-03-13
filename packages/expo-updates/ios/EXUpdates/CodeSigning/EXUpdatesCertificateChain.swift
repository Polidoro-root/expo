// Copyright 2015-present 650 Industries. All rights reserved.

import Foundation
import ASN1Decoder

public enum EXUpdatesCertificateChainError : Int, Error {
  case CertificateEmptyError
  case CertificateMissingCodeSigningError
  case CertificateChainError
}

/**
 * Full certificate chain for verifying code signing.
 * The chain should look like the following:
 *    0: code signing certificate
 *    1...n-1: intermediate certificates
 *    n: root certificate
 *
 * Requirements:
 * - Length(certificateChain) > 0
 * - certificate chain is valid and each certificate is valid
 * - 0th certificate is a valid code signing certificate
 */
class EXUpdatesCertificateChain {
  // ASN.1 path to the extended key usage info within a CERT
  static let EXUpdatesCodeSigningCertificateExtendedUsageCodeSigningOID = "1.3.6.1.5.5.7.3.3"
  
  private var certificateStrings: [String]
  
  public required init(certificateStrings: [String]) throws {
    self.certificateStrings = certificateStrings
  }
  
  public func codeSigningCertificate() throws -> (SecCertificate, X509Certificate) {
    if (certificateStrings.isEmpty) {
      throw EXUpdatesCertificateChainError.CertificateEmptyError
    }
    
    let certificateChain = try certificateStrings.map { certificateString throws in
      try EXUpdatesCertificateChain.constructCertificate(certificateString: certificateString)
    }
    try EXUpdatesCertificateChain.validateChain(certificateChain: certificateChain)
    guard let leafCertificate = certificateChain.first else {
      throw EXUpdatesCertificateChainError.CertificateEmptyError
    }
    if (!EXUpdatesCertificateChain.isCodeSigningCertificate(certificate: leafCertificate)) {
      throw EXUpdatesCertificateChainError.CertificateMissingCodeSigningError
    }
    return leafCertificate
  }
  
  private static func constructCertificate(certificateString: String) throws -> (SecCertificate, X509Certificate) {
    guard let certificateData = certificateString.data(using: .utf8) else { throw EXUpdatesCodeSigningConfigurationError.CertificateParseError }
    
    guard let certificateDataDer = decodeToDER(pem: certificateData) else {
      throw EXUpdatesCodeSigningConfigurationError.CertificateParseError
    }
    
    let x509Certificate = try X509Certificate(der: certificateDataDer)
    
    guard x509Certificate.checkValidity() else {
      throw EXUpdatesCodeSigningConfigurationError.CertificateValidityError
    }
    
    guard let secCertificate = SecCertificateCreateWithData(nil, certificateDataDer as CFData) else {
      throw EXUpdatesCodeSigningConfigurationError.CertificateParseError
    }
    
    return (secCertificate, x509Certificate)
  }
  
  private static func validateChain(certificateChain: [(SecCertificate, X509Certificate)]) throws {
//    for i in 0...(certificateChain.count - 2) {
//      let (certSecCert, certCert) = certificateChain[i]
//      let (issuerSecCert, issuerCert) = certificateChain[i + 1]
//
//      if (certCert.issuerDistinguishedName != issuerCert.subjectDistinguishedName) {
//        throw EXUpdatesCertificateChainError.CertificateChainError
//      }
//
//      SecCertificate
//    }
    
    let secCertificates = certificateChain.map { (secCertificate, _) in
      secCertificate
    }
    let policy = SecPolicyCreateBasicX509()
    var optionalTrust: SecTrust?
    let status = SecTrustCreateWithCertificates(secCertificates as AnyObject, policy, &optionalTrust)
    guard status == errSecSuccess else { return }
    let trust = optionalTrust!
    
    let anchorCert = secCertificates.last
    let anchors = [anchorCert]
    SecTrustSetAnchorCertificates(trust, anchors as CFArray)
    
    var error: CFError?
    if SecTrustEvaluateWithError(trust, &error) {
      return
    } else {
      if let error = error {
        print(error)
      }
      throw EXUpdatesCertificateChainError.CertificateChainError
    }
  }
  
  private static func isCACertificate(certificate: (SecCertificate, X509Certificate)) -> Bool {
    let (_, x509Certificate) = certificate
    
    if let ext = x509Certificate.extensionObject(oid: .basicConstraints) as? X509Certificate.BasicConstraintExtension {
      if (!ext.isCA) {
        return false
      }
    } else {
      return false
    }
    
    let keyUsage = x509Certificate.keyUsage
    if (keyUsage.isEmpty || !keyUsage[5]) {
      return false
    }
    
    return true
  }
  
  private static func isCodeSigningCertificate(certificate: (SecCertificate, X509Certificate)) -> Bool {
    let (_, x509Certificate) = certificate
    
    let keyUsage = x509Certificate.keyUsage
    if (keyUsage.isEmpty || !keyUsage[0]) {
      return false
    }
    
    let extendedKeyUsage = x509Certificate.extendedKeyUsage
    if (!extendedKeyUsage.contains(EXUpdatesCertificateChain.EXUpdatesCodeSigningCertificateExtendedUsageCodeSigningOID)) {
      return false
    }
    
    return true
  }
  
  private static let beginPemBlock = "-----BEGIN CERTIFICATE-----"
  private static let endPemBlock   = "-----END CERTIFICATE-----"
  
  /**
   * Mostly from ASN1Decoder with the fix for disallowing multiple certificatess in the PEM.
   */
  private static func decodeToDER(pem pemData: Data) -> Data? {
    guard let pem = String(data: pemData, encoding: .ascii) else {
      return nil
    }
    
    if pem.components(separatedBy: beginPemBlock).count - 1 != 1 {
      return nil
    }
    
    let lines = pem.components(separatedBy: .newlines)
    var base64buffer  = ""
    var certLine = false
    for line in lines {
      if line == endPemBlock {
        certLine = false
      }
      if certLine {
        base64buffer.append(line)
      }
      if line == beginPemBlock {
        certLine = true
      }
    }
    if let derDataDecoded = Data(base64Encoded: base64buffer) {
      return derDataDecoded
    }
    
    return nil
  }
}
