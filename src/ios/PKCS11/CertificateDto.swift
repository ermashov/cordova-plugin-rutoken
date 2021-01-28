//
//  CertificateDto.swift
//  rutoken-swift
//
//  Created by Boris Bengus on 27.01.2021.
//

import Foundation

public struct CertificateDto: Codable {
    public struct Issuer: Codable {
        public let c: String?
        public let sT: String?
        public let l: String?
        public let o: String?
        public let oU: String?
        public let cN: String?
        
        public init(from x509: OpaquePointer) {
            let issuerName = X509_get_issuer_name(x509)
            
            self.c = getText(from: issuerName, by: NID_countryName)
            self.sT = getText(from: issuerName, by: NID_streetAddress)
            self.l = getText(from: issuerName, by: NID_localityName)
            self.o = getText(from: issuerName, by: NID_organizationName)
            self.oU = getText(from: issuerName, by: NID_organizationalUnitName)
            self.cN = getText(from: issuerName, by: NID_commonName)
        }
    }
    
    public struct Subject: Codable {
        public let email: String?
        public let c: String?
        public let sT: String?
        public let l: String?
        public let o: String?
        public let cN: String?
        
        public init(from x509: OpaquePointer) {
            let subjectName = X509_get_subject_name(x509)
            
            let emailStack = X509_get1_email(x509)
            if
                let emailStack = emailStack,
                let emailBytes = sk_OPENSSL_STRING_value(emailStack, 0)
            {
                self.email = String.fromInt8(emailBytes)
            } else {
                self.email = nil
            }
            X509_email_free(emailStack)
            self.c = getText(from: subjectName, by: NID_countryName)
            self.sT = getText(from: subjectName, by: NID_streetAddress)
            self.l = getText(from: subjectName, by: NID_localityName)
            self.o = getText(from: subjectName, by: NID_organizationName)
            self.cN = getText(from: subjectName, by: NID_commonName)
        }
    }
    
    public let ckaId: String
    public let issuer: Issuer
    public let subject: Subject
    /// base64 pem сертификата
    public let pem: String
    public let serialNumber: String?
    
    public init(from certPointer: UnsafeMutablePointer<PKCS11_CERT>) {
        let x509 = certPointer.pointee.x509!
        // Падаем и разбираемся. сертификат без айдишника невозможен.
        self.ckaId = String.fromUInt8(certPointer.pointee.id)!
        self.issuer = Issuer(from: x509)
        self.subject = Subject(from: x509)
        // Кодируем x509 в base64
        let x509Length = i2d_X509(x509, nil)
        var x509Data = Data(repeating: 0x00, count: Int(x509Length))
        x509Data.withUnsafeMutableBytes {
            var pointer = $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
            i2d_X509(x509, &pointer)
        }
        self.pem = x509Data.base64EncodedString()
        // Достаем serial_number в hex
        if let serialAsn1 = X509_get0_serialNumber(x509) {
            let serialData = Data(buffer: UnsafeBufferPointer(start: serialAsn1.pointee.data, count: Int(serialAsn1.pointee.length)))
            self.serialNumber = serialData.hexEncodedString(options: .upperCase)
        } else {
            self.serialNumber = nil
        }
    }
}

private func getText(
    from x509Name: OpaquePointer?,
    by nid: Int32
) -> String? {
    guard let x509Name = x509Name else { return nil }
    let len = X509_NAME_get_text_by_NID(x509Name, nid, nil, 0) + 1
    guard len > 0 else { return nil }
    var cString: [Int8] = Array(repeating: 0, count: Int(len))
    X509_NAME_get_text_by_NID(x509Name, nid, &cString, len)
    let string = String(cString: cString)
    
    return string
}
