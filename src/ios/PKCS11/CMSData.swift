//
//  CMSData.swift
//  rutoken-swift
//
//  Created by Boris Bengus on 28.01.2021.
//

import Foundation

public enum CMSData {
    public static func cmsEncrypt(
        _ document: Data,
        recipientsX509Stack: OpaquePointer
    ) throws -> Data {
        // document bio
        guard let bio = BIO_new(BIO_s_mem()) else {
            throw PKCS11Error.generalError
        }
        defer {
            BIO_free(bio)
        }
        try document.withUnsafeBytes {
            let pointer = $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
            let res = BIO_write(bio, pointer, Int32(document.count))
            if res != document.count {
                throw PKCS11Error.generalError
            }
        }
        
        /// encrypt
        let flags: Int32 = 0 // CMS_STREAM
        
        // encrypt content
        let cipher = EVP_des_cbc()
        guard let encryptedCms = CMS_encrypt(recipientsX509Stack, bio, cipher, UInt32(flags)) else {
            fputs("Error CMS_encrypt\n", stderr)
            ERR_print_errors_fp(stderr)
            throw PKCS11Error.generalError
        }
        defer {
            CMS_ContentInfo_free(encryptedCms)
        }
        
        guard let encryptedBio = BIO_new(BIO_s_mem()) else {
            throw PKCS11Error.generalError
        }
        defer {
            BIO_free(encryptedBio)
        }
        i2d_CMS_bio(encryptedBio, encryptedCms)
        
        var encryptedBytesPtr: UnsafeMutableRawPointer?
        let encryptedBytesLen = BIO_ctrl(encryptedBio, BIO_CTRL_INFO, 0, &encryptedBytesPtr)
        let encryptedData = Data(bytes: encryptedBytesPtr!, count: encryptedBytesLen)
        
        return encryptedData
    }
    
    public static func cmsDecrypt(
        _ document: Data,
        x509: OpaquePointer,
        evpPKey: OpaquePointer
    ) throws -> Data
    {
        guard let bio = BIO_new(BIO_s_mem()) else {
            throw PKCS11Error.generalError
        }
        defer {
            BIO_free(bio)
        }
        
        try document.withUnsafeBytes {
            let pointer = $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
            let res = BIO_write(bio, pointer, Int32(document.count))
            if res != document.count {
                throw PKCS11Error.generalError
            }
        }
        
        var encryptedCms = CMS_ContentInfo_new()
        guard encryptedCms != nil else {
            throw PKCS11Error.generalError
        }
        defer {
            CMS_ContentInfo_free(encryptedCms)
        }
        d2i_CMS_bio(bio, &encryptedCms)
        
        // Decrypt CMS
        guard let decryptedBio = BIO_new(BIO_s_mem()) else { throw PKCS11Error.generalError }
        defer { BIO_free(decryptedBio) }
        
        let r = CMS_decrypt(encryptedCms, evpPKey, x509, nil, decryptedBio, 0)
        guard r == 1 else {
            fputs("Error Decrypting Data\n", stderr)
            ERR_print_errors_fp(stderr)
            throw PKCS11Error.generalError
        }
        
        var decryptedBytesPtr: UnsafeMutableRawPointer?
        let decryptedBytesLen = BIO_ctrl(decryptedBio, BIO_CTRL_INFO, 0, &decryptedBytesPtr)
        let decryptedData = Data(bytes: decryptedBytesPtr!, count: decryptedBytesLen)
        
        return decryptedData
    }
    
    public static func cmsSign(
        _ document: Data,
        x509: OpaquePointer,
        evpPKey: OpaquePointer
    ) throws -> Data
    {
        guard let bio = BIO_new(BIO_s_mem()) else {
            throw PKCS11Error.generalError
        }
        defer {
            BIO_free(bio)
        }
        try document.withUnsafeBytes {
            let pointer = $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
            let res = BIO_write(bio, pointer, Int32(document.count))
            if res != document.count {
                throw PKCS11Error.generalError
            }
        }
        
        guard let cms = CMS_sign(x509, evpPKey, nil, bio, UInt32(CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED)) else {
            throw PKCS11Error.generalError
        }
        defer {
            CMS_ContentInfo_free(cms)
        }
        
        let cmsLength = i2d_CMS_ContentInfo(cms, nil)
        var cmsData = Data(repeating: 0x00, count: Int(cmsLength))
        cmsData.withUnsafeMutableBytes {
            var pointer = $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
            i2d_CMS_ContentInfo(cms, &pointer)
        }
        
        return cmsData
    }
}
