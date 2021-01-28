//
//  PKCS11Error.swift
//  rutoken-swift
//
//  Created by Boris Bengus on 27.01.2021.
//

import Foundation

public enum PKCS11Error: LocalizedError {
    case generalError
    case loginRequired
    case loginFailed
    case enumeratingSlotsFailed
    case enumeratingCertificatesFailed
    case enumeratingKeysFailed
    case keyPairNotFound
    case tokenDisconnected
    case unknown(reason: Error)
    
    public static func wrapError(_ error: Error) -> PKCS11Error {
        if let error = error as? PKCS11Error {
            return error
        } else {
            return .unknown(reason: error)
        }
    }
    
    
    // MARK: - LocalizedError
    public var errorDescription: String? {
        switch self {
        case .generalError:
            return "PKCS11 general error"
        case .loginRequired:
            return "PKCS11 token login required"
        case .loginFailed:
            return "PKCS11 token login failed"
        case .enumeratingSlotsFailed:
            return "PKCS11 enumerating slots failed"
        case .enumeratingCertificatesFailed:
            return "PKCS11 enumerating certificates failed"
        case .enumeratingKeysFailed:
            return "PKCS11 enumerating keys failed"
        case .keyPairNotFound:
            return "PKCS11 key pair not found"
        case .tokenDisconnected:
            return "PKCS11 token disconnected"
        case .unknown(let reason):
            return "PKCS11 unknown error: \(reason.localizedDescription)"
        }
    }
}
