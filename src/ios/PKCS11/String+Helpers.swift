//
//  String+Helpers.swift
//  rutoken-swift
//
//  Created by Boris Bengus on 27.01.2021.
//

import Foundation

extension String {
    static func fromInt8(_ bytes: UnsafeMutablePointer<Int8>?) -> String? {
        if let bytes = bytes {
            return String(cString: bytes)
        } else {
            return nil
        }
    }
    
    static func fromUInt8(_ bytes: UnsafeMutablePointer<UInt8>?) -> String? {
        if let bytes = bytes {
            return String(cString: bytes)
        } else {
            return nil
        }
    }
}
