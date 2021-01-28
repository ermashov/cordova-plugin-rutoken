//
//  JSONEncoder+CodingStrategy.swift
//  rutoken-swift
//
//  Created by Boris Bengus on 28.01.2021.
//

import Foundation

// wrapper to allow us to substitute our mapped string keys.
struct AnyCodingKey : CodingKey {
    var stringValue: String
    var intValue: Int?
    
    init(_ base: CodingKey) {
        self.init(stringValue: base.stringValue, intValue: base.intValue)
    }
    
    init(stringValue: String) {
        self.stringValue = stringValue
    }
    
    init(intValue: Int) {
        self.stringValue = "\(intValue)"
        self.intValue = intValue
    }
    
    init(stringValue: String, intValue: Int?) {
        self.stringValue = stringValue
        self.intValue = intValue
    }
}

extension JSONEncoder.KeyEncodingStrategy {
    static var convertToUpperCamelCase: JSONEncoder.KeyEncodingStrategy {
        return .custom { codingKeys in
            
            var key = AnyCodingKey(codingKeys.last!)
            
            // uppercase first letter
            if let firstChar = key.stringValue.first {
                let i = key.stringValue.startIndex
                key.stringValue.replaceSubrange(
                    i ... i, with: String(firstChar).uppercased()
                )
            }
            return key
        }
    }
}
