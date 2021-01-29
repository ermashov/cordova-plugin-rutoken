//
//  TokenDto.swift
//  rutoken-swift
//
//  Created by Boris Bengus on 27.01.2021.
//

import Foundation

/// Моделька токена
public struct TokenDto: Codable {
    public let slotId: Int
    public let label: String?
    public let model: String?
    public let serialNumber: String?
    
    public init(from slotPointer: UnsafeMutablePointer<PKCS11_SLOT>) {
        let slot = slotPointer.pointee
        
        self.slotId = Int(PKCS11_get_slotid_from_slot(slotPointer))
        if let token = slot.token {
            self.label = String.fromInt8(token.pointee.label)
            self.model = String.fromInt8(token.pointee.model)
            self.serialNumber = String.fromInt8(token.pointee.serialnr)
        } else {
            self.label = nil
            self.model = nil
            self.serialNumber = nil
        }
    }
}
