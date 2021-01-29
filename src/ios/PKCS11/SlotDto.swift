//
//  SlotDto.swift
//  rutoken-swift
//
//  Created by Boris Bengus on 27.01.2021.
//

import Foundation

/// Моделька слота без токена
public struct SlotDto: Codable {
    public let slotId: Int
    
    public init(from slotPointer: UnsafeMutablePointer<PKCS11_SLOT>) {
        self.slotId = Int(PKCS11_get_slotid_from_slot(slotPointer))
    }
}
