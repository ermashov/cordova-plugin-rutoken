//
//  RutokenPlugin.swift
//  rutoken-swift
//
//  Created by Boris Bengus on 28.01.2021.
//

import Foundation

@objc(RutokenPlugin) 
class RutokenPlugin: CDVPlugin {
    private lazy var jsonEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToUpperCamelCase
        encoder.outputFormatting =  .prettyPrinted
        
        return encoder
    }()

    override func pluginInitialize() {
        super.pluginInitialize()
        // Do smth on plugin initialization
    }
    
    @objc(initializeEngine:)
    func initializeEngine(command: CDVInvokedUrlCommand) {
        PKCS11Wrapper.shared.initialize { [weak self] result in
            guard let self = self else { return }
            
            let pluginResult: CDVPluginResult
            switch result {
            case .success:
                pluginResult = CDVPluginResult(status: .ok)
            case .failure(let error):
                pluginResult = CDVPluginResult(
                    status: .error,
                    messageAs: error.localizedDescription
                )
            }
            self.commandDelegate?.send(pluginResult, callbackId: command.callbackId)
        }
    }
    
    @objc(getTokens:)
    func getTokens(command: CDVInvokedUrlCommand) {
        PKCS11Wrapper.shared.getTokens { [weak self] result in
            guard let self = self else { return }
            
            let pluginResult: CDVPluginResult
            switch result {
            case .success(let tokens):
                let jsonData = try! self.jsonEncoder.encode(tokens)
                let jsonString = String(data: jsonData, encoding: .utf8)
                pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_OK,
                    messageAs: jsonString
                )
            case .failure(let error):
                pluginResult = CDVPluginResult(
                    status: .error,
                    messageAs: error.localizedDescription
                )
            }
            self.commandDelegate?.send(pluginResult, callbackId: command.callbackId)
        }
    }
}
