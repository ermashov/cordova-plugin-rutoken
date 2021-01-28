//
//  RutokenPlugin.swift
//  rutoken-swift
//
//  Created by Boris Bengus on 28.01.2021.
//

import Foundation

@objc(RutokenPlugin) 
class RutokenPlugin: CDVPlugin {
    private lazy var jsonEncoder = JSONEncoder()

    override func pluginInitialize() {
        super.pluginInitialize()
        // Do smth on plugin initialization
    }
    
    @objc(initializeEngine:)
    func initializeEngine(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
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
    }
    
    @objc(getTokens:)
    func getTokens(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            PKCS11Wrapper.shared.getTokens { [weak self] result in
                guard let self = self else { return }
                
                let pluginResult: CDVPluginResult
                switch result {
                case .success(let tokens):
                    let jsonData = try! self.jsonEncoder.encode(tokens)
                    let jsonString = String(data: jsonData, encoding: .utf8)
                    pluginResult = CDVPluginResult(
                        status: .ok,
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
    
    @objc(getCertificates:)
    func getCertificates(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            PKCS11Wrapper.shared.getCertificates { [weak self] result in
                guard let self = self else { return }
                
                let pluginResult: CDVPluginResult
                switch result {
                case .success(let certificates):
                    let jsonData = try! self.jsonEncoder.encode(certificates)
                    let jsonString = String(data: jsonData, encoding: .utf8)
                    pluginResult = CDVPluginResult(
                        status: .ok,
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
    
    @objc(waitForSlotEvent:)
    func waitForSlotEvent(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            PKCS11Wrapper.shared.startMonitoring(
                onTokenAdd: { [weak self] token in
                    guard let self = self else { return }
                    
                    let response = TokenAddResponse(tokenInfo: token)
                    let jsonData = try! self.jsonEncoder.encode(response)
                    let jsonString = String(data: jsonData, encoding: .utf8)
                    let pluginResult = CDVPluginResult(
                        status: .ok,
                        messageAs: jsonString
                    )
                    pluginResult?.setKeepCallbackAs(true)
                    self.commandDelegate?.send(pluginResult, callbackId: command.callbackId)
                },
                onTokenRemove: { [weak self] slot in
                    guard let self = self else { return }
                    
                    let response = TokenRemoveResponse(tokenInfo: slot)
                    let jsonData = try! self.jsonEncoder.encode(response)
                    let jsonString = String(data: jsonData, encoding: .utf8)
                    let pluginResult = CDVPluginResult(
                        status: .ok,
                        messageAs: jsonString
                    )
                    pluginResult?.setKeepCallbackAs(true)
                    self.commandDelegate?.send(pluginResult, callbackId: command.callbackId)
                }
            )
        }
    }
}

private struct TokenAddResponse: Encodable {
    let event = "add"
    let tokenInfo: TokenDto
}

private struct TokenRemoveResponse: Encodable {
    let event = "remove"
    let tokenInfo: SlotDto
}
