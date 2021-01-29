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

    
    // MARK: - Plugin initialization
    override func pluginInitialize() {
        super.pluginInitialize()
        // Do smth on plugin initialization
    }
    
    
    // MARK: - Plugin commands
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
    
    @objc(login:)
    func login(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            
            guard let pin = command.arguments[0] as? String else {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "use { pin: 'string' }."),
                    callbackId: command.callbackId
                )
                return
            }
            
            PKCS11Wrapper.shared.login(pin: pin) { [weak self] result in
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
    
    @objc(cmsEncrypt:)
    func cmsEncrypt(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            
            guard
                let certStrings = command.arguments[0] as? [String],
                let dataString = command.arguments[1] as? String,
                let data = dataString.data(using: .utf8) else
            {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "use { certs: ['', '', ...], data: 'utf-8 string for encrypting' }."),
                    callbackId: command.callbackId
                )
                return
            }
            let recipientPems = certStrings.compactMap { Data(base64Encoded: $0) }
            guard !recipientPems.isEmpty else {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "wrong base64 pems sent to certs param."),
                    callbackId: command.callbackId
                )
                return
            }
            
            PKCS11Wrapper.shared.cmsEncrypt(
                data,
                recipientPems: recipientPems
            ) { [weak self] result in
                guard let self = self else { return }

                let pluginResult: CDVPluginResult
                switch result {
                case .success(let encryptedData):
                    pluginResult = CDVPluginResult(
                        status: .ok,
                        messageAs: encryptedData.base64EncodedString()
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
    
    @objc(cmsDecrypt:)
    func cmsDecrypt(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            
            guard
                let ckaId = command.arguments[0] as? String,
                let base64String = command.arguments[1] as? String,
                let data = Data(base64Encoded: base64String) else
            {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "use { ckaId: 'id from getCertificates', data: 'encrypted base64' }."),
                    callbackId: command.callbackId
                )
                return
            }
            
            PKCS11Wrapper.shared.cmsDecrypt(
                ckaId: ckaId,
                data: data
            ) { [weak self] result in
                guard let self = self else { return }

                let pluginResult: CDVPluginResult
                switch result {
                case .success(let decryptedData):
                    pluginResult = CDVPluginResult(
                        status: .ok,
                        messageAs: String(data: decryptedData, encoding: .utf8)
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
    
    @objc(cmsSign:)
    func cmsSign(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            
            guard
                let ckaId = command.arguments[0] as? String,
                let dataString = command.arguments[1] as? String,
                let data = dataString.data(using: .utf8) else
            {
                self.commandDelegate?.send(
                    self.wrongParamsResult(message: "use { ckaId: 'id from getCertificates', data: 'utf-8 string for signing' }."),
                    callbackId: command.callbackId
                )
                return
            }
            
            PKCS11Wrapper.shared.cmsSign(
                ckaId: ckaId,
                data: data
            ) { [weak self] result in
                guard let self = self else { return }

                let pluginResult: CDVPluginResult
                switch result {
                case .success(let signedData):
                    pluginResult = CDVPluginResult(
                        status: .ok,
                        messageAs: signedData.base64EncodedString()
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
    
    
    // MARK: - Private
    private struct TokenAddResponse: Encodable {
        let event = "add"
        let tokenInfo: TokenDto
    }

    private struct TokenRemoveResponse: Encodable {
        let event = "remove"
        let tokenInfo: SlotDto
    }
    
    private func wrongParamsResult(message: String) -> CDVPluginResult {
        return CDVPluginResult(
            status: .error,
            messageAs: "Wrong params error: \(message)"
        )
    }
}
