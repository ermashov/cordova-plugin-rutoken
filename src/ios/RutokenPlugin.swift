//
//  RutokenPlugin.swift
//  rutoken-swift
//
//  Created by Boris Bengus on 28.01.2021.
//

import Foundation

@objc(RutokenPlugin) 
class RutokenPlugin: CDVPlugin {
    // private let LOG_TAG = "RutokenPlugin"

    override func pluginInitialize() {
        super.pluginInitialize()
    }

    func initialize(command: CDVInvokedUrlCommand) {
        // let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK)
        // self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
    }

    // func addPermission(command: CDVInvokedUrlCommand) {
    //     let message = command.argumentAtIndex(1) != nil ? "\(command.argumentAtIndex(1))" : ""
    //     pscope!.addPermission(self.permissionMethods![command.argumentAtIndex(0) as! String]!() as! Permission, message: message)
    //     let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK)
    //     self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
    // }

    // func show(command: CDVInvokedUrlCommand) {
    //     pscope!.show()
    //     let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK)
    //     self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
    // }

    // func requestPermission(command: CDVInvokedUrlCommand) {
    //     let type = command.argumentAtIndex(0) as! String

    //     self.pscope!.viewControllerForAlerts = self.viewController
    //     self.requestMethods![type]!()

    //     let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK)
    //     self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
    // }
}
