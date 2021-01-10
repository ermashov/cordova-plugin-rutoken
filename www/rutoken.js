cordova.define("cordova-plugin-rutoken.Rutoken", function(require, exports, module) {
    var Rutoken = function() {};


    Rutoken.prototype.waitForSlotEvent = function(success, fail) {
        cordova.exec(success, fail, 'RutokenPlugin', 'waitForSlotEvent', []);
    };

    Rutoken.prototype.getCertificates = function(params, success, fail) {
        cordova.exec(success, fail, 'RutokenPlugin', 'getCertificates', [
            params.slotId,
        ]);
    };

    Rutoken.prototype.getTokens = function(success, fail) {
        cordova.exec(success, fail, 'RutokenPlugin', 'getTokens', []);
    };

    Rutoken.prototype.getTokenInfo = function(params, success, fail) {
        cordova.exec(success, fail, 'RutokenPlugin', 'getTokenInfo', [
            params.slotId,
        ]);
    };

    if (!window.plugins) {
        window.plugins = {};
    }
    if (!window.plugins.rutoken) {
        window.plugins.rutoken = new Rutoken();
    }

    if (module.exports) {
        module.exports = Rutoken;
    }
});
