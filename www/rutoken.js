cordova.define("cordova-plugin-rutoken.Rutoken", function(require, exports, module) {
    var Rutoken = function() {};


    Rutoken.prototype.init = function(success, fail) {
        cordova.exec(success, fail, 'RutokenPlugin', 'init', []);
    };


    Rutoken.prototype.getTokenInfo = function(params, success, fail) {
        cordova.exec(success, fail, 'RutokenPlugin', 'getTokenInfo', [
            params.slotId,
        ]);
    };

    Rutoken.prototype.getCertificates = function(success, fail) {
        cordova.exec(success, fail, 'RutokenPlugin', 'getCertificates', []);
    };

    Rutoken.prototype.getTokens = function(success, fail) {
        cordova.exec(success, fail, 'RutokenPlugin', 'getTokens', []);
    };

    Rutoken.prototype.waitForSlotEvent = function(success, fail) {
        cordova.exec(success, fail, 'RutokenPlugin', 'waitForSlotEvent', []);
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
