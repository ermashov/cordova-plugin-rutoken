var Rutoken = function() {};

Rutoken.prototype.getTokens = function(success, fail) {
    cordova.exec(success, fail, 'RutokenPlugin', 'getTokens', []);
};

Rutoken.prototype.waitForSlotEvent = function(success, fail) {
    cordova.exec(success, fail, 'RutokenPlugin', 'waitForSlotEvent', []);
};

Rutoken.prototype.getCertificates = function(params, success, fail) {
    cordova.exec(success, fail, 'RutokenPlugin', 'getCertificates', [
        params.slotId,
    ]);
};

Rutoken.prototype.cmsSign = function(params, success, fail) {
    cordova.exec(success, fail, 'RutokenPlugin', 'cmsSign', [
        params.slotId,
        params.pin,
        params.ckaId,
        params.data,
    ]);
};
Rutoken.prototype.cmsEncrypt = function(params, success, fail) {
    cordova.exec(success, fail, 'RutokenPlugin', 'cmsEncrypt', [
        params.slotId,
        params.pin,
        params.ckaId,
        params.data,
    ]);
};
Rutoken.prototype.cmsDecrypt = function(params, success, fail) {
    cordova.exec(success, fail, 'RutokenPlugin', 'cmsDecrypt', [
        params.slotId,
        params.pin,
        params.ckaId,
        params.data,
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