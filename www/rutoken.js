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

if (!window.plugins) {
    window.plugins = {};
}
if (!window.plugins.rutoken) {
    window.plugins.rutoken = new Rutoken();
}

if (module.exports) {
    module.exports = Rutoken;
}