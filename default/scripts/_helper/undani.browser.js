﻿// Para la tolerancia de compatibilidad con JQuery 1.9
var matched, browser;

jQuery.uaMatch = function (ua) {
    ua = ua.toLowerCase();

    var match = /(chrome)[ \/]([\w.]+)/.exec(ua) ||
        /(webkit)[ \/]([\w.]+)/.exec(ua) ||
        /(opera)(?:.*version|)[ \/]([\w.]+)/.exec(ua) ||
        /(msie) ([\w.]+)/.exec(ua) ||
        ua.indexOf("compatible") < 0 && /(mozilla)(?:.*? rv:([\w.]+)|)/.exec(ua) ||
        [];

    return {
        browser: match[1] || "",
        version: match[2] || "0"
    };
};

matched = jQuery.uaMatch(navigator.userAgent);
browser = {};

if (matched.browser) {
    browser[matched.browser] = true;
    browser.version = matched.version;
}

// Chrome es Webkit, pero Webkit también es Safari.
if (browser.chrome) {
    browser.webkit = true;
} else if (browser.webkit) {
    browser.safari = true;
}

jQuery.browser = browser;