(function ($) {

    function Settings(s) {
        var settings = {
            publicKey: "publicKey",
            privateKey: "privateKey",
            password: "password"
        };

        if (typeof s === "undefined")
            alert("The host is not set");
        else {
            if (typeof s.host === "undefined") 
                alert("The host is not set");

            if (typeof s.publicKey === "undefined")
                s["publicKey"] = settings.publicKey;

            if (typeof s.privateKey === "undefined")
                s["privateKey"] = settings.privateKey;

            if(typeof s.password === "undefined")
                s["password"] = settings.password;
        }

        return s;
    }

    $.fn.uSign = function (settings) {
        var sign = this;
        settings = Settings(settings);

        sign = $.extend(this,
        {
            FormInstance: function (token, environmentId, formInstanceId) {
                if (typeof token === "undefined" || token === '') {
                    sign.trigger("error", "The token has not been specified");
                    return;
                }

                if (typeof environmentId === "undefined" || token === '') {
                    sign.trigger("error", "The environment has not been specified");
                    return;
                }
                if (typeof formInstanceId === "undefined" || token === '') {
                    sign.trigger("error", "The form instance has not been specified");
                    return;
                }
                
                sign.trigger("starting");

                var formData = new FormData();
                var publicKey = $("#" + settings.publicKey)[0].files[0];
                var privateKey = $("#" + settings.privateKey)[0].files[0];
                var password = $("#" + settings.password).val();

                formData.append("token", token);
                formData.append("environmentId", environmentId);
                formData.append("formInstanceId", formInstanceId);
                formData.append("publicKey", publicKey);

                $.ajax({
                    url: settings.host + "/Execution/Sign/FormInstance/Start",
                    data: formData,
                    processData: false,
                    contentType: false,
                    enctype: 'multipart/form-data',
                    type: 'POST'
                })
                    .done(function (result) {
                        if (result.error === '') 
                            SealWithPrivateKey(publicKey, privateKey, password, result);
                        else
                            sign.trigger("error", result.error);
                    })
                    .fail(function (jqXHR, textStatus, errorThrown) {
                        sign.trigger("error", errorThrown);
                    });
            }
        });

        function SealWithPrivateKey(publicKey, privateKey, password, pkr) {
            Signature.Crypto.SignAsync(privateKey, password, pkr.sealWithPublicKey, "sha256")
                .done(function (result) {
                    if (result.error) {
                        sign.trigger("error", result.error);
                        return;
                    }
                    
                    var formData = new FormData();
                    formData.append("number", pkr.number);
                    formData.append("publicKey", publicKey);
                    formData.append("sealWithPrivateKey", Signature.Crypto.ArrayToBase64(result.signatureAsArray));

                    $.ajax({
                        url: settings.host + "/Execution/Sign/FormInstance/End",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        type: 'POST'                      
                    })
                        .done(function (result) {
                            if (result === '') {
                                sign.trigger("done");
                            } else {
                                sign.trigger("error", result);
                            }
                            
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            sign.trigger("error", errorThrown);
                        });
                })
                .fail(function (result) {
                    sign.trigger("error", result.error);
                });
        };

        return sign;
    };

    $.fn.uSignIn = function (settings) {
        var signIn = this;        
        settings = Settings(settings);

        signIn = $.extend(signIn,
            {
                Go: function () {
                    signIn.trigger("starting");
                    
                    var formData = new FormData();
                    formData.append("certificate", $("#" + settings.certificate)[0].files[0]);

                    $.ajax({
                        type: "POST",
                        enctype: "multipart/form-data",
                        url: settings.host + "/Execution/SignIn",
                        data: formData
                    })
                        .done(function (result) {
                            Signature.Crypto.SignAsync($("#" + settings.key)[0].files[0], $("#" + settings.password)[0].files[0], "SignIn", "sha256")
                                .done(function (result) {
                                    signIn.trigger("done");
                                })
                                .fail(function (result) {
                                    signIn.trigger("error", result.error);
                                });
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            if (jqXHR.status == 0)
                                signIn.trigger("error", "The signature service is not found");
                            else
                                signIn.trigger("error", errorThrown);
                        });
                }
            });

        return signIn;
    };

})(jQuery);