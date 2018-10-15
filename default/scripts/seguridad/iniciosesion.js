/// <reference path="../../ui/plugins/nprogress/nprogress.js" />

$(document).ready(function (e) {

    var oValidator = $('#frmInicioSesion').uValidate({
        bShowDetail: false,
        fnMensajeError: MensajeError,
        rules: { txtUsuarioNombre: { required: true }, txtContrasena: { required: true } }
    });

    // Autenticar
    $('#btnIniciarSesion').click(function (e) {
        if (oValidator.form()) {
            // Token
            var token = $('input[name=__RequestVerificationToken]').val();
            var headers = {};
            headers['__RequestVerificationToken'] = token;

            // Usuario
            var oUsuario = {
                UsuarioNombre: $('#txtUsuarioNombre').val(),
                Contrasena: $('#txtContrasena').val(),
                Recuerdame: $('#chkRecuerdame').prop('checked')
            };

            NProgress.start();
            $.ajax({
                cache: false,
                dataType: 'json',
                type: 'POST',
                headers: headers,
                data: { jo: JSON.stringify(oUsuario), returnUrl: $('#frmInicioSesion').attr('data-return-url') },
                url: '/_Seguridad/Autenticar'
            })
            .done(function (_resultado, textStatus, jqXHR) {
                if (_resultado.Errores == null) {
                    // Re-dirigir la página
                    window.location.href = _resultado.Valor;
                } else {
                    // Errores conocidos al intentar autenticar
                    MensajeError('Los datos introducidos no son correctos.');
                }
            })
            .fail(function (jqXHR, textStatus, errorThrown) {
                MensajeError('<strong>' + error.status + ' </strong>' + error.statusText);
            })
            .always(function (jqXHR, textStatus, errorThrown) {
                NProgress.done();
            });

        } else {
            $('#login-form').effect("shake", { distance: 20, times: 3 }, 1000);
        }
    });

    function MensajeError(m) {
        $('div[role=alert]').show();
        $('div[role=alert]').html('<strong>Error: </strong>' + m)
        window.setTimeout(function () {
            $('div[role = alert]').hide();
        }, 7000);
    }

});