var api;

if (document.domain == 'app.cre.gob.mx') {
    api = {
        documento: 'http://api-documento.cre.gob.mx',
        bps: 'http://api-bps.cre.gob.mx'
    };
} else {
    api = {
        documento: 'http://localhost:39833',
        bps: 'http://localhost:26636'
    };
}

function setCookie(cname, cvalue, exdays) {
    var d = new Date();
    d.setTime(d.getTime() + (exdays * 24 * 60 * 60 * 1000));
    var expires = "expires=" + d.toGMTString();
    document.cookie = cname + "=" + cvalue + "; " + expires;
}

function getCookie(cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') c = c.substring(1);
        if (c.indexOf(name) != -1) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

function checkCookie_Cargar() {

    // Permite recordar el ancla del menú
    var r = getCookie("undanianclamenu");
    if (r != "") {
        if ((r + '').toLowerCase() === 'true') {
            anclaMenu();
        }
    } else {
        setCookie("undanianclamenu", true, 365);
        anclaMenu();
    }

}

function anclaMenu() {
    document.getElementsByTagName('body')[0].className += ' menu-pin';
    document.getElementById('anclamenu').className = 'fa fs-14';
}

$(document).ready(function () {
    $('#appMenu').load('http://fw.cre.gob.mx/_Aplicaciones.html', function () {
        $('[name=UndaniApp]').click(function (e) {
            $.ajax({
                type: 'GET',
                url: '/_Aplicacion/ObtenerInicio?app=' + $(this).attr('id'),
                dataType: 'json'
            })
            .done(function (_resultado, textStatus, jqXHR) {
                if (_resultado.Errores == null) {
                    // Re-dirigir la página
                    window.location.href = _resultado.Valor;
                }
                else {
                    // Error al guardar
                    for (var i = 0; i < _resultado.Errores.length; i++) {
                        $.uMensaje({ sTipo: 'Error', sOrigen: _resultado.Errores[i].Origen, sMensaje: _resultado.Errores[i].Mensaje });
                    }
                }
            })
            .fail(function (jqXHR, textStatus, errorThrown) {
                // Error del servicio
                $.uMensaje({ sTipo: 'Error', sOrigen: jqXHR.status, sMensaje: errorThrown });
            });
        });
    });

    
});