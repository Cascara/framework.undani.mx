(function ($) {

    var aoAcciones = new Array();
    var oValidator;
    var fnGuardar;
    var fnPreAccion;
    var fnAntesEnvio;


    $.fn.uAcciones = function (oSettings) {
        // Limpiar
        this.empty();
        aoAcciones.length = 0;

        // Función que se ejecuta antes de enviar la forma
        fnValidarAntesEnvio = oSettings.fnValidarAntesEnvio;

        // Asigna función para guardar la información
        fnGuardar = oSettings.fnGuardar;

        // Asigna funcion que se realiza antes de realizar una acción
        fnPreAccion = oSettings.fnPreAccion;

        // Asigna el objeto de validación
        oValidator = oSettings.oValidator;

        // Crear los botones de acción
        for (var i = 0; i < oSettings.aoAcciones.length; i++) {
            var id = 'cmdAccion' + oSettings.aoAcciones[i].Id;
            aoAcciones[id] = oSettings.aoAcciones[i];
            this.append('<button id="' + id +
                '" type="button" class="btn ' + oSettings.aoAcciones[i].Color +
                ' btn-accion"><i class="fa ' + oSettings.aoAcciones[i].Icono +
                '"></i>' + oSettings.aoAcciones[i].Nombre + '</button>');
        }
        $('.btn-accion').click(fnAccion);

        // Crear el boton para cerrar
        this.append('<button id="cmdCerrarEP" type="button" class="btn"><i class="fa fa-sign-out"></i>Cerrar</button>');
        $('#cmdCerrarEP').click(fnCerrar);
    };

    $.fn.uBitacora = function (aoBitacora, sUserName) {
        // Limpiar
        this.empty();
        
        var comentario = '';
        var avatar = '';
        var imagenes = new Array();
        for (var i = 0; i < aoBitacora.length; i++) {
            comentario = '<li class="' + (sUserName == aoBitacora[i].UsuarioNombre.toLowerCase() ? "by_me" : "by_user") + '">';
            comentario += '<a href="#" title=""><img src="/Content/usuario/' + aoBitacora[i].UsuarioNombre + '.jpg" alt="" /></a>'
                        + '<div class="messageArea"><span class="aro"></span><div class="infoRow">'
                        + '<span class="name"><strong>' + aoBitacora[i].UsuarioNombre + '</strong> dice:</span>'
                        + '<span class="time">' + aoBitacora[i].Fecha + '</span></div>'
                        + aoBitacora[i].Comentario + '</div></li>';
            this.append(comentario);
        }
    }

    function ImagenExiste(url) {
        var img = new Image();
        img.src = url;
        return img.height != 0;
    }

    $.fn.uDialogoComentario = function () {
        if (!this.hasClass('manual')) {
            if (this.attr('id') != 'frmAccion') { this.attr('id', 'frmAccion'); }
            this.attr({ action: '#', onsubmit: 'return false' });
            this.addClass('form-horizontal');
            this.empty();
            this.append('<div class="modal fade" id="dlgAccion" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button><h6 class="modal-title"><i class="fa fa-comment"></i><span id="lblAccion"></span> la estructura presupuestal</h6></div><div class="modal-body"><div class="well row-fluid"><div class="control-group"><label class="control-label">Comentario:</label><div class="controls"><textarea id="txtComentario" name="txtComentario" rows="4" cols="5" class="span12"></textarea></div></div></div></div><div class="modal-footer"><button id="cmdAccion" type="submit" class="btn"></button><button type="button" class="btn btn-default" data-dismiss="modal"><i class="fa fa-sign-out"></i>Cerrar</button></div></div></div></div>');
        }        
        $('#cmdAccion').click(fnCmdAccion);
    }

    $.uDeshabilitar = function (aoControles) {
        for (var i = 0; i < aoControles.length; i++) {
            switch (aoControles[i].TipoControlId) {
                case 1: // input
                    $('#' + aoControles[i].Nombre).attr('readonly', 'readonly');
                    break;
                case 2: // textarea
                    $('#' + aoControles[i].Nombre).attr('readonly', 'readonly');
                    break;
                case 3: // select
                    $('#' + aoControles[i].Nombre).select2("disable");
                    break;
                case 4: // select multiple
                    $('#' + aoControles[i].Nombre).select2("disable");
                    break;
                case 5: // checkbox
                    $('#' + aoControles[i].Nombre).attr('disabled', 'disabled');
                    break;
                case 6: // radio
                    $('#' + aoControles[i].Nombre).attr('disabled', 'disabled');
                    break;
                case 7: // ibutton
                    $('#' + aoControles[i].Nombre).attr('disabled', 'disabled');
                    break;
                case 8: // uploader
                    $('#' + aoControles[i].Nombre).attr('disabled', 'disabled');
                    break;
                case 9: // a
                    $('#' + aoControles[i].Nombre).attr('disabled', 'disabled');
                    break;
                case 10: // datatable
                    $('#' + aoControles[i].Nombre + ' tbody').removeClass('seleccionable');
                    $('#' + aoControles[i].Nombre).removeClass('table-hover');
                    break;
                case 11: // div
                    $('#' + aoControles[i].Nombre).attr('disabled', 'disabled');
                    break;
                case 12: // fieldset
                    $('#' + aoControles[i].Nombre).attr('disabled', 'disabled');
                    break;
                case 13: // button
                    $('#' + aoControles[i].Nombre).hide();
                    break;
            }
        }
    }

    $.uHabilitar = function (aoControles) {
        for (var i = 0; i < aoControles.length; i++) {
            switch (aoControles[i].TipoControlId) {
                case 1: // input
                    $('#' + aoControles[i].Nombre).removeAttr('readonly');
                    break;
                case 2: // textarea
                    $('#' + aoControles[i].Nombre).removeAttr('readonly');
                    break;
                case 3: // select
                    $('#' + aoControles[i].Nombre).select2("enable");
                    break;
                case 4: // select multiple
                    $('#' + aoControles[i].Nombre).select2("enable");
                    break;
                case 5: // checkbox
                    $('#' + aoControles[i].Nombre).removeAttr('disabled');
                    break;
                case 6: // radio
                    $('#' + aoControles[i].Nombre).removeAttr('disabled');
                    break;
                case 7: // ibutton
                    $('#' + aoControles[i].Nombre).removeAttr('disabled');
                    break;
                case 8: // uploader
                    $('#' + aoControles[i].Nombre).removeAttr('disabled');
                    break;
                case 9: // a
                    $('#' + aoControles[i].Nombre).removeAttr('disabled');
                    break;
                case 10: // datatable
                    $('#' + aoControles[i].Nombre + ' tbody').addClass('seleccionable');
                    $('#' + aoControles[i].Nombre).addClass('table-hover');
                    break;
                case 11: // div
                    $('#' + aoControles[i].Nombre).removeAttr('disabled');
                    break;
                case 12: // fieldset
                    $('#' + aoControles[i].Nombre).removeAttr('disabled');
                    break;
                case 13: // button
                    $('#' + aoControles[i].Nombre).show();
                    break;
            }
        }
    }

    var fnCerrar = function (e) {
        // Redireccionar al los recibidos
        window.location.replace('/Inicio/Recibidos');
    };

    var fnAccion = function (e) {
        var oAccion = aoAcciones[$(this).attr('id')];

        if (typeof fnPreAccion != 'undefined') {
            fnPreAccion(oAccion);
        }

        // Limpiar las validaciones
        oValidator.resetForm();

        // Limpiar las reglas de valildación
        for (var i in oValidator.settings.rules) {
            delete oValidator.settings.rules[i];
        }

        if (oAccion.Validaciones != "") {
            var oValidaciones = JSON.parse(oAccion.Validaciones);
            for (var i = 0; i < oValidaciones.length; i++) {
                $('[name=' + oValidaciones[i].name +']').rules("add", oValidaciones[i].rules);
            }
        }

        if (oValidator.form()) {
            if (oAccion.SolicitarComentario == true) {
                var bValidacionAntesEnvio = true;
                // Validación adicional antes de que la actividad sea enviada a otro usuario
                if (typeof fnValidarAntesEnvio != 'undefined') {
                    bValidacionAntesEnvio = fnValidarAntesEnvio();
                }
                if (bValidacionAntesEnvio) {
                    $('#txtComentario').val('');
                    $('#dlgAccion').attr('data-id', oAccion.Id);
                    $('#dlgAccion').attr('data-descripcion', oAccion.Descripcion);
                    $('#dlgAccion').attr('data-cerrar-ventana', oAccion.CerrarVentana);
                    $('#cmdAccion').html($(this).html());
                    $('#cmdAccion').attr('class', $(this).attr('class'));
                    $('#lblAccion').html(oAccion.Nombre);
                    $('#dlgAccion').modal({ backdrop: 'static' });
                }
            } else {
                fnGuardar(oAccion.Id, '', oAccion.Descripcion, oAccion.CerrarVentana);
            }
        }      
    };

    var fnCmdAccion = function (e) {
        $('#dlgAccion').modal('hide');
        fnGuardar($('#dlgAccion').attr('data-id'), $('#txtComentario').val(), $('#dlgAccion').attr('data-descripcion'), Boolean($('#dlgAccion').attr('data-cerrar-ventana')));
    }

})(jQuery);