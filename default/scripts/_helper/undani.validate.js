(function ($) {

    //var oValidator = $('#NombreForma').uValidate({
    //    bShowDetail: false,
    //    rules: { NombreControl1: { required: true }, NombreControl2: { required: true } }
    //});

    $.fn.uValidate = function (oSettings) {
        var fnInvalidHandler;

        // Mostrar el detalle de la validación
        fnInvalidHandler = function (e, validator) {
            if ($('#' + this.id).attr('data-validate') == 1) {
                var errores = validator.numberOfInvalids();
                if (errores) {
                    var mensaje = '';
                    if (oSettings.bShowDetail) {
                        mensaje = errores == 1 ? 'Corrija el siguiente campo:\n\n' : 'Corrija los siguientes ' + errores + ' campos:\n\n';
                        var e = 1;
                        for (var i in validator.errorMap) {
                            mensaje = mensaje + e + '. ' + $('#' + i).attr('data-validate-detail') + '\n';
                            e = e + 1;
                        }
                        alert(mensaje);
                    } else {
                        mensaje = errores == 1 ? 'Corrija el campo marcado' : 'Corrija los ' + errores + ' campos marcados';
                        if (typeof oSettings.fnMensajeError !== 'undefined')
                            oSettings.fnMensajeError(mensaje);
                        else
                            $.uMensaje({ sTipo: 'Validacion', sMensaje: mensaje });
                    }
                    $('#' + this.id).attr('data-validate', 0);
                }
            } else {
                $('#' + this.id).attr('data-validate', 1);
            }
        };

        this.attr('data-validate', 1);

        // Crea el objeto de validación
        oValidate = this.validate({
            invalidHandler: fnInvalidHandler,
            rules: oSettings.rules,
            messages: oSettings.messages,
            ignore: 'select[type=hidden]',
            highlight: function (element, errorClass, validClass) {
                $(element.form).find('label[for=' + element.id + ']').fadeIn('slow');
            },
            unhighlight: function (element, errorClass, validClass) {
                $(element.form).find('label[for=' + element.id + ']').fadeOut('slow');
            },
            errorPlacement: function (error, element) {
                error.insertAfter(element).hide().fadeIn('slow');
            }
        });

        return oValidate;
    };

    // Agrega la validación de datatables
    $.validator.addMethod('minRows', function (value, element, param) {
        return parseFloat(value) >= param;
    });

    $.extend($.validator.messages, {
        required: 'Obligatorio',
        remote: 'Rellena este campo',
        email: 'Email inválido',
        url: 'URL inválida',
        date: 'Fecha inválida',
        dateISO: 'Fecha (ISO) inválida',
        number: 'Entero inválido',
        digits: 'Sólo dígitos',
        creditcard: 'Tarjeta inválida',
        equalTo: 'Escribe el mismo valor',
        accept: 'Extensión incorrecta',
        maxlength: $.validator.format('Máximo {0} caracteres'),
        minlength: $.validator.format('Mínimo {0} caracteres'),
        rangelength: $.validator.format('Valor entre {0} y {1} caracteres'),
        range: $.validator.format('Valor entre {0} y {1}'),
        max: $.validator.format('Valor menor o igual a {0}'),
        min: $.validator.format('Valor mayor o igual a {0}'),
        minRows: $.validator.format('Al menos {0} filas')
    });

})(jQuery);