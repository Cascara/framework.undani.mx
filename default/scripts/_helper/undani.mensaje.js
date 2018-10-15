(function ($) {

    //$.uMensaje({ sTipo: 'Error', sOrigen: 'Texto del origen', sMensaje: 'Texto del error.' });
    //$.uMensaje({ sTipo: 'Exito', sMensaje: 'Texto del mensaje.' });
    //$.uMensaje({ sTipo: 'Alerta', sMensaje: 'Texto del mensaje.' });
    //$.uMensaje({ sMensaje: 'Texto del mensaje.' });

    $.uMensaje = function (oSettings) {
        switch (oSettings.sTipo) {
            case 'Error':
                $('body').pgNotification({
                    style: typeof oSettings.sEstilo !== 'undefined' ? oSettings.sEstilo : 'flip',
                    message: oSettings.sMensaje,
                    position: typeof oSettings.sPosicion !== 'undefined' ? oSettings.sPosicion : 'top-right',
                    timeout: 20000,
                    type: 'danger'
                }).show();
                console.log(oSettings.sOrigen + ': ' + oSettings.sMensaje);
                break;
            case 'Exito':
                $('body').pgNotification({
                    style: typeof oSettings.sEstilo !== 'undefined' ? oSettings.sEstilo : 'flip',
                    message: oSettings.sMensaje,
                    position: typeof oSettings.sPosicion !== 'undefined' ? oSettings.sPosicion : 'top-right',
                    timeout: 10000,
                    type: 'success'
                }).show();
                break;
            case 'Alerta':
                $('body').pgNotification({
                    style: typeof oSettings.sEstilo !== 'undefined' ? oSettings.sEstilo : 'flip',
                    message: oSettings.sMensaje,
                    position: typeof oSettings.sPosicion !== 'undefined' ? oSettings.sPosicion : 'top-right',
                    timeout: 10000,
                    type: 'warning'
                }).show();
                break;
            case 'Informacion':
                $('body').pgNotification({
                    style: typeof oSettings.sEstilo !== 'undefined' ? oSettings.sEstilo : 'flip',
                    message: oSettings.sMensaje,
                    position: typeof oSettings.sPosicion !== 'undefined' ? oSettings.sPosicion : 'top-right',
                    timeout: 10000,
                    type: 'info'
                }).show();
                break;
            default:
                $('body').pgNotification({
                    style: typeof oSettings.sEstilo !== 'undefined' ? oSettings.sEstilo : 'flip',
                    message: oSettings.sMensaje,
                    position: typeof oSettings.sPosicion !== 'undefined' ? oSettings.sPosicion : 'top-right',
                    timeout: 5000,
                    type: 'default'
                }).show();
                break;
        }
    };

})(jQuery);