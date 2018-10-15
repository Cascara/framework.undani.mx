/// <reference path="../../ui/jquery-1.9.1.min.js" />

$(document).ready(function (e) {

    moment.locale('es');

    var aoColumns = [
        {
            mData: 'Abierto', width: '100px',
            sClass: 'h-align-center',
            mRender: function (data, type, full) {
                var semaforo;
                switch (full.Semaforo) {
                    case 1:
                        semaforo = '#10cfbd';
                        break;
                    case 2:
                        semaforo = '#f8d053';
                        break;
                    case 3:
                        semaforo = '#f55753';
                        break;
                    default:
                        semaforo = '#e6e6e6';
                }
                var icono = '<span class="label" style="background-color: ' + semaforo + '; margin-right: 7px;">&nbsp;</span><span class="label" style="color: #fff; background-color: ' + full.Color + '">' + (data ? '&nbsp;' : 'Nueva') + '</span>';
                return icono;
            }
        },
        { mData: 'Proceso', width: '130px' },
        { mData: 'Actividad', width: '250px' },
        { mData: 'Fecha', width: '140px',
            mRender: function (data, type, full) {
                return moment(data, "DD/MM/YYYY").fromNow();
            }
        },
        { mData: 'Asunto' }
    ];

    for (var i = 0; i < parseInt($('#dtActividades').attr('data-numero-ia')); i++) {
        aoColumns.push({ mData: 'Properties.InformacionAdicional' + i });
    }    

    // Lista de actividades
    var dtActividades = $('#dtActividades').uDataTable( aoColumns, 'No hay actividades por atender');

    $('#buscar-actividad').keyup(function () {
        dtActividades.fnFilter($(this).val());
    });

    // Obtener los mensajes recibidos
    function ObtenerActividades() {
        NProgress.start(); // Inicia barra de progreso
        $.ajax({
            type: 'POST',
            url: '/BpsBandeja/ObtenerMensajesEntrada',
            dataType: 'json'
        })
        .done(function (_resultado, textStatus, jqXHR) {
            if (_resultado.Errores == null) {
                dtActividades.fnClearTable();
                if (_resultado.Valor.length > 0)
                    dtActividades.fnAddData(_resultado.Valor);
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
        })
        .always(function (jqXHR, textStatus, errorThrown) {
            NProgress.done(); // Termina barra de progreso
        });
    };

    // Obtiene las actividades por primera vez
    ObtenerActividades();

    // Selecciona una actividad
    $('#dtActividades tbody').click(function (e) {
        var oMensaje = dtActividades.fnGetData()[$(e.target.parentNode)[0]._DT_RowIndex];

        $.ajax({
            type: 'POST',
            url: "/BpsBandeja/AbrirMensaje",
            data: { id: oMensaje.Id },
            dataType: 'json'
        })
        .done(function (_resultado, textStatus, jqXHR) {
            if (_resultado.Errores == null) {
                var url = _resultado.Valor;
                window.location.href = url;
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