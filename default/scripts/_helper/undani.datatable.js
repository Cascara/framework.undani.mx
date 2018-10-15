(function ($) {

    // Textos es español
    var _Language = {
        sProcessing: 'Procesando...',
        sLengthMenu: '_MENU_',
        sZeroRecords: 'No se encontraron resultados',
        sEmptyTable: 'No se encontraron resultados',
        sInfo: 'Mostrando del <b>_START_ al _END_</b> de _TOTAL_ elementos',
        sInfoEmpty: 'Mostrando del 0 al 0 de un total de 0',
        sInfoFiltered: '(filtrado de un total de _MAX_ registros)',
        sInfoPostFix: '',
        sSearch: '',
        sUrl: '',
        sInfoThousands: ',',
        sLoadingRecords: 'Cargando...',
        oPaginate: {
            sFirst: 'Primero',
            sLast: 'Último',
            sNext: 'Siguiente',
            sPrevious: 'Anterior'
        },
        oAria: {
            sSortAscending: ': Activar para ordenar la columna de manera ascendente',
            sSortDescending: ': Activar para ordenar la columna de manera descendente'
        }
    };

    // Crear DataTable
    $.fn.uDataTable = function (aoColumns, sZeroRecords, iDisplayLength) {

        var id = $(this).attr('id');

        var oLanguage = JSON.parse(JSON.stringify(_Language));

        if (typeof sZeroRecords !== 'undefined') {
            oLanguage.sZeroRecords = sZeroRecords;
            oLanguage.sEmptyTable = sZeroRecords;
        }

        var oSettingsDefault ={
            sDom: "<'table-responsive't><'row'<p i>>",
            sPaginationType: "bootstrap",
            destroy: true,
            scrollCollapse: true,
            oLanguage: oLanguage,
            aoColumns: aoColumns,
            fnDrawCallback: function (s) {
                $('input[name=' + id + ']').val(s.aoData.length);
                if ($('label[for=txt' + id + ']').length > 0) {
                    var minRow = $('input[name=' + id + ']').rules().minRows;
                    if (s.aoData.length >= minRow) {
                        $('label[for=txt' + id + ']').hide();
                    }
                }
            }
        };

        if (typeof iDisplayLength !== 'undefined') {
            if (iDisplayLength > 0) {
                oSettingsDefault.iDisplayLength = iDisplayLength;
                oSettingsDefault.bInfo = true;
            }
        }

        var dt = this.dataTable(oSettingsDefault);

        // Agrega al final una caja de texto oculta para la validación
        $(document.getElementById(id).parentElement).append('<input id="txt' + id + '" name="' + id + '" type="hidden" />');        

        return dt;
    };

    // Crear DataTable
    $.fn.uDataTableServerSide = function (sAjaxSource, aoColumns, sZeroRecords, iOrderIndexCol, sTypeOrder, iDisplayLength, oAditionalParameters) {

        var id = this.attr('id');
        var _oAditionalParameters = oAditionalParameters;

        var recarga = $('#' + id).portlet({
            progress: 'bar',
            onRefresh: function () { }
        });

        var oLanguage = JSON.parse(JSON.stringify(_Language));

        if (typeof sZeroRecords !== 'undefined') {
            oLanguage.sZeroRecords = sZeroRecords;
            oLanguage.sEmptyTable = sZeroRecords;
        }

        var oSettingsDefault = {
            sDom: "<'table-responsive't><'row'<p i>>",
            sPaginationType: "bootstrap",
            bAutoWidth: false,
            destroy: true,
            scrollCollapse: true,
            oLanguage: oLanguage,
            aoColumns: aoColumns,
            bServerSide: true,
            sAjaxSource: sAjaxSource,
            order: [[ iOrderIndexCol, sTypeOrder ]],
            fnServerData: function (sSource, aoData, fnCallback, oSettings) {
                var oData = DataFactory(aoData);
                recarga.portlet({ refresh: true });
                oSettings.jqXHR = $.ajax({
                    type: 'GET',
                    url: sSource,
                    data: oData,
                    dataType: 'json'
                })
                .done(fnCallback)
                .fail(function (jqXHR, textStatus, errorThrown) {
                    if (jqXHR.status == 0)
                        $.uMensaje({ sTipo: 'Error', sOrigen: 'úndani', sMensaje: 'El tabla de datos no pudo encontrar el servicio.' });
                    else
                        $.uMensaje({ sTipo: 'Error', sOrigen: jqXHR.status, sMensaje: errorThrown });
                })
                .always(function (jqXHR, textStatus, errorThrown) {
                    recarga.portlet({ refresh: false });
                });
            },
            fnDrawCallback: function (s) {
                $('input[name=' + id + ']').val(s.aoData.length);
                if ($('label[for=txt' + id + ']').length > 0) {
                    var minRow = $('input[name=' + id + ']').rules().minRows;
                    if (s.aoData.length >= minRow) {
                        $('label[for=txt' + id + ']').hide();
                    }
                }
            }
        };

        if (typeof iDisplayLength !== 'undefined') {
            if (iDisplayLength > 0) {
                oSettingsDefault.iDisplayLength = iDisplayLength;
                oSettingsDefault.bInfo = true;
            }
        }

        function DataFactory(aoData) {
            var oData = { 'aoData': JSON.stringify(aoData) };
            if (typeof _oAditionalParameters !== 'undefined') {
                for (var key in _oAditionalParameters) {
                    oData[key] = _oAditionalParameters[key];
                }
            }
            return oData;
        }

        var dt = this.dataTable(oSettingsDefault);

        dt = $.extend(dt,
            {
                id: function () {
                    return id;
                },
                oParametrosAdicionales: function (o) {
                    if (typeof o !== 'undefined') {
                        _oAditionalParameters = o;
                    }
                    return _oAditionalParameters;
                }
            });

        // Agrega al final una caja de texto oculta para la validación
        $(document.getElementById(id).parentElement).append('<input id="txt' + id + '" name="' + id + '" type="hidden" />');

        return dt;
    };

})(jQuery);