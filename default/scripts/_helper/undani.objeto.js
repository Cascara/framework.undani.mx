/// <reference path="../../jquery.js" />

(function ($) {
    $.fn.uObjeto = function () {
        var aoAttr = this.find('[data-attr-tipo]');
        var o = {};

        // Atributos de la forma
        var aNombre;
        var sAttrNombre;
        for (var a = 0; a < this[0].attributes.length; a++) {
            if (this[0].attributes[a].name.indexOf('data-attr-') != -1) {
                aNombre = this[0].attributes[a].name.replace('data-attr-', '').split('-');
                sAttrNombre = '';
                for (var b = 0; b < aNombre.length; b++) {
                    sAttrNombre += aNombre[b].charAt(0).toUpperCase() + aNombre[b].slice(1);
                }
                o[sAttrNombre] = this[0].attributes[a].value;
            }
        }

        // Elementos HTML
        for (var i = 0; i < aoAttr.length; i++) {
            switch (aoAttr[i].tagName.toLowerCase()) {
                case 'input':
                    switch ($(aoAttr[i]).attr('type')) {
                        case 'text':
                            switch ($(aoAttr[i]).attr('data-attr-tipo')) {
                                case 'cadena':
                                    o[aoAttr[i].name] = $(aoAttr[i]).val();
                                    break;
                                case 'entero':
                                    o[aoAttr[i].name] = parseInt($(aoAttr[i]).val());
                                    break;
                                case 'decimal':
                                    o[aoAttr[i].name] = parseFloat($(aoAttr[i]).val());
                                    break;
                            }
                            break;
                        case 'password':
                            o[aoAttr[i].name] = $(aoAttr[i]).val();
                            break;
                        case 'checkbox':
                            o[aoAttr[i].name] = $(aoAttr[i]).is(':checked')
                            break;
                    }
                    break;
                case 'select':
                    switch ($(aoAttr[i]).attr('data-attr-tipo')) {
                        case 'entero':
                            o[aoAttr[i].name] = parseInt($(aoAttr[i]).val());
                            break;
                        case 'cadena':
                            o[aoAttr[i].name] = parseInt($(aoAttr[i]).children('option:selected').text());
                            break;
                    }
                    break;
            }            
        }
        return o;
    };
})(jQuery);