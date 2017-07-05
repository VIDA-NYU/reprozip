define(['base/js/namespace',
        'base/js/utils',
        'base/js/dialog'],
function(IPython, utils, dialog) {
    var $ = require('jquery');

    var ajax = utils.ajax || $.ajax;

    function fn_trace(env) {
        var cancel = function() {};

        dialog.modal({
            body: "Executing notebook under trace...",
            title: "Tracing notebook with ReproZip",
            buttons: {
                "Cancel": {
                    class: "btn-primary",
                    click: cancel
                }
            },
            notebook: env.notebook,
            keyboard_manager: env.notebook.keyboard_manager
        });

        IPython.keyboard_manager.actions.call("jupyter-notebook:save-notebook");

        ajax(utils.url_path_join(IPython.notebook.base_url, "reprozip/trace"),
             {
                method: "POST",
                data: {file: IPython.notebook.notebook_path}
             });
    }

    function _on_load(env){
        console.info('extension reprozip-jupyter loaded');

        var trace_action = {
            help: "Trace this notebook using ReproZip",
            icon: "fa-file-archive-o",
            help_index: "",
            handler: fn_trace
        };
        var trace_action_name = IPython.keyboard_manager.actions.register(
            trace_action,
            'trace-with-reprozip',
            'reprozip');
        console.log("Created action", trace_action_name);
        IPython.toolbar.add_buttons_group([trace_action_name]);
    }

    return {load_ipython_extension: _on_load};
});
