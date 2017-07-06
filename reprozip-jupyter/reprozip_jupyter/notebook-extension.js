define(['jquery',
        'base/js/namespace',
        'base/js/utils',
        'base/js/dialog'],
function notebook_extension($, IPython, utils, dialog) {
    var ajax = utils.ajax || $.ajax;

    // Called when the user clicks the "trace" action
    function fn_trace(env) {
        // TODO: Cancel trace?
        var cancel = function cancel() {};

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

        // Save the notebook first, get called back when it is done
        // (there is a round-trip to the server)
        var saved = function saved() {
            env.notebook.events.off("notebook_saved.Notebook", saved);
            console.log("reprozip: notebook saved, triggering trace");

            ajax(utils.url_path_join(IPython.notebook.base_url,
                                         "reprozip/trace"), {
                method: "POST",
                data: {file: IPython.notebook.notebook_path}
            });
        };
        console.log("reprozip: saving notebook")
        env.notebook.events.on("notebook_saved.Notebook", saved);
        env.notebook.save_checkpoint();
    }

    function _on_load(env){
        console.info('reprozip: extension reprozip-jupyter loaded');

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
        console.log("reprozip: created action", trace_action_name);
        IPython.toolbar.add_buttons_group([trace_action_name]);
    }

    return {load_ipython_extension: _on_load};
});
