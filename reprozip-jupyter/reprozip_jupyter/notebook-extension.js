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

        var modal = dialog.modal({
            body: "Executing notebook under trace...",
            title: "Packing notebook with ReproZip",
            buttons: {
                "Cancel": {
                    class: "btn-warning",
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
            }).then(function packed(response) {
                console.log("reprozip: packing successful");
                modal.modal("hide");
                dialog.modal({
                    body: "Created package " + response.bundle,
                    title: "Packing notebook with ReproZip",
                    buttons: {
                        "Close": {
                            class: "btn-primary"
                        }
                    }
                });
            }, function failed() {
                console.error("reprozip: packing failed");
                modal.modal("hide");
                var m = dialog.modal({
                    body: "Packing failed!",
                    title: "Packing notebook with ReproZip",
                    show: false,
                    buttons: {
                        "Close": {
                            class: "btn-danger"
                        }
                    }
                });
                m.find(".modal-body").html("<div class=\"alert alert-danger\"><strong>Packing failed!</strong> Check the server console for details.</div>");
                m.modal("show");
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
