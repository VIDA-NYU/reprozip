#include <Python.h>


PyObject *Err_Base;


static PyObject *pytracer_exec(PyObject *self, PyObject *args)
{
    const char *binary, *databasepath;
    PyObject *argv;
    if(!(PyArg_ParseTuple(args, "s#O!s#",
                          &binary, &binary_length,
                          &PyList_Type, &argv,
                          &databasepath, &databasepath_length)))
        return NULL;

    /* TODO */
}


static PyMethodDef methods[] = {
    {"exec", pytracer_exec, METH_VARARGS,
     "exec(binary, argv, databasepath)\n"
     "\n"
     "Runs the specified binary with the argument list argv under trace and "
     "writes\nthe captured events to SQLite3 database databasepath."},
};

PyMODINIT_FUNC init_pytracer(void)
{
    PyObject *mod;

    mod = Py_InitModule("_pytracer", methods);
    if(mod == NULL)
        return;

    Err_Base = PyErr_NewException("_pytracer.Error", NULL, NULL);
    Py_INCREF(Err_Base);
    PyModule_AddObject(mod, "Error", Err_Base);
}
