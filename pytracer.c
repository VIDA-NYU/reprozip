#include <Python.h>

#include "tracer.h"


PyObject *Err_Base;


static PyObject *pytracer_execute(PyObject *self, PyObject *args)
{
    PyObject *ret;

    /* Reads arguments */
    const char *binary, *databasepath;
    char **argv;
    size_t argv_len;
    PyObject *py_argv;
    if(!(PyArg_ParseTuple(args, "sO!s",
                          &binary,
                          &PyList_Type, &py_argv,
                          &databasepath)))
        return NULL;

    /* DEBUG */
    fprintf(stderr,
            "pytracer_execute(\n"
            "    binary=%s\n"
            "    argv=",
            binary);
    PyObject_Print(py_argv, stderr, 0);
    fprintf(stderr,
            "\n"
            "    databasepath=%s\n"
            "    )\n",
            databasepath);

    /* Converts argv from Python list to char[][] */
    {
        argv_len = PyList_Size(py_argv);
        size_t i;
        int bad = 0;
        argv = malloc((argv_len + 1) * sizeof(char*));
        for(i = 0; i < argv_len; ++i)
        {
            PyObject *arg = PyList_GetItem(py_argv, i);
            if(PyUnicode_Check(arg))
            {
                const char *str;
                PyObject *pyutf8 = PyUnicode_AsUTF8String(arg);
                if(pyutf8 == NULL)
                {
                    bad = 1;
                    break;
                }
                fprintf(stderr, "\n");
#if PY_MAJOR_VERSION >= 3
                str = PyBytes_AsString(pyutf8);
#else
                str = PyString_AsString(pyutf8);
#endif
                if(str == NULL)
                {
                    bad = 1;
                    break;
                }
                argv[i] = strdup(str);
                Py_DECREF(pyutf8);
            }
            else
            {
                const char *str;
#if PY_MAJOR_VERSION >= 3
                str = PyBytes_AsString(arg);
#else
                str = PyString_AsString(arg);
#endif
                if(str == NULL)
                {
                    bad = 1;
                    break;
                }
                argv[i] = strdup(str);
            }
        }
        if(bad)
        {
            size_t j;
            for(j = 0; j < i; ++j)
                free(argv[j]);
            free(argv);
            return NULL;
        }
        argv[argv_len] = NULL;
    }

    if(fork_and_trace(binary, argv_len, argv, databasepath) == 0)
    {
        Py_INCREF(Py_None);
        ret = Py_None;
    }
    else
    {
        PyErr_SetString(Err_Base, "Error occurred");
        ret = NULL;
    }

    /* Deallocs argv */
    {
        size_t i;
        for(i = 0; i < argv_len; ++i)
            free(argv[i]);
        free(argv);
    }

    return ret;
}


static PyMethodDef methods[] = {
    {"execute", pytracer_execute, METH_VARARGS,
     "execute(binary, argv, databasepath)\n"
     "\n"
     "Runs the specified binary with the argument list argv under trace and "
     "writes\nthe captured events to SQLite3 database databasepath."},
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "reprozip._pytracer",       /* m_name */
    "C interface to tracer",    /* m_doc */
    -1,                         /* m_size */
    methods,                    /* m_methods */
    NULL,                       /* m_reload */
    NULL,                       /* m_traverse */
    NULL,                       /* m_clear */
    NULL,                       /* m_free */
};
#endif

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit__pytracer(void)
#else
PyMODINIT_FUNC init_pytracer(void)
#endif
{
    PyObject *mod;

#if PY_MAJOR_VERSION >= 3
    mod = PyModule_Create(&moduledef);
#else
    mod = Py_InitModule("reprozip._pytracer", methods);
#endif
    if(mod == NULL)
    {
#if PY_MAJOR_VERSION >= 3
        return NULL;
#else
        return;
#endif
    }

    Err_Base = PyErr_NewException("_pytracer.Error", NULL, NULL);
    Py_INCREF(Err_Base);
    PyModule_AddObject(mod, "Error", Err_Base);

#if PY_MAJOR_VERSION >= 3
    return mod;
#endif
}
