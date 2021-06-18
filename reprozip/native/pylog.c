#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <Python.h>

#include "log.h"


static PyObject *py_logger = NULL;
static PyObject *py_logger_log = NULL;
int logging_level = 0;


int log_setup()
{
    if(py_logger == NULL)
    {
        // Import Python's logging module
        PyObject *logging = PyImport_ImportModuleEx("logging",
                                                    NULL, NULL, NULL);
        if(logging == NULL)
            return -1;

        // Get the logger
        {
            PyObject *func = PyObject_GetAttrString(logging, "getLogger");
            py_logger = PyObject_CallFunction(func, "(s)", "reprozip");
            Py_DECREF(logging);
            Py_DECREF(func);
            if(py_logger == NULL)
                return -1;
        }

        // Get the log function
        py_logger_log = PyObject_GetAttrString(py_logger, "log");
        if(py_logger_log == NULL)
        {
            /* LCOV_EXCL_START : Logger objects always have a 'log' method */
            Py_DECREF(py_logger);
            py_logger = NULL;
            return -1;
            /* LCOV_EXCL_STOP */
        }
    }

    // Get the effective logging level
    {
        PyObject *meth = PyObject_GetAttrString(py_logger,
                                                "getEffectiveLevel");
        PyObject *level = PyObject_CallFunctionObjArgs(meth, NULL);
        Py_DECREF(meth);
        if(level == NULL)
            return -1;
        logging_level = PyLong_AsLong(level);
        if(PyErr_Occurred())
        {
            /* LCOV_EXCL_START : Logger objects are reliable */
            Py_DECREF(level);
            return -1;
            /* LCOV_EXCL_STOP */
        }
        Py_DECREF(level);
    }

    return 0;
}

void log_real_(pid_t tid, int lvl, const char *format, ...)
{
    va_list args;
    char datestr[13]; /* HH:MM:SS.mmm */
    static char *buffer = NULL;
    static size_t bufsize = 4096;
    size_t length;

    /* Fast filter: don't call Python if level is not enough */
    if(lvl < logging_level)
        return;

    if(buffer == NULL)
        buffer = malloc(bufsize);
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        strftime(datestr, 13, "%H:%M:%S", localtime(&tv.tv_sec));
        sprintf(datestr+8, ".%03u", (unsigned int)(tv.tv_usec / 1000));
    }
    va_start(args, format);
    length = (size_t)vsnprintf(buffer, bufsize, format, args);
    va_end(args);
    if(length + 1 >= bufsize)
    {
        while(length + 1 >= bufsize)
            bufsize *= 2;
        free(buffer);
        buffer = malloc(bufsize);
        va_start(args, format);
        length = vsnprintf(buffer, bufsize, format, args);
        va_end(args);
    }

    if(tid > 0)
        PyObject_CallFunction(py_logger_log, "(l, s, l, s)",
                              lvl, "[%d] %s", tid, buffer);
    else
        PyObject_CallFunction(py_logger_log, "(l, s, s)",
                              lvl, "%s", buffer);
}
