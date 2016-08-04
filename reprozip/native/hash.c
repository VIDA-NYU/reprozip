#include <Python.h>
#include <stdio.h>

#define CHUNK_SIZE 4096

static void hash_chunk(PyObject *hash_method, const char *chunk, size_t len)
{
    PyObject *buf, *args;
    if(len == 0)
        return;
    buf = PyString_FromStringAndSize(chunk, len);
    args = PyTuple_Pack(1, buf);
    Py_DECREF(buf);
    PyObject_CallObject(hash_method, args);
    Py_DECREF(args);
}

int hash_file(FILE *fp, char *hexdigest)
{
    char buffer[CHUNK_SIZE];
    PyObject *hasher = NULL;
    PyObject *hash_method = NULL;
    PyObject *empty_tuple = NULL;
    size_t len;

    // hasher = hashlib.sha1()
    {
        PyObject *hashlib_module = PyImport_ImportModule("hashlib");
        if(hashlib_module == NULL)
            return -1;
        PyObject *sha1_func = PyObject_GetAttrString(hashlib_module, "sha1");
        Py_DECREF(hashlib_module);
        if(sha1_func == NULL)
            return -1;
        empty_tuple = PyTuple_New(0);
        hasher = PyObject_CallObject(sha1_func, empty_tuple);
        hash_method = PyObject_GetAttrString(hasher, "update");
        if(hash_method == NULL)
            goto error;
    }

    // Hash file
    len = fread(buffer, 1, 4096, fp);
    hash_chunk(hash_method, buffer, len);
    while(len == 4096)
    {
        len = fread(buffer, 1, 4096, fp);
        hash_chunk(hash_method, buffer, len);
    }

    // Get hex digest
    Py_DECREF(hash_method);
    {
        PyObject *digest;
        PyObject *hex_method = PyObject_GetAttrString(hasher, "hexdigest");
        if(hex_method == NULL)
            goto error;
        digest = PyObject_CallObject(hex_method, empty_tuple);
        Py_DECREF(hasher); hasher = NULL;
        Py_DECREF(empty_tuple); empty_tuple = NULL;
        if(PyString_Size(digest) != 40)
            goto error;
        strcpy(hexdigest, PyString_AsString(digest));
        Py_DECREF(digest);
        return 0;
    }

error:
    Py_XDECREF(hasher);
    Py_XDECREF(hash_method);
    Py_XDECREF(empty_tuple);
    return -1;
}
