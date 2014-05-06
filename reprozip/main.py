import _pytracer

import codecs
import locale
import os
import sqlite3
import sys
import tempfile


def print_db(database):
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    processes = cur.execute('''
            SELECT id, parent, timestamp
            FROM processes;
            ''')
    print(u"\nProcesses:")
    header = u"+------+--------+--------------------+"
    print(header)
    print(u"|  id  | parent |      timestamp     |")
    print(header)
    for proc in processes:
        f_id = "{: 5d} ".format(proc['id'])
        if proc['parent'] is not None:
            f_parent = "{: 7d} ".format(proc['parent'])
        else:
            f_parent = "        "
        f_timestamp = "{: 19d} ".format(proc['timestamp'])
        print(u'|'.join(('', f_id, f_parent, f_timestamp, '')))
        print(header)
    cur.close()

    cur = conn.cursor()
    processes = cur.execute('''
            SELECT id, name, timestamp, mode, process
            FROM opened_files;
            ''')
    print(u"\nFiles:")
    header = (u"+--------+--------------------+---------+------+--------------"
              u"----------------+")
    print(header)
    print(u"|   id   |      timestamp     | process | mode | name          "
          u"               |")
    print(header)
    for proc in processes:
        f_id = "{: 7d} ".format(proc['id'])
        f_timestamp = "{: 19d} ".format(proc['timestamp'])
        f_proc = "{: 8d} ".format(proc['process'])
        f_mode = "{: 5d} ".format(proc['mode'])
        f_name = " {: <29s}".format(proc['name'])
        print(u'|'.join(('', f_id, f_timestamp, f_proc, f_mode, f_name, '')))
        print(header)
    cur.close()

    conn.close()


def main():
    # Locale
    locale.setlocale(locale.LC_ALL, '')

    # Encoding for output streams
    if str == bytes:
        writer = codecs.getwriter(locale.getpreferredencoding())
        sys.stdout = writer(sys.stdout)
        sys.stderr = writer(sys.stderr)

    if len(sys.argv) < 2:
        sys.stderr.write(u"Usage: {bin} <program> [args [...]]\n".format(
                         bin=os.path.basename(sys.argv[0])))
        sys.exit(1)

    fd, database = tempfile.mkstemp(prefix='reprozip_', suffix='.sqlite3')
    os.close(fd)
    try:
        _pytracer.execute(sys.argv[1], sys.argv[1:], database)
        print(u"\n\n----------------------------------------------------------"
              u"---------------------")
        print_db(database)
    finally:
        os.remove(database)
