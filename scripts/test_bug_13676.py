from __future__ import unicode_literals

import sqlite3
import sys


data_in = "R\xE9mi\0wrote\0this"


if __name__ == '__main__':
    conn = sqlite3.connect('')
    conn.row_factory = sqlite3.Row

    conn.execute(
        '''
        CREATE TABLE test(data TEXT);
        ''')
    conn.execute(
        '''
        INSERT INTO test(data)
        VALUES(?);
        ''',
        (data_in,))
    data_rows = conn.execute(
        '''
        SELECT data FROM test;
        ''')
    data_out = next(iter(data_rows))[0]

    if data_out == data_in:
        print("Ok, not susceptible to Python bug 13676")
    else:
        sys.stderr.write("This Python installation is affected by Python bug "
                         "13676\n")
        sys.stderr.write("Stored: %r, retrieved: %r" % (data_in, data_out))
        sys.stderr.write("This version will NOT work with reprozip\n")
        sys.stderr.write("See http://bugs.python.org/issue13676\n")
        sys.exit(1)
