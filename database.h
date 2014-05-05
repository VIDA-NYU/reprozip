#ifndef DATABASE_H
#define DATABASE_H

#define FILE_READ   0x01
#define FILE_WRITE  0x02
#define FILE_EXEC   0x04

int db_init(const char *filename);
int db_close();
int db_add_process(unsigned int id, unsigned int parent_id);
int db_add_first_process(unsigned int id);
int db_add_file_open(unsigned int process,
                     const char *name, unsigned int mode);

#endif
