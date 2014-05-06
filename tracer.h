#ifndef TRACER_H
#define TRACER_H

#include "config.h"

int fork_and_trace(const char *binary, int argc, char **argv,
                   const char *database_path);

#endif
