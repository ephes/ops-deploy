/*
 * A fake Traefik or PostgreSQL server binary for the container collect
 * cases of the software-live parity harness (PLAN.md 6.2). Built by
 * parity/world.py with gcc and VERSION_TEXT defined:
 *
 *   <binary> version | --version   prints VERSION_TEXT and exits 0
 *   <binary>                        waits until it is killed (the "server")
 *
 * It is a real ELF file, so /proc/<pid>/exe of the running process points
 * at it and both programs hash and probe it as they do the real servers.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef VERSION_TEXT
#error "VERSION_TEXT must be defined"
#endif

int main(int argc, char **argv)
{
    if (argc > 1 && (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0)) {
        fputs(VERSION_TEXT, stdout);
        return 0;
    }
    for (;;) {
        pause();
    }
}
