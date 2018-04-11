#ifndef ALIENOS_SYSCALLS_H
#define ALIENOS_SYSCALLS_H

// target installation does not have this defined
#define SYS_getrandom 318

// 0 - no colors, 1 - limited colors, 2 - full colors
extern int color_level;

// returns 1 if child called end, -1 if there was an error, 0 otherwise
int do_syscall(int *exit_code_ptr, pid_t cpid, int child_mem);


#endif // ALIENOS_SYSCALLS_H
