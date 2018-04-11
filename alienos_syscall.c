#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <fcntl.h>
#include <ncurses.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <asm/ptrace.h>
#include "alienos.h"
#include "alienos_syscall.h"


int color_level = 0;


static inline bool key_correct(int c) {
    return c >= ALIENOS_ASCII_LOWEST && c <= ALIENOS_ASCII_HIGHEST;
}


static inline bool coords_correct(int x, int y) {
    return (x >= 0 && x < ALIENOS_COLUMNS && y >= 0 && y < ALIENOS_ROWS);
}


static int copy_output_buffer(int fd, uint16_t *dest, uint64_t src_off, int n) {
    return (n <= 0 || n > ALIENOS_COLUMNS
            || pread64(fd, dest, (size_t)n * 2, src_off) != (size_t)n * 2)
           ? -1 : 0;
}


static int get_color(chtype *color, uint16_t achar) {
    int color_id = 0;

    if(color_level) {
        color_id = (achar >> 8) & 0xf;
        color_id += 1;
    }

    *color = COLOR_PAIR(color_id);
    return (color_id == ERR) ? -1 : 0;
}


static int get_chtype(chtype *ch, uint16_t achar) {
    chtype c = (chtype)(achar & 0xff);
    chtype color;

    if((!key_correct((int)c)) || get_color(&color, achar)) {
        return -1;
    }

    *ch = c | color;
    return 0;
}


static int do_return(uint64_t return_value, pid_t prog_pid, struct user_regs_struct regs_struct) {
    regs_struct.rax = return_value;
    return (int)ptrace(PTRACE_SETREGS, prog_pid, 0, &regs_struct);
}


static int do_getrand(uint64_t *return_value_ptr) {
    return (syscall(SYS_getrandom, return_value_ptr, 4, 0) != 4) ? -1 : 0;
}


static int do_getkey(uint64_t *return_value_ptr) {
    int key;
    while(1) {
        switch(key = getch()) {
            case ERR:
                return -1;
            case KEY_RIGHT:
                *return_value_ptr = ALIENOS_KEY_RIGHT;
                return 0;
            case KEY_LEFT:
                *return_value_ptr = ALIENOS_KEY_LEFT;
                return 0;
            case KEY_UP:
                *return_value_ptr = ALIENOS_KEY_UP;
                return 0;
            case KEY_DOWN:
                *return_value_ptr = ALIENOS_KEY_DOWN;
                return 0;
            case KEY_ENTER:
                *return_value_ptr = ALIENOS_KEY_ENTER;
                return 0;
            default:
                if(key_correct(key)) {
                    *return_value_ptr = (uint64_t)key;
                    return 0;
                }
        }
    }
}


static int do_print(int x, int y, uint16_t *achars, int n) {
    int i, old_x, old_y;
    chtype ch;

    getyx(stdscr, old_y, old_x);

    if(!coords_correct(x, y) || !coords_correct(x + n - 1, y) || move(y, x) == ERR) {
        return -1;
    }

    for(i = 0; i < n; ++i) {
        if(get_chtype(&ch, achars[i]) || (addch(ch) == ERR)) {
            return -1;
        }
    }

    if(move(old_y, old_x) == ERR || refresh() == ERR) {
        return -1;
    }

    return 0;
}


static int do_setcursor(int x, int y) {
    return (!coords_correct(x, y) || move(y, x) == ERR || refresh() == ERR) ? -1 : 0;
}


int do_syscall(int *exit_code_ptr, pid_t cpid, int child_mem) {

    static uint16_t output_buffer[ALIENOS_COLUMNS];
    static struct user_regs_struct regs_struct;

    if(ptrace(PTRACE_GETREGS, cpid, 0, &regs_struct)) {
        return -1;
    }

    uint64_t syscall_number = regs_struct.orig_rax,
            arg0 = regs_struct.rdi,
            arg1 = regs_struct.rsi,
            arg2 = regs_struct.rdx,
            arg3 = regs_struct.r10,
            return_value;

    switch (syscall_number) {

        case 0: // end
            *exit_code_ptr = (int)arg0;
            return 1;

        case 1: // getrand

            return (do_getrand(&return_value)
                    || do_return(return_value, cpid, regs_struct)) ? -1 : 0;

        case 2: // getkey
            return (do_getkey(&return_value)
                    || do_return(return_value, cpid, regs_struct)) ? -1 : 0;

        case 3: // print
            return
                    (copy_output_buffer(child_mem, output_buffer, arg2, (int)arg3)
                     || do_print((int)arg0, (int)arg1, output_buffer, (int)arg3))
                    ? -1 : 0;

        case 4:
            return do_setcursor((int)arg0, (int)arg1);

        default: // invalid syscall number
            return -1;
    }
}
