#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <ncurses.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <wait.h>
#include "alienos.h"
#include <asm/ptrace.h>


#define SYS_getrandom 318

// 0 - no colors, 1 - limited colors, 2 - full colors
int color_level = 0;


// Returns maximum number of parameters or -1, fills params_addr
int find_params(const char *path, uint64_t *params_addr) {
    int fd;
    Elf64_Half i;
    Elf64_Ehdr ehdr_struct;
    Elf64_Off phdr_off;
    Elf64_Half phdr_size;
    Elf64_Half phdr_count;
    Elf64_Phdr phdr_struct;
    uint64_t params_count = 0;
    bool params_found = false;

    if((fd = open(path, O_LARGEFILE | O_RDONLY)) == -1) {
        goto fail_no_close;
    }

    if(pread64(fd, &ehdr_struct, sizeof(Elf64_Ehdr), 0) != sizeof(Elf64_Ehdr)) {
        perror("pread(prog_source)");
        goto fail;
    }

    phdr_off = ehdr_struct.e_phoff;
    phdr_size = ehdr_struct.e_phentsize;
    phdr_count = ehdr_struct.e_phnum;

    for(i = 0; i < phdr_count; ++i, phdr_off += phdr_size) {
        if(pread64(fd, &phdr_struct, sizeof(Elf64_Phdr), phdr_off) != sizeof(Elf64_Phdr)) {
            perror("pread(prog_source)");
            goto fail;
        }

        if(phdr_struct.p_type == ALIENOS_PT_PARAMS) {
            if(params_found) { // duplicate PT_PARAMS segment
                return -1;
            }
            params_found = true;
            *params_addr = phdr_struct.p_paddr;
            params_count = phdr_struct.p_memsz;
            if(params_count % 4) {
                goto fail;
            }
            params_count /= 4;
        }
    }

    if(close(fd)) {
        perror("close(prog_source)");
        goto fail_no_close;
    }

    if(params_count > INT_MAX) { // argc is int anyways
        return INT_MAX;
    }

    return (int)params_count;

    fail:
    if(close(fd)) {
        perror("close(prog_source)");
    }
    fail_no_close:
    return -1;
}


int child(const char *path, pid_t ppid) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL)) {
        perror("[child] prctl");
        return -1;
    }

    // checks if parent died before we set its death signal
    if (getppid() != ppid) {
        if(printf("[child] parent process died, exiting\n") == -1) {
            perror("[child] printf()");
        }
        return -1;
    }

    // sets parent as the tracer (does not stop the tracee)
    if(ptrace(PTRACE_TRACEME, 0, 0, 0)) {
        perror("[child] ptrace(PTRACE_TRACEME)");
        return -1;
    }

    // allows parent to set ptrace options before execve happens
    if(raise(SIGSTOP)) {
        if(printf("[child] raise(SIGSTOP)\n") == -1) {
            perror("[child] printf()");
        }
        return -1;
    }

    // executes the program from the file
    char * const empty = { NULL }; // empty argv & env
    if(execve(path, &empty, &empty)) {
        perror("[child] execv()");
        return -1;
    }

    return -1; // not reachable
}

static inline bool key_correct(int c) {
    return c >= ALIENOS_ASCII_LOWEST && c <= ALIENOS_ASCII_HIGHEST;
}

int do_getkey(uint64_t *return_value_ptr) {
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



static inline bool coords_correct(int x, int y) {
    return (x >= 0 && x < ALIENOS_COLUMNS && y >= 0 && y < ALIENOS_ROWS);
}

int get_color(chtype *color, uint16_t achar) {
    int color_id = 0;

    if(color_level) {
        color_id = (achar >> 8) & 0xf;
        color_id += 1;
    }

    *color = COLOR_PAIR(color_id);
    return (color_id == ERR) ? -1 : 0;
}

int do_setcursor(int x, int y) {
    return (!coords_correct(x, y) || move(y, x) == ERR || refresh() == ERR) ? -1 : 0;
}

int get_chtype(chtype *ch, uint16_t achar) {
    chtype c = (chtype)(achar & 0xff);
    chtype color;

    if((!key_correct((int)c)) || get_color(&color, achar)) {
        return -1;
    }

    *ch = c | color;
    return 0;
}

int do_print(int x, int y, uint16_t *achars, int n) {
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

int copy_output_buffer(int fd, uint16_t *dest, uint64_t src_off, int n) {
    return (n <= 0 || n > ALIENOS_COLUMNS
            || pread64(fd, dest, (size_t)n * 2, src_off) != (size_t)n * 2)
            ? -1 : 0;
}

int do_return(uint64_t return_value, pid_t prog_pid, struct user_regs_struct regs_struct) {
    regs_struct.rax = return_value;
    return (int)ptrace(PTRACE_SETREGS, prog_pid, 0, &regs_struct);
}

int do_getrand(uint64_t *return_value_ptr) {
    return (syscall(SYS_getrandom, return_value_ptr, 4, 0) != 4) ? -1 : 0;
}

// returns 1 if child called end, -1 if there was an error, 0 otherwise
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

int inject_params(int child_mem, int arg_count, char **args, uint64_t params_addr) {
    int i;
    long long int arg;
    uint64_t dest_off = params_addr;

    for(i = 0; i < arg_count; ++i, dest_off += 4) {
        if((arg = strtoll(args[i], NULL, 10)) < INT32_MIN || arg > INT32_MAX) {
            if(printf("argument number %d is not a 32-bit int\n", i) == -1) {
                perror("printf()");
                return -1;
            }
        }

        if(pwrite64(child_mem, &arg, 4, dest_off) != 4) {
            if(printf("pwrite(child_mem)\n") == -1) {
                perror("printf()");
                return -1;
            }
        }
    }
    return 0;
}

int init_colors() {
    short i;

    if(start_color() == ERR) {
        return -1;
    }

    if(!has_colors() || COLOR_PAIRS < 9 || COLORS < 7) { // no colors
        return 0;
    }

    if(!can_change_color() || COLOR_PAIRS < 18 || COLORS < 16) { // limited colors
        short fg[16] = {
            COLOR_BLACK,
            COLOR_BLUE,
            COLOR_GREEN,
            COLOR_CYAN,
            COLOR_RED,
            COLOR_MAGENTA,
            COLOR_YELLOW,
            COLOR_WHITE, // light gray
            COLOR_WHITE, // dark gray
            COLOR_BLUE, // light ...
            COLOR_GREEN,
            COLOR_CYAN,
            COLOR_RED,
            COLOR_MAGENTA,
            COLOR_YELLOW,
            COLOR_WHITE,
        };

        for(i = 0; i < 16; ++i) {
            if (init_pair(i + (short)1, fg[i], COLOR_BLACK) == ERR) {
                return -1;
            }
        }
        return 1;
    }

    short rgb[16][3] = {
        {0, 0, 0}, // black
        {0, 0, 500}, // blue
        {0, 650, 0}, // green
        {0, 500, 500}, // cyan
        {600, 0, 0}, // red
        {700, 0, 700}, // pink
        {700, 700, 0}, // yellow
        {750, 750, 750}, // light gray
        {500, 500, 500}, // dark gray
        {0, 0, 1000}, // light blue
        {0, 1000, 0}, // light green
        {0, 1000, 1000}, // light cyan
        {1000, 0, 0}, // light red
        {1000, 191, 1000}, // light pink
        {1000, 1000, 0}, // light yellow
        {1000, 1000, 1000}, // white
    };

    for(i = 0; i < 16; ++i) {
        if(init_color(i, rgb[i][0], rgb[i][1], rgb[i][2]) == ERR) {
            return -1;
        }
    }

    for(i = 0; i < 16; ++i) {
        if (init_pair(i + (short)1, i, 0) == ERR) {
            return -1;
        }
    }

    return 2;
}

void test_colors() {
    printw("colors = %d, color_pairs = %d\n", COLORS, COLOR_PAIRS);
    refresh();
    //while(1) {};
    uint16_t achars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    uint16_t level = '0' + color_level;

    do_print(0, 0, &level, 1);

    int i;
    for(i = 0; i < 16; ++i) {
        achars[i] |= (i << 8);
    }

    do_print(0, 1, achars, 16);

    while(1) {}
}


int parent(int *exit_code_ptr, pid_t cpid, int arg_count, char **args, uint64_t params_addr) {
    int wstatus;
    int wsignal;
    int child_mem;
    int syscall_status;

    char mem_path[16];
    memset(mem_path, 0, 16);

    if(snprintf(mem_path, 16, "/proc/%d/mem", cpid) < 11) {
        if(printf("snprintf()\n") == -1) {
            perror("printf()");
        }
        goto fail_no_close;
    }

    if(waitpid(cpid, &wstatus, 0) != cpid) {
        perror("waitpid()");
        goto fail_no_close;
    }

    if(!WIFSTOPPED(wstatus)) {
        if(printf("child died before raising sigstop\n") == -1) {
            perror("printf()");
        }
        goto fail_no_close;
    }
    wsignal = WSTOPSIG(wstatus);

    // we expect exactly one SIGSTOP that child raises
    if(wsignal != SIGSTOP) {
        if(printf("child received unexpected signal\n") == -1) {
            perror("printf()");
        }
        goto fail_no_close;
    }

    if(ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD)) {
        perror("ptrace(PTRACE_SETOPTIONS)");
        goto fail_no_close;
    }

    if(ptrace(PTRACE_CONT, cpid, 0, 0)) {
        perror("ptrace(PTRACE_CONT)");
        goto fail_no_close;
    }

    if(waitpid(cpid, &wstatus, 0) != cpid) {
        perror("waitpid()");
        goto fail_no_close;
    }

    if(!WIFSTOPPED(wstatus)) {
        if(printf("WIFSTOPPED()\n") == -1) {
            perror("printf()");
        }
        goto fail_no_close;
    }
    wsignal = WSTOPSIG(wstatus);

    // we expect exactly exec event
    if(wsignal == SIGTRAP) {
        if(wstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {

            if((child_mem = open(mem_path, O_RDWR | O_LARGEFILE)) == -1) {
                perror("open(prog_mem)");
                goto fail_no_close;
            }

            if(inject_params(child_mem, arg_count, args, params_addr)) {
                goto fail;
            }
        }
        else if(wstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
            if(printf("child exited unexpectedly before execve\n") == -1) {
                perror("printf()");
            }
            goto fail_no_close;
        }
        else {
            if(printf("received unexpected SIGTRAP\n") == -1) {
                perror("printf()");
            }
            goto fail_no_close;
        }
    }
    else {
        if (printf("received unexpected signal: %s\n", strsignal(wsignal)) == -1) {
            perror("printf()");
        }
        goto fail_no_close;
    }

    initscr(); // on error calls exit, unfortunately we cannot pass exit code

    // we need one additional row so that addch in bottom-right field does not return error
    if(cbreak() == ERR
       || noecho() == ERR
       || keypad(stdscr, TRUE) == ERR
       || wresize(stdscr, ALIENOS_ROWS + 1, ALIENOS_COLUMNS) == ERR
       || (color_level = init_colors()) == -1
       || refresh() == ERR) {
        goto fail;
    }

    //test_colors();// TODO remove

    while(1) {
        if(ptrace(PTRACE_SYSEMU, cpid, 0, 0) || (waitpid(cpid, &wstatus, 0) != cpid) || !WIFSTOPPED(wstatus)) {
            goto fail;
        }
        wsignal = WSTOPSIG(wstatus);

        // child in syscall-stop
        if(wsignal == (SIGTRAP | 0x80)) {
            syscall_status = do_syscall(exit_code_ptr, cpid, child_mem);
            if(syscall_status == 1) {
                break;
            }
            else if(!syscall_status) {
                continue;
            }
        }
        // unexpected exit, signal or syscall error
        goto fail;
    }

    endwin();
    if(close(child_mem)) {
        perror("close(prog_mem)");
    }

    return 0;

    fail:
        endwin();
        if(close(child_mem)) {
            perror("close(prog_mem)");
        }
    fail_no_close:
        return -1;
}




int main(int argc, char **argv) {
    const char *prog_path;
    int params_count;
    uint64_t params_addr;
    pid_t emu_pid = getpid();
    pid_t prog_pid;
    int arg_count;
    int exit_code = 127;

    if(argc < 2) {
        if(printf("Usage: emu program [program_parameters]\n") == -1) {
            perror("printf");
        }
        return 127;
    }

    prog_path = argv[1];

    if((params_count = find_params(prog_path, &params_addr)) < 0) {
        return 127;
    }

    arg_count = (params_count < (argc - 2)) ? params_count : (argc - 2);


    switch(prog_pid = fork()) {
        case -1:
            perror("fork()");
            return 127;
        case 0:
            if(child(prog_path, emu_pid)) {
                return 127;
            }
        default:
            if(parent(&exit_code, prog_pid, arg_count, (argv + 2), params_addr) == -1) {
                return 127;
            }
    }

    return exit_code;
}
