#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <syscall.h>
#include <ncurses.h>
#include <fcntl.h>
#include <elf.h>
#include "alienos.h"

#define SYS_getrandom 318


void child(const char *prog, pid_t emu_pid) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL)) {
        perror("prctl");
        exit(127);
    }

    // checks if parent died before we set its death signal
    if (getppid() != emu_pid) {
        printf("emu process died, exiting\n");
        exit(127);
    }

    // sets parent as the tracer (does not stop the tracee)
    if(ptrace(PTRACE_TRACEME, 0, 0, 0)) {
        perror("ptrace(PTRACE_TRACEME)");
        exit(127);
    }

    // allows parent to set ptrace options before execve happens
    if(raise(SIGSTOP)) {
        printf("raise(SIGSTOP)\n");
        exit(127);
    }

    // executes the program from the file
    //TODO
    if(execve(prog, NULL, NULL)) {
        perror("execv()");
        exit(127);
    }
}

void do_return(pid_t prog_pid, struct user_regs_struct regs_struct, uint64_t return_value) {
    regs_struct.rax = return_value;
    if(ptrace(PTRACE_SETREGS, prog_pid, 0, &regs_struct)) {
        perror("PTRACE_SETREGS");
        exit(127);
    }
}

// TODO error handling
uint32_t do_getrand() {
    uint32_t return_value;
    if(syscall(SYS_getrandom, &return_value, 4, 0) != 4) {
        perror("getrandom");
        exit(127);
    }
    //printf("[syscall] getrand, zwracam %d\n", return_value);
    return return_value;
}

inline bool is_key_correct(int c) {
    return c >= ALIENOS_ASCII_LOWEST && c <= ALIENOS_ASCII_HIGHEST;
}

int do_getkey() {
    //printf("[syscall] getkey, zwracam 0x83(strzalka w prawo)\n");
    int key;
    while(1) {
        switch(key = getch()) {
            case ERR:
                printf("getkey\n");
                exit(127);
            case KEY_RIGHT:
                return ALIENOS_KEY_RIGHT;
            case KEY_LEFT:
                return ALIENOS_KEY_LEFT;
            case KEY_UP:
                return ALIENOS_KEY_UP;
            case KEY_DOWN:
                return ALIENOS_KEY_DOWN;
            case KEY_ENTER:
                return ALIENOS_KEY_ENTER;
            default:
                if(is_key_correct(key)) {
                    return key;
                }
        }
    }
}



inline void check_coords(int x, int y) {
    if(x < 0 || x >= ALIENOS_COLUMNS || y < 0 || y >= ALIENOS_ROWS) {
        printf("check_coords\n");
        exit(127);
    }
}

int get_color(uint16_t achar) {
    static int colors[16] = {0}; // TODO
    int index = (achar >> 8) & 0xf;
    return colors[index];
}

void do_setcursor(int x, int y) {
    check_coords(x, y);
    if(move(y, x) == ERR) {
        printf("do_setcursor first move\n");
        exit(127);
    }
    //printw("[syscall] setcursor z parametrami: x = %d, y = %d\n", x, y);
    refresh();
}

chtype get_printable(uint16_t achar, int i) {
    int c = achar & 0xff;
    if(!is_key_correct(c)) {
        printf("got achar: %x, c: %x, i: %d", (uint32_t)achar, c, i);
        printf("get_printable\n");
        exit(127);
    }
    return (chtype)(c | get_color(achar));
}

void do_print(int x, int y, uint16_t *chars, int n) {
    check_coords(x, y);
    check_coords(x + n - 1, y);
    int i, old_x, old_y;
    getyx(stdscr, old_y, old_x);
    if(move(y, x) == ERR) {
        printf("do_print first move\n");
        exit(127);
    }
    for(i = 0; i < n; ++i) {
        if(addch(get_printable(chars[i], i)) == ERR) {
            printf("do_print addch\n");
            exit(127);
        }
    }

    if(move(old_y, old_x) == ERR) {
        printf("do_print last move\n");
        exit(127);
    }
    //printw("[syscall] print z parametrami: x = %d, y = %d, chars = %p, n = %d\n", x, y, chars, n);
    //TODO refresh error handling
    refresh();
}

void copy_chars_buffer(int fd, uint16_t *dest, uint16_t *src, int n) {
    if(n <= 0 || n > ALIENOS_COLUMNS) {
        exit(127);
    }
    if(pread64(fd, dest, (size_t)n * 2, (uint64_t)src) != (size_t)n * 2) {
        exit(127);
    }
}

bool do_syscall(pid_t prog_pid, int child_mem, int *exit_code) {
    struct user_regs_struct regs_struct;
    if(ptrace(PTRACE_GETREGS, prog_pid, 0, &regs_struct)) {
        perror("PTRACE_GETREGS");
        exit(127);
    }

    uint64_t syscall_number = regs_struct.orig_rax,
             arg0 = regs_struct.rdi,
             arg1 = regs_struct.rsi,
             arg2 = regs_struct.rdx,
             arg3 = regs_struct.r10,
             return_value;

    uint16_t buffer[ALIENOS_COLUMNS];

    switch (syscall_number) {
        case 0: // end
            *exit_code = (int)arg0;
            return true;
        case 1:
            return_value = (uint64_t)do_getrand();
            do_return(prog_pid, regs_struct, return_value);
            break;
        case 2:
            return_value = (uint64_t)do_getkey();
            do_return(prog_pid, regs_struct, return_value);
            break;
        case 3:
            //TODO check long/unsigned to signed
            copy_chars_buffer(child_mem, buffer, (uint16_t *)arg2, (int)arg3);
            do_print((int)arg0, (int)arg1, buffer, (int)arg3);
            break;
        case 4:
            do_setcursor((int)arg0, (int)arg1);
            break;
        default:
            printf("invalid syscall invoked: %lld\n", regs_struct.orig_rax);
            exit(127);
    }
    return false;
}

void parent(pid_t prog_pid, int *exit_code_ptr) {
    // pierwszy wait
    // sprawdzic czy nie ma bledu / zakonczenia dziecka
    // ustawic opcje
    // robic wait az do execve event, przechwytujac SIGSTOP (czy tylko ???)
    // jak dostaniemy execve event, przejsc do petli emulujacej

    int wstatus;
    int wsignal;
    int child_mem;

    char child_mem_path[64];
    memset(child_mem_path, 0, 64);
    //TODO error handling
    snprintf(child_mem_path, 64, "/proc/%d/mem", prog_pid);

    if(waitpid(prog_pid, &wstatus, 0) == -1) {
        perror("first waitpid");
        exit(127);
    }
    if(!WIFSTOPPED(wstatus)) {
        printf("first WIFSTOPPED\n");
        exit(127);
    }
    if(ptrace(PTRACE_SETOPTIONS, prog_pid, 0, PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD)) {
        perror("PTRACE_SETOPTIONS");
        exit(127);
    }
    wsignal = WSTOPSIG(wstatus);
    if(wsignal != SIGSTOP) {
        printf("child received unexpected signal\n");
        exit(127);
    }

    while(1) {
        if(ptrace(PTRACE_CONT, prog_pid, 0, 0)) {
            perror("PTRACE_CONT");
            exit(127);
        }

        if(waitpid(prog_pid, &wstatus, 0) == -1) {
            perror("preexecve waitpid");
            exit(127);
        }

        if(!WIFSTOPPED(wstatus)) {
            printf("first WIFSTOPPED\n");
            exit(127);
        }
        wsignal = WSTOPSIG(wstatus);
        if(wsignal == SIGSTOP) {
            continue;
        }
        if(wsignal == SIGTRAP) {
            if(wstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
                //printf("execve caught\n");
                if((child_mem = open(child_mem_path, O_RDWR | O_LARGEFILE)) == -1) {
                    exit(127);
                }
                break;
            }
            if(wstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
                printf("child exited unexpectedly\n");
                exit(127);
            }
            printf("received unexpected SIGTRAP\n");
            exit(127);
        }
        printf("received unexpected signal: %s\n", strsignal(wsignal));
        exit(127);
    }

    bool child_exited = false;

    while(!child_exited) {
        if(ptrace(PTRACE_SYSEMU, prog_pid, 0, 0)) {
            perror("PTRACE_SYSEMU");
            exit(127);
        }

        if(waitpid(prog_pid, &wstatus, 0) == -1) {
            perror("postexecve waitpid");
            exit(127);
        }

        if(!WIFSTOPPED(wstatus)) {
            printf("first WIFSTOPPED\n");
            exit(127);
        }
        wsignal = WSTOPSIG(wstatus);
        if(wsignal == (SIGTRAP | 0x80)) {
            child_exited = do_syscall(prog_pid, child_mem, exit_code_ptr);
            continue;
        }

        if(wstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
            printf("child exited unexpectedly\n");
            exit(127);
        }

        printf("received unexpected signal: %s\n", strsignal(wsignal));
        exit(127);
    }

    // po odpaleniu

}

int main(int argc, char **argv) {
    if(argc < 2) {
        printf("Usage: emu program [program_parameters]\n");
        return 127;
    }
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    scrollok(stdscr, false);
    //FIXME
    wresize(stdscr, ALIENOS_ROWS + 1, ALIENOS_COLUMNS);
    refresh();


    const char *prog = argv[1];
    pid_t emu_pid = getpid();
    pid_t prog_pid;
    int exit_code = 127;

    switch(prog_pid = fork()) {
        case -1:
            perror("fork()");
            return 127;
        case 0:
            child(prog, emu_pid);
            break;
        default:
            parent(prog_pid, &exit_code);
    }

    endwin();
    return exit_code;
}
