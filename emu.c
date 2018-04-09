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
#include <limits.h>
#include "alienos.h"

#define SYS_getrandom 318

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
        perror("prctl");
        exit(127);
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
        printf("raise(SIGSTOP)\n") {
            perror("printf()");
        }
        return -1;
    }

    // executes the program from the file
    char * const empty = { NULL }; // empty argv & env
    if(execve(path, &empty, &empty)) {
        perror("execv()");
        return -1;
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

int copy_chars_buffer(int fd, uint16_t *dest, uint16_t *src, int n) {
    if(n <= 0 || n > ALIENOS_COLUMNS) {
        return -1;
    }
    if(pread64(fd, dest, (size_t)n * 2, (uint64_t)src) != (size_t)n * 2) {
        perror("pread(prog_mem)");
        return -1;
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
            if(copy_chars_buffer(child_mem, buffer, (uint16_t *)arg2, (int)arg3)) {
                exit(127);
            }
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

int parent(pid_t cpid, int *exit_code_ptr) {
    // pierwszy wait
    // sprawdzic czy nie ma bledu / zakonczenia dziecka
    // ustawic opcje
    // robic wait az do execve event, przechwytujac SIGSTOP (czy tylko ???)
    // jak dostaniemy execve event, przejsc do petli emulujacej

    int wstatus;
    int wsignal;
    int child_mem;

    char mem_path[16];
    memset(mem_path, 0, 16);

    // TODO more handling?
    if(snprintf(mem_path, 16, "/proc/%d/mem", cpid) < 11) {
        if(printf("snprintf()\n") == -1) {
            perror("printf()");
        }
        return -1;
    }

    if(waitpid(cpid, &wstatus, 0) == -1) {
        perror("waitpid()");
        return -1;
    }
    if(!WIFSTOPPED(wstatus)) {
        if(printf("WIFSTOPPED()\n") == -1) {
            perror("printf");
        }
        return -1;
    }

    wsignal = WSTOPSIG(wstatus);
    if(wsignal != SIGSTOP) {
        if(printf("child received unexpected signal\n") == -1) {
            perror("printf");
        }
        return -1;
    }

    if(ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD)) {
        perror("ptrace(PTRACE_SETOPTIONS)");
        return -1;
    }

    while(1) {
        if(ptrace(PTRACE_CONT, cpid, 0, 0)) {
            perror("ptrace(PTRACE_CONT)");
            return -1;
        }

        if(waitpid(cpid, &wstatus, 0) == -1) {
            perror("waitpid");
            return -1;
        }

        if(!WIFSTOPPED(wstatus)) {
            if(printf("WIFSTOPPED()\n") == -1) {
                perror("printf");
            }
            return -1;
        }

        wsignal = WSTOPSIG(wstatus);

        // TODO czy potrzebne?
        if(wsignal == SIGSTOP) {
            continue;
        }
        if(wsignal == SIGTRAP) {
            if(wstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
                if((child_mem = open(mem_path, O_RDWR | O_LARGEFILE)) == -1) {
                    exit(127);
                }
                break;
            }
            if(wstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
                printf("child exited unexpectedly\n");
                exit(127);
            }
            printf("received unexpected SIGTRAP\n");
            return -1;
        }
        printf("received unexpected signal: %s\n", strsignal(wsignal));
        return -1;
    }

    bool child_exited = false;

    while(!child_exited) {
        if(ptrace(PTRACE_SYSEMU, prog_pid, 0, 0)) {
            perror("PTRACE_SYSEMU");
            return -1;
        }

        if(waitpid(prog_pid, &wstatus, 0) == -1) {
            perror("postexecve waitpid");
            return -1;
        }

        if(!WIFSTOPPED(wstatus)) {
            printf("first WIFSTOPPED\n");
            return -1;
        }
        wsignal = WSTOPSIG(wstatus);
        if(wsignal == (SIGTRAP | 0x80)) {
            child_exited = do_syscall(prog_pid, child_mem, exit_code_ptr);
            continue;
        }

        if(wstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
            printf("child exited unexpectedly\n");
            return -1;
        }

        printf("received unexpected signal: %s\n", strsignal(wsignal));
        return -1;
    }

    // po odpaleniu

}




int main(int argc, char **argv) {
    const char *prog_path;
    int params_count;
    uint64_t params_addr;
    pid_t emu_pid = getpid();
    pid_t prog_pid;
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

    switch(prog_pid = fork()) {
        case -1:
            perror("fork()");
            return 127;
        case 0:
            if(child(prog_path, emu_pid)) {
                return 127;
            }
        default:
            if(parent(prog_pid, &exit_code) == -1) {
                return 127;
            }
    }

    return exit_code;



    return 0;


    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    //FIXME
    wresize(stdscr, ALIENOS_ROWS + 1, ALIENOS_COLUMNS);
    refresh();



    endwin();

}
