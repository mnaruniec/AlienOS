#define _GNU_SOURCE
#include <stdio.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h> // TODO might be necessary
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <syscall.h>
#include "alienos.h"

#define SYS_getrandom 318


void child(const char *prog, pid_t emu_pid) {
    // TODO przeczytac man execve
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
    printf("[syscall] getrand, zwracam %d\n", return_value);
    return return_value;
}

int do_getkey() {
    printf("[syscall] getkey, zwracam 0x83(strzalka w prawo)\n");
    return 0x83;
}

void do_print(int x, int y, uint16_t *chars, int n) {
    printf("[syscall] print z parametrami: x = %d, y = %d, chars = %p, n = %d\n", x, y, chars, n);
}

void do_setcursor(int x, int y) {
    printf("[syscall] setcursor z parametrami: x = %d, y = %d\n", x, y);
}

bool do_syscall(pid_t prog_pid, int *exit_code) {
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
            do_print((int)arg0, (int)arg1, (uint16_t *)arg2, (int)arg3);
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

void parent(pid_t prog_pid) {
    // pierwszy wait
    // sprawdzic czy nie ma bledu / zakonczenia dziecka
    // ustawic opcje
    // robic wait az do execve event, przechwytujac SIGSTOP (czy tylko ???)
    // jak dostaniemy execve event, przejsc do petli emulujacej

    int wstatus;
    int wsignal;
    int exit_code;

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
                printf("execve caught\n");
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
            child_exited = do_syscall(prog_pid, &exit_code);
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

    const char *prog = argv[1];
    pid_t emu_pid = getpid();
    pid_t prog_pid;

    switch(prog_pid = fork()) {
        case -1:
            perror("fork()");
            return 127;
        case 0:
            child(prog, emu_pid);
            break;
        default:
            parent(prog_pid);
    }


    return 0;
}
