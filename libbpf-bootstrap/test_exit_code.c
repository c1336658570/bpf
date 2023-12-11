// gcc test_exit_code.c -o test_exit_code -g -gdwarf-2 -g3
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

int main(void)
{
	int count = 1;
	int pid;
	int status;

	pid = fork();
	printf("pid=%d\n", pid);

	if (pid < 0) {
		perror("fork error : ");
	} else if (pid == 0) {
		printf("This is son, his count is: %d (%p). and his pid is: %d\n", ++count, &count, getpid());
		// sleep(3);
		int *a = 0;
		// *a = 3;
		exit(9999);		// 测试进程退出码
	} else {
		pid = wait(&status);

		printf("This is father, his count is: %d (%p), his pid is: %d, son exit status: %d[%08x]\n", count, &count, getpid(), status, status);
		exit(9999);
	}

	return 0;
}
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/// @description "Process ID to trace"
const volatile int pid_target = 0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid_target && pid_target != pid)
        return false;

    // Use bpf_printk to print the process information
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

/// "Trace open family syscalls."
char LICENSE[] SEC("license") = "GPL";