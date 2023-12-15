// clang main.c -o main
// strace -f ./main "ls -la"
// [pid 2195556] write(1, "drwxrwxr-x 2 cccmmf cccmmf  4096"..., 50) = -1 EPERM (不允许的操作)
// [pid 2195556] write(1, "drwxrwxr-x 3 cccmmf cccmmf  4096"..., 51) = -1 EPERM (不允许的操作)
// ...
// [pid 2195556] write(1, "-rw-rw-r-- 1 cccmmf cccmmf  2831"..., 58) = -1 EPERM (不允许的操作)
// ...
#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

// 安装Seccomp过滤器
static int install_filter(int nr, int arch, int error) {
  // 定义Seccomp过滤规则（BPF过滤指令）。BPF过滤指令使用BPF_STMT和BPF_JUMP宏来定义。
  struct sock_filter filter[] = {
    // 加载系统调用数据结构中的arch字段
    // 将seccomp数据包中的体系结构arch作为双字节存入累加器。BPF_LD表示将数据存入累加器
    // BPF_W表示传双字节。该指令要求seccomp数据包数据在固定的BPF_ABS偏移处。
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
    // 跳转到下一个规则，如果arch字段等于指定的架构
    // 使用BPF_JEQ指令检查累加器常数BPF_K中的体系结构的值是否等于体系结构arch。
    // 如果相等，将以零偏移量跳到下一条指令。否则，由于体系结构arch不匹配，将以偏移量3进行跳转，井返回错误。
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 0, 3),
    // 加载系统调用数据结构中的nr字段
    // 将数据包中的系统调用数值nr作为双字节存入累加器中。该指令要求系统调用数值在固定的BPF_ABS偏移处。
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
    // 如果nr字段等于指定的系统调用号，跳转到下一个规则，否则执行下一条规则
    // 将系统调用数值与nr变量的值进行比较。如果相等，将转到下一条指令，井禁止系统调用。
    // 否则，将返回SECCOMP_RET_ALLOW，代表允许系统调用。
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1),
    // 返回一个错误码，允许传递一个额外的数据（error）
    // SECCOMP_RET_ERRNO。系统调用不会被执行，并且过滤器返回值中的SECCOMP_RET_DATA部分将作为errno值传递到用户空间。
    // 表示程序终止，BPF_RET表示程序返回。结果输入错误码为SECCOMP_RET_ERRNO，带有err变量的指定错误号。
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA)),
    // 允许执行系统调用。SECCOMP_RET_ALLOW，系统调用允许执行。
    // 表示程序终止，BPF_RET表示程序返回。返回值为SECCOMP_RET_ALLOW,表示允许系统调用。
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    /*
    上面的指令类似如下功能：
    if (arch != AUDIT_ARCH_X86_64) {
      return SECCOMP_RET_ERRNO;
    }
    if (nr == __NR_write) {
      return SECCOMP_RET_ERRNO;
    }
    return SECCOMP_RET_ALLOW;
    */
  };
  // 定义sock_fprog结构体，该结构体包含过滤代码和过滤器本身的长度。该结构体将作为声明进程操作的参数
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  // 使用prctl设置Seccomp过滤器
  // SECCOMP_MODE_FILTER模式，那么Seccomp过滤将采用基于BPF过滤器的方式对系统调用进行过滤，
  // 系统调用过滤的方式与数据包的过滤方式相同。
  // 可以使用prctl函数，指定使用PR_SET_SECCOMP操作来加载Seccomp过滤器。
  // 这些Seccomp过滤器是BPF程序，该程序会在每个Seccomp数据包上执行，数据包以seccomp_data结构表示。
  /*
  struct seccomp_data {
  int nr;
  __u32 arch;     // 体系结构
  __u64 instruction_pointer;    // 系统调用时的CPU值令指针
  __u64 args[6];                // 六个类型为uint64的系统调用参数
  };
  */
  // 加载程序！使用prctl并使用PR_SET_SECCOMP作为选项，进入安全的计算模式。
  // 然后，我们使用SECCOMP_MODE_FILTER参数指定seccomp模式来加载过滤器，
  // SECCOMP_MODE_FILTER包含在sock_fprog类型的prog变量中
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
    perror("prctl(PR_SET_SECCOMP)");
    return 1;
  }
  return 0;
}

int main(int argc, char const *argv[]) {
  // 使用prctl设置PR_SET_NO_NEW_PRIVS标志，用来避免子进程具有比父进程更大的权限。
  // 这使我们可以在没有root权限的情况下，在install_filter函数中调用prctl。
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    return 1;
  }
  // 安装Seccomp过滤器，限制系统调用__NR_write的执行，返回错误码EPERM
  // 调用install_filter函数。我们将阻止所有与X86-64体系结构相关的write系统调用，拒绝所有相关的写尝试。
  install_filter(__NR_write, AUDIT_ARCH_X86_64, EPERM);
  // 执行传递给程序的命令
  return system(argv[1]);
}
