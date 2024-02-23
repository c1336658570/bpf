// gcc 04加载BPF程序.c -o 04加载BPF程序
#include <errno.h>          // 为了错误处理
#include <linux/bpf.h>      // 位于/usr/include/linux/bpf.h, 包含BPF系统调用的一些常量, 以及一些结构体的定义
#include <stdint.h>         // 为了uint64_t等标准类型的定义
#include <stdio.h>
#include <stdlib.h>         // 为了exit()函数
#include <sys/syscall.h>    // 为了syscall()

// 类型转换
#define ptr_to_u64(x) ((uint64_t)x)

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

// 通过系统调用, 向内核加载一段BPF指令
// BPF_PROG_LOAD命令用于在内核中装载eBPF程序, 返回一个与eBPF程序关联的文件描述符
// prog_type如下
/*
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
  ...
	BPF_PROG_TYPE_SYSCALL,    // a program that can execute syscalls
};
*/
// insns是struct bpf_insn指令组成的数组
// insn_cnt是insns中指令的个数
// license是许可字符串, 为了与标志为gpl_only的助手函数匹配必须设置GPL
// log_buf是一个调用者分配的缓冲区, 内核中的验证器可以在里面保存验证的log信息. 这个log信息由多行字符串组成, 目的是让程序作者明白为什么验证器认为这个程序是不安全的(相当于编译器的日志), 随着验证器的发展, 输出格式可能会改变
// log_size是log_buf的缓冲区大小, 要是缓冲区不足以保存全部的验证器日志, 那么会返回-1, 并把errno设置为ENOSPC
// log_level是验证器日志的详细级别, 00表示验证器不会提供日志, 在这种情况下log_buf必须是空指针, log_size必须是0
// 对返回的文件描述符调用close()会卸载eBPF程序
#define LOG_BUF_SIZE 65536
char bpf_log_buf[LOG_BUF_SIZE];
int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns, int insn_cnt, const char *license) {
  union bpf_attr attr = {
    .prog_type = type,                    // 程序类型
    .insns = ptr_to_u64(insns),           // 指向指令数组的指针
    .insn_cnt = insn_cnt,                 // 有多少条指令
    .license = ptr_to_u64(license),       // 指向整数字符串的指针
    .log_buf = ptr_to_u64(bpf_log_buf),   // log输出缓冲区
    .log_size = LOG_BUF_SIZE,             // log缓冲区大小
    .log_level = 2,                       // log等级
    // 0: 不记录任何日志信息。
    // 1: 记录错误信息。
    // 2: 记录警告信息。
    // 3: 记录信息性的消息。
    // 4: 记录调试信息。
  };

  return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

// BPF程序就是一个bpf_insn数组, 一个struct bpf_insn代表一条bpf指令
// /usr/include/linux/bpf_common.h中定义了一些宏，是BPF汇编值令
// /usr/src/linux-hwe-6.2-headers-6.2.0-36/include/linux/filter.h中有一些定义的BPF宏，用来当简化汇编编程
struct bpf_insn bpf_prog[] = {
  {0xb7, 0, 0, 0, 0x2},       // 初始化一个struct bpf_insn, 指令含义: mov r0, 0x2;
  {0x95, 0, 0, 0, 0x0},       // 初始化一个struct bpf_insn, 指令含义: exit;
};

int main(void) {
  // 加载一个bpf程序
  int prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, bpf_prog, sizeof(bpf_prog) / sizeof(bpf_prog[0]), "GPL");
  if (prog_fd < 0) {
    perror("BPF load prog");
    exit(-1);
  }

  printf("prog_fd: %d\n", prog_fd);
  printf("%s\n", bpf_log_buf);          // 输出程序日志

  return 0;
}