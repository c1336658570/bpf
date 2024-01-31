// man 手册的代码示例
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

/*
 * static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags): 定义一个静态的 perf_event_open 函数，用于调用 perf_event_open 系统调用。
 * struct perf_event_attr pe;: 定义 perf_event_attr 结构体变量 pe，用于配置 perf 事件的属性。
 * long long count;: 用于存储事件计数的变量。
 * int fd;: 用于存储 perf 事件的文件描述符。
 * memset(&pe, 0, sizeof(pe));: 使用 memset 函数将 pe 结构体初始化为零。
 * pe.type = PERF_TYPE_HARDWARE;: 将事件类型设置为硬件事件。
 * pe.size = sizeof(pe);: 设置结构体的大小。
 * pe.config = PERF_COUNT_HW_INSTRUCTIONS;: 设置 perf 事件的具体配置，这里是统计硬件指令的数量。
 * pe.disabled = 1;: 设置 perf 事件开始时为禁用状态。
 * pe.exclude_kernel = 1;: 设置排除内核空间。
 * pe.exclude_hv = 1;: 设置排除超级用户空间。
 * fd = perf_event_open(&pe, 0, -1, -1, 0);: 调用 perf_event_open 函数打开 perf 事件，返回文件描述符。
 * if (fd == -1) { fprintf(stderr, "Error opening leader %llx\n", pe.config); exit(EXIT_FAILURE); }: 检查打开 perf 事件的结果，如果失败则输出错误信息并退出程序。
 * ioctl(fd, PERF_EVENT_IOC_RESET, 0);: 使用 ioctl 函数将 perf 事件复位。
 * ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);: 使用 ioctl 函数启用 perf 事件。
 * printf("Measuring instruction count for this printf\n");: 输出提示信息。
 * ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);: 使用 ioctl 函数禁用 perf 事件。
 * read(fd, &count, sizeof(count));: 使用 read 函数读取事件计数。
 * printf("Used %lld instructions\n", count);: 输出测量到的指令数量。
 * close(fd);: 关闭 perf 事件的文件描述符。
 * return 0;: 返回程序正常退出状态。
 */

// 定义 perf_event_open 系统调用的包装函数
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
  int ret;

  // 调用 perf_event_open 系统调用
  ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
  return ret;
}

int main(int argc, char **argv) {
  struct perf_event_attr pe;      // Perf 事件属性结构体
  long long count;                // 存储事件计数的变量
  int fd;                         // Perf 事件的文件描述符

  // 使用默认值初始化 perf_event_attr 结构体
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_HARDWARE;   // 事件类型（硬件）
  pe.size = sizeof(pe);           // 结构体大小
  pe.config = PERF_COUNT_HW_INSTRUCTIONS;   // 统计硬件指令数量
  pe.disabled = 1;                          // 初始禁用状态
  pe.exclude_kernel = 1;                    // 排除内核空间
  pe.exclude_hv = 1;                        // 排除超级用户空间

  // 打开新的 perf 事件，使用 perf_event_open 包装函数
  fd = perf_event_open(&pe, 0, -1, -1, 0);
  if (fd == -1) {
    fprintf(stderr, "Error opening leader %llx\n", pe.config);
    exit(EXIT_FAILURE);
  }
  // 重置并启用 perf 事件
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  printf("Measuring instruction count for this printf\n");
  
  // 禁用 perf 事件并读取事件计数
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  read(fd, &count, sizeof(count));

  // 显示测量到的指令数量
  printf("Used %lld instructions\n", count);

  // 关闭 perf 事件的文件描述符
  close(fd);
}
