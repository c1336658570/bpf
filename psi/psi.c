// gcc psi.c -o psi
// sudo ./psi

/**
 * psi的使用
 * 
 * cat /proc/pressure/cpu 
 * some avg10=0.00 avg60=0.08 avg300=0.04 total=328643428
 * full avg10=0.00 avg60=0.00 avg300=0.00 total=0
 * 
 * cat /proc/pressure/io 
 * 
 * cat /proc/pressure/memory 
 * 
 * avg10、avg60 和 avg300 分别是最近 10 秒、60 秒和 300 秒的停顿时间百分比。
 * 
 * 比如avg10=0.03 意思是任务因为 CPU 资源的不可用，在最近的 10 秒内，有 0.03%的时间停顿等待 CPU。
 * 如果 avg 大于 40，也就是有 40% 时间在等待硬件资源，就说明这种资源的压力已经比较大了。
 * 
 * total 是任务停顿的总时间，以微秒（microseconds）为单位。通过 total 可以检测出停顿持续太短而无法影响平均值的情况。
 * 
 * some 指标说明一个或多个任务由于等待资源而被停顿的时间百分比。some是所有任务中等待时间内最长的那个任务等待时间的百分比
 * 比如在最近的 60 秒内，任务 A 的运行没有停顿，而由于内存紧张，任务 B 在运行过程中花了 30 秒等待内存，则 some 的值为 50%。
 * 
 * full 指标表示所有的任务由于等待资源而被停顿的时间百分比。full是所有任务都在等待的时间的百分比
 * 在最近的 60 秒内，任务 B 等待了 30 秒的内存，任务 A 等待了 10 秒内存，并且和任务 B 的等待时间重合。
 * 在这个重合的时间段 10 秒内，任务 A 和 任务 B 都在等待内存，结果是 some 指标为 50%，full 指标为 10/60 = 16.66%。
*/

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
  // 触发事件的字符串。"some 500000 1000000"，代表着在任何 1 秒的时间窗口内，
  // 如果一个或多个进程因为等待 IO 而造成的时间停顿超过了阈值 500ms，将触发通知事件。
  const char trig[] = "some 500000 1000000";
  struct pollfd fds;    // 创建一个 pollfd 结构体，用于监视文件描述符
  int n;                // 用于保存 poll 函数的返回值

  // 打开文件 /proc/pressure/io，设置为读写和非阻塞模式
  fds.fd = open("/proc/pressure/io", O_RDWR | O_NONBLOCK);
  if (fds.fd < 0) {
    // 处理文件打开错误
    printf("/proc/pressure/io open error: %s\n", strerror(errno));
    return 1;
  }
  // 监视 POLLPRI 事件（高优先级数据可读）
  fds.events = POLLPRI;

  // 向文件写入触发事件的字符串
  if (write(fds.fd, trig, strlen(trig) + 1) < 0) {
    // 处理写入错误
    printf("/proc/pressure/io write error: %s\n", strerror(errno));
    return 1;
  }

  // 输出提示信息
  printf("waiting for events...\n");
  while (1) {
    // 使用 poll 函数监听文件描述符的事件
    n = poll(&fds, 1, -1);
    if (n < 0) {
      // 处理 poll 函数错误
      printf("poll error: %s\n", strerror(errno));
      return 1;
    }
    if (fds.revents & POLLERR) {
      // 处理 POLLERR 事件，表明事件源已经不存在
      printf("got POLLERR, event source is gone\n");
      return 0;
    }
    if (fds.revents & POLLPRI) {
      // 处理 POLLPRI 事件，表明触发了事件
      printf("event triggered!\n");
    } else {
      // 处理其他未知事件
      printf("unknown event received: 0x%x\n", fds.revents);
      return 1;
    }
  }

  return 0;
}
