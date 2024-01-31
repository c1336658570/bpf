/*
 * 
 * # 使用probe，在a.out的sum函数设置一个事件
 * sudo perf probe -x ./a.out sum
 * Added new event:
 * probe_a:sum          (on sum in /home/cccmmf/bpf/perf/a.out)
 * You can now use it in all perf tools, such as:
 *         perf record -e probe_a:sum -aR sleep 1
 * 
 * sudo perf probe -d sum			# 删除sum上的probe
 * 
 * 不知道为什么sudo perf record -e probe_a:sum ./a.out一直报错，不能用
 * sudo perf record -e probe_a:sum ./a.out
 * 
 * sudo perf report
 * 
 * sudo perf script
 * 
 * 不知道为什么sudo perf stat -e probe_a:sum ./a.out一直报错，不能用
 * sudo perf stat -e probe_a:sum ./a.out
*/

#include <unistd.h>

int sum (int a, int b) {
  return a + b;
}

int main(void) {
  for (int i = 0; ; i++) {
    sum(1, 2);
    sleep(1);
  }

  return 0;
}