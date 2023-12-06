#include <sys/sdt.h>

// 用户静态定义跟踪点

/*
 * 用户静态定义跟踪点(USDT)为用户空间的应用程序提供了静态跟踪点。用
 * 户静态定义跟踪点为BPF的跟踪功能提供了低开销接入点，是检测应用程序
 * 的便捷方告。用户静态定义跟踪点可以在生产环境中使用，用来跟踪任何编程语言编写的应用程序。
 * 
 * 像静态内核跟踪点一样，USDT允许开发人员添加代码监测指令，内核将
 * USDT作为陷阱，用来执行BPF程序。USDT的Hello World只有几行代码:
 * 
 * 在演示如何将 BPF 程序附加到用户定义跟踪点之前，我们需要谈论一下如何
 * 发现USDT。因为这些跟踪点以二进制格式定义在可执行文件中，我们需要
 * 一种无须研究源代码就能查看程序定义的探针的方法。提取该信息的一种方
 * 也是直接读取 ELF 二进制文件。首先，我们将使用 GCC 编译上述的USDT Hello World示例:
 * gcc -o hello_usdt hello_usdt.c
 * 
 * readelf -n ./hello_usdt
 * 显示ELF文件中的信息。输出包括定义的USDT。NT_STAPSDT
 * 
 * 对于发现二进制文件中定义的跟踪点，更好的办怯是使用 BCC 的 tplist 工
 * 具来显示内核跟踪点和USDT。 tplist 工具的优点是输出简单，它仅显示
 * 跟踪点定义，没有有关可执行文件的任何其他信息。它的用法类似于 readelf的用法:
 * tplist-bpfcc -l ./hello_usdt
 * tplist 工具可以单独列出每个定义的跟踪点。在我们的示例中，它仅显示一行(定义probe-main跟踪点):
 * b'./hello_usdt' b'hello - usdt':b'probe - main
 * 
 * 当获得二进制文件支持的跟踪点之后，你就可以像之前的示例那样，以简单的方式将 BPF 程序附加到这些跟踪点上:
*/

int main(int argc, char const *argv[]) {
  // 用Linux提供的宏DTRACE_PROBE来定义我们的第一个USDT。
  // DTRACE_PROBE用于注册跟踪点，内核通过此跟踪点来注入BPF函数回调。宏的第一个参数是被跟踪程序。第二个参数是跟踪名。
  DTRACE_PROBE(hello - usdt, probe - main);
  return 0;
}
