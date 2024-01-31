perf是一款Linux性能分析工具。Linux性能计数器是一个新的基于内核的子系统，它提供一个性能分析框架，比如硬件（CPU、PMU(Performance Monitoring Unit)）功能和软件(软件计数器、tracepoint)功能。
通过perf，应用程序可以利用PMU、tracepoint和内核中的计数器来进行性能统计。它不但可以分析制定应用程序的性能问题（per thread），也可以用来分析内核的性能问题，当然也可以同事分析应用程序和内核，从而全面理解应用程序中的性能瓶颈。

使用perf，可以分析程序运行期间发生的硬件事件，比如instructions retired、processor clock cycles等；也可以分析软件时间，比如page fault和进程切换。

perf是一款综合性分析工具，大到系统全局性性能，再小到进程线程级别，甚至到函数及汇编级别。

```bash
sudo perf record -e cycles ls -R
sudo perf report 
sudo perf stat ls

sudo perf probe --add do_sys_open
sudo perf probe --del probe:do_sys_open
perf record -e probe:do_sys_open -aR sleep10

perf trace ls

# 使用probe，在a.out的sum函数设置一个事件
sudo perf probe -x ./a.out sum                                           17:08:05
[sudo] cccmmf 的密码： 
Added new event:
  probe_a:sum          (on sum in /home/cccmmf/bpf/perf/a.out)

You can now use it in all perf tools, such as:

        perf record -e probe_a:sum -aR sleep 1

sudo perf probe -d sum			# 删除sum上的probe

sudo perf record -e probe_a:sum ./a.out

sudo perf report

sudo perf script

sudo perf stat -e probe_a:sum ./a.out
```

```bash
perf list		# 查看当前系统支持的性能事件；

perf bench		# 对系统性能进行摸底；

perf test		# 对系统进行健全性测试；

perf stat		# 对全局性能进行统计；

perf top		# 可以实时查看当前系统进程函数占用率情况；

perf probe		# 可以自定义动态事件；

perf kmem		# 针对slab子系统性能分析；

perf kvm		# 针对kvm虚拟化分析；

perf lock		# 分析锁性能；

perf mem		# 分析内存slab性能；

perf sched		# 分析内核调度器性能；

perf trace		# 记录系统调用轨迹；

pref record		# 记录信息到perf.data；

perf report		# 生成报告；

perf diff		# 对两个记录进行diff；

perf evlist		# 列出记录的性能事件；

perf annotate	# 显示perf.data函数代码；

perf archive	# 将相关符号打包，方便在其它机器进行分析；

perf script		# 将perf.data输出可读性文本；
```

```bash
perf --help

sudo perf stat -e instructions ls 		# 统计ls指令条数，执行时间，用户态时间和内核态时间

# 实时地显示系统当前的性能统计信息。
perf top

# perf record的作用和perf stat类似，它可以运行一个命令并生成统计信息，不过perf record不会将结果显示出来，而是将结果输出到文件中。perf record生成的文件可以用perf report来进行解析。
perf record & perf report
```

```bash
sudo perf list hardware		# 显示支持的硬件事件相关
sudo perf list sw			# 显示支持的软件事件列表
sudo perf list cache		# 显示硬件cache相关事件列表
sudo perf list pmu			# 显示支持的PMU事件列表
sudo perf list tracepoint	# 显示支持的所有tracepoint列表
```

```bash
sudo perf top
第一列：符号引发的性能事件的比例，指占用的cpu周期比例。

第二列：符号所在的DSO(Dynamic Shared Object)，可以是应用程序、内核、动态链接库、模块。

第三列：DSO的类型。[.]表示此符号属于用户态的ELF文件，包括可执行文件与动态链接库；[k]表述此符号属于内核或模块。

第四列：符号名。有些符号不能解析为函数名，只能用地址表示。

```

perf top界面常用命令如下：

```bash
h：显示帮助，即可显示详细的帮助信息。

UP/DOWN/PGUP/PGDN/SPACE：上下和翻页。

a：annotate current symbol，注解当前符号。能够给出汇编语言的注解，给出各条指令的采样率。

d：过滤掉所有不属于此DSO的符号。非常方便查看同一类别的符号。

P：将当前信息保存到perf.hist.N中。
```

perf top常用选项有：

```bash
-e <event>：指明要分析的性能事件。

-p <pid>：Profile events on existing Process ID (comma sperated list). 仅分析目标进程及其创建的线程。

-k <path>：Path to vmlinux. Required for annotation functionality. 带符号表的内核映像所在的路径。

-K：不显示属于内核或模块的符号。

-U：不显示属于用户态程序的符号。

-d <n>：界面的刷新周期，默认为2s，因为perf top默认每2s从mmap的内存区域读取一次性能数据。

-g：得到函数的调用关系图。
```

perf stat用于运行指令，并分析其统计结果。虽然perf top也可以指定pid，但是必须先启动应用才能查看信息。

perf stat能完整统计应用整个生命周期的信息。

```bash
perf stat [-e <EVENT> | --event=EVENT] [-a] <command>
perf stat [-e <EVENT> | --event=EVENT] [-a] — <command> [<options>]

sudo perf stat
# 输出解释如下：
cpu-clock：任务真正占用的处理器时间，单位为ms。CPUs utilized = task-clock / time elapsed，CPU的占用率。

context-switches：程序在运行过程中上下文的切换次数。

CPU-migrations：程序在运行过程中发生的处理器迁移次数。Linux为了维持多个处理器的负载均衡，在特定条件下会将某个任务从一个CPU迁移到另一个CPU。

CPU迁移和上下文切换：发生上下文切换不一定会发生CPU迁移，而发生CPU迁移时肯定会发生上下文切换。发生上下文切换有可能只是把上下文从当前CPU中换出，下一次调度器还是将进程安排在这个CPU上执行。

page-faults：缺页异常的次数。当应用程序请求的页面尚未建立、请求的页面不在内存中，或者请求的页面虽然在内存中，但物理地址和虚拟地址的映射关系尚未建立时，都会触发一次缺页异常。另外TLB不命中，页面访问权限不匹配等情况也会触发缺页异常。

cycles：消耗的处理器周期数。如果把被ls使用的cpu cycles看成是一个处理器的，那么它的主频为2.486GHz。可以用cycles / task-clock算出。

stalled-cycles-frontend：指令读取或解码的质量步骤，未能按理想状态发挥并行左右，发生停滞的时钟周期。

stalled-cycles-backend：指令执行步骤，发生停滞的时钟周期。

instructions：执行了多少条指令。IPC为平均每个cpu cycle执行了多少条指令。

branches：遇到的分支指令数。branch-misses是预测错误的分支指令数。

# 其他常用参数
    -a, --all-cpus        显示所有CPU上的统计信息
    -C, --cpu <cpu>       显示指定CPU的统计信息
    -c, --scale           scale/normalize counters
    -D, --delay <n>       ms to wait before starting measurement after program start
    -d, --detailed        detailed run - start a lot of events
    -e, --event <event>   event selector. use 'perf list' to list available events
    -G, --cgroup <name>   monitor event in cgroup name only
    -g, --group           put the counters into a counter group
    -I, --interval-print <n>
                          print counts at regular interval in ms (>= 10)
    -i, --no-inherit      child tasks do not inherit counters
    -n, --null            null run - dont start any counters
    -o, --output <file>   输出统计信息到文件
    -p, --pid <pid>       stat events on existing process id
    -r, --repeat <n>      repeat command and print average + stddev (max: 100, forever: 0)
    -S, --sync            call sync() before starting a run
    -t, --tid <tid>       stat events on existing thread id
...

执行sudo perf stat -C 0，统计CPU 0的信息。想要停止后，按下Ctrl+C终止。可以看到统计项一样，只是统计对象变了。

如果需要统计更多的项，需要使用-e，如：
sudo perf stat -e task-clock,context-switches,cpu-migrations,page-faults,cycles,stalled-cycles-frontend,stalled-cycles-backend,instructions,branches,branch-misses,L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses,dTLB-loads,dTLB-load-misses ls
```

perf bench

perf bench作为benchmark工具的通用框架，包含sched/mem/numa/futex等子系统，all可以指定所有。

perf bench可用于评估系统sched/mem等特定性能。

```bash
perf bench sched：调度器和IPC机制。包含messaging和pipe两个功能。

perf bench mem：内存存取性能。包含memcpy和memset两个功能。

perf bench numa：NUMA架构的调度和内存处理性能。包含mem功能。

perf bench futex：futex压力测试。包含hash/wake/wake-parallel/requeue/lock-pi功能。

perf bench all：所有bench测试的集合

sudo perf bench sched all
sudo perf bench sched messaging
sudo perf bench sched messaging -p
sudo perf bench sched pipe
sudo perf bench mem all
sudo perf bench futex all
```

### 3.4.1 perf bench sched all

测试messaging和pipi两部分性能。

#### 3.4.1.1 sched messaging评估进程调度和核间通信

sched message 是从经典的测试程序 hackbench 移植而来，用来衡量调度器的性能，overhead 以及可扩展性。

该 benchmark 启动 N 个 reader/sender 进程或线程对，通过 IPC(socket 或者 pipe) 进行并发的读写。一般人们将 N 不断加大来衡量调度器的可扩展性。

sched message 的用法及用途和 hackbench 一样，可以通过修改参数进行不同目的测试：

> -g, --group <n> Specify number of groups
>
> -l, --nr_loops <n> Specify the number of loops to run (default: 100)
>
> -p, --pipe Use pipe() instead of socketpair()
>
> -t, --thread Be multi thread instead of multi process

测试结果：

> al@al-System-Product-Name:~/perf$ perf bench sched all
> \# Running sched/messaging benchmark...
> \# 20 sender and receiver processes per group
> \# 10 groups == 400 processes run
>
>    Total time: 0.173 [sec]
>
> \# Running sched/pipe benchmark...
> \# Executed 1000000 pipe operations between two processes
>
>    Total time: 12.233 [sec]
>
>    12.233170 usecs/op
>       81744 ops/sec

使用pipe()和socketpair()对测试影响：

> 1. perf bench sched messaging
>
> \# Running 'sched/messaging' benchmark:
> \# 20 sender and receiver processes per group
> \# 10 groups == 400 processes run
>
>    Total time: 0.176 [sec]
>
> 
>
> 2. perf bench sched messaging -p
>
> \# Running 'sched/messaging' benchmark:
> \# 20 sender and receiver processes per group
> \# 10 groups == 400 processes run
>
>    Total time: 0.093 [sec]

可见socketpair()性能要明显低于pipe()。

#### 3.4.1.2 sched pipe评估pipe性能

sched pipe 从 Ingo Molnar 的 pipe-test-1m.c 移植而来。当初 Ingo 的原始程序是为了测试不同的调度器的性能和公平性的。

其工作原理很简单，两个进程互相通过 pipe 拼命地发 1000000 个整数，进程 A 发给 B，同时 B 发给 A。因为 A 和 B 互相依赖，因此假如调度器不公平，对 A 比 B 好，那么 A 和 B 整体所需要的时间就会更长。

> al@al-System-Product-Name:~/perf$ perf bench sched pipe
> \# Running 'sched/pipe' benchmark:
> \# Executed 1000000 pipe operations between two processes
>
>    Total time: 12.240 [sec]
>
>    12.240411 usecs/op
>       81696 ops/sec

### 3.4.2 perf bench mem all

该测试衡量 不同版本的memcpy/memset/ 函数处理一个 1M 数据的所花费的时间，转换成吞吐率。

> al@al-System-Product-Name:~/perf$ perf bench mem all
> \# Running mem/memcpy benchmark...
> \# function 'default' (Default memcpy() provided by glibc)
> \# Copying 1MB bytes ...
>
> ​    1.236155 GB/sec.
>
> ..

### 3.4.3 perf bench futex

Futex是一种用户态和内核态混合机制，所以需要两个部分合作完成，linux上提供了sys_futex系统调用，对进程竞争情况下的同步处理提供支持。

所有的futex同步操作都应该从用户空间开始，首先创建一个futex同步变量，也就是位于共享内存的一个整型计数器。

当进程尝试持有锁或者要进入互斥区的时候，对futex执行"down"操作，即原子性的给futex同步变量减1。如果同步变量变为0，则没有竞争发生， 进程照常执行。

如果同步变量是个负数，则意味着有竞争发生，需要调用futex系统调用的futex_wait操作休眠当前进程。

当进程释放锁或 者要离开互斥区的时候，对futex进行"up"操作，即原子性的给futex同步变量加1。如果同步变量由0变成1，则没有竞争发生，进程照常执行。

如果加之前同步变量是负数，则意味着有竞争发生，需要调用futex系统调用的futex_wake操作唤醒一个或者多个等待进程。

> al@al-System-Product-Name:~/perf$ perf bench futex all
> \# Running futex/hash benchmark...
> Run summary [PID 3806]: 5 threads, each operating on 1024 [private] futexes for 10 secs.
>
> [thread 0] futexes: 0x4003d20 ... 0x4004d1c [ 4635648 ops/sec ]
> [thread 1] futexes: 0x4004d30 ... 0x4005d2c [ 4611072 ops/sec ]
> [thread 2] futexes: 0x4005e70 ... 0x4006e6c [ 4254515 ops/sec ]
> [thread 3] futexes: 0x4006fb0 ... 0x4007fac [ 4559360 ops/sec ]
> [thread 4] futexes: 0x40080f0 ... 0x40090ec [ 4636262 ops/sec ]
>
> Averaged 4539371 operations/sec (+- 1.60%), total secs = 10
>
> \# Running futex/wake benchmark...
> Run summary [PID 3806]: blocking on 5 threads (at [private] futex 0x96b52c), waking up 1 at a time.
>
> [Run 1]: Wokeup 5 of 5 threads in 0.0270 ms
> [Run 2]: Wokeup 5 of 5 threads in 0.0370 ms
>
> ...

 perf record

运行一个命令，并将其数据保存到perf.data中。随后，可以使用perf report进行分析。

perf record和perf report可以更精确的分析一个应用，perf record可以精确到函数级别。并且在函数里面混合显示汇编语言和代码。

创建一个fork.c文件用于测试：

[![复制代码](https://common.cnblogs.com/images/copycode.gif)](javascript:void(0);)

```
#include <stdio.h>

void test_little(void)
{
  int i,j;

  for(i = 0; i < 30000000; i++) 
    j=i; 
}

void test_mdedium(void)
{
  int i,j;

  for(i = 0; i < 60000000; i++) 
    j=i; 
}

void test_high(void)
{
  int i,j;

  for(i = 0; i < 90000000; i++) 
    j=i; 
}

void test_hi(void)
{
  int i,j;

  for(i = 0; i < 120000000; i++) 
    j=i; 
}

int main(void)
{
  int i, pid, result;

  for(i = 0; i<2; i++) {
    result = fork();
    if(result>0)
      printf("i=%d parent parent=%d current=%d child=%d\n", i, getppid(), getpid(), result);
    else
      printf("i=%d child parent=%d current=%d\n", i, getppid(), getpid());

    if(i==0)
    {
      test_little();
      sleep(1);
    } else {
      test_mdedium();
      sleep(1);
    }
  }

  pid = wait(NULL);
  test_high();
  printf("pid=%d wait=%d\n", getpid(), pid);
  sleep(1);
  pid = wait(NULL);
  test_hi();
  printf("pid=%d wait=%d\n", getpid(), pid);
  return 0;
}
```

[![复制代码](https://common.cnblogs.com/images/copycode.gif)](javascript:void(0);)

编译fork.c文件gcc fork.c -o fork-g -O0，同时可以使用此方法分析是否选择编译优化产生的结果。-g是只能callgraph功能，-O0是关闭优化。

### 常用选项

> -e record指定PMU事件
>   --filter event事件过滤器
> -a 录取所有CPU的事件
> -p 录取指定pid进程的事件
> -o 指定录取保存数据的文件名
> -g 使能函数调用图功能
> -C 录取指定CPU的事件

sudo perf record -a -g ./fork：会在当前目录生成perf.data文件。

sudo perf report --call-graph none结果如下,后面结合perf timechart分析.

如果想只看fork产生的信息：

> sudo perf report --call-graph none -c fork

可以看出只显示了fork程序的相关符号及其占用率。

##  perf report

解析perf record产生的数据，并给出分析结果。

### 常用参数：

> -i 导入的数据文件名称，如果没有则默认为perf.data
>
> -g 生成函数调用关系图，**此时内核要打开CONFIG_KALLSYMS；用户空间库或者执行文件需要带符号信息(not stripped)，编译选项需要加上-g。**
>
> --sort 从更高层面显示分类统计信息，比如： pid, comm, dso, symbol, parent, cpu,socket, srcline, weight, local_weight.

sudo perf report -i perf.data



1.抓取perf信息并转换

> ```vhdl
> perf record -F 99 -a -g -- sleep 60
> perf script > out.perf
> ```

> ```csharp
> ./stackcollapse-perf.pl out.perf > out.folded
> ```

> ```bash
> ./flamegraph.pl out.kern_folded > kernel.svg
> ```