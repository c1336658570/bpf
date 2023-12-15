## BPFTool

### 特征查看

```bash
sudo bpftool feature		# 得到一个详尽的输出，其中包含系统所有支持的BPF特征的详情。

该命令用于显示关于系统支持的所有BPF（Berkeley Packet Filter）特性的详细信息。它提供了有关内核中BPF子系统支持的功能和特性的概述。这些功能可以包括不同类型的BPF程序、映射以及其他功能。运行此命令有助于用户了解其支持BPF的内核的功能。

输出可能包括以下详细信息：

BPF程序类型（例如，BPF_PROG_TYPE_SOCKET_FILTER，BPF_PROG_TYPE_XDP）
BPF映射类型（例如，BPF_MAP_TYPE_HASH，BPF_MAP_TYPE_ARRAY）
某些参数的最大允许值
支持的BPF指令及其特性
运行此命令有助于用户了解其系统上有哪些BPF特性以及它们在特定用例中可以用于什么目的。
```

### 检查BPF程序

```bash
sudo bpftool prog show 		# 检查系统中运行程序的情况。

472: cgroup_skb  tag 6deef7357e7b4530  gpl
	loaded_at 2023-12-08T06:59:13+0800  uid 0
	xlated 64B  jited 58B  memlock 4096B
	pids systemd(1)

冒号前左侧数字表示程序标识符，后面我们将根据程序标识符来检查程序的详细信息。此程序被附加到 cgroup 套接字缓存区中。如果这些程序是由 Systemd 启动的，那么程序的加载时间将与系统启动时的时间是匹配的。

472: 这是BPF程序的ID，用于唯一标识这个特定的BPF程序。
cgroup_skb: 表示这个BPF程序的类型是cgroup_skb，这可能是一个用于处理与cgroup和skb（Socket Buffer）相关的功能的程序。
tag 6deef7357e7b4530: 这是一个标签，通常是一个唯一的标识符，用于标记或区分不同的BPF程序。
gpl: 表示这个BPF程序使用了GPL（GNU General Public License）许可证。
loaded_at 2023-12-08T06:59:13+0800: 表示这个BPF程序加载的时间是2023年12月8日上午6:59:13，时区是+0800（东八区，即中国标准时间）。
uid 0: 表示加载这个BPF程序的用户ID是0，通常表示以超级用户的身份加载的。
xlated 64B: 表示已经翻译（translated）的BPF程序的大小是64字节。
jited 58B: 表示已经被即时编译（jited）的BPF程序的大小是58字节。
memlock 4096B: 表示这个BPF程序锁定（memlock）的内存大小是4096字节。
pids systemd(1): 表示与这个BPF程序相关联的进程（pids）是Systemd（进程ID为1）。这可能指示这个BPF程序与Systemd进程有关，并且可能是为了进行与进程管理相关的操作。


该命令用于检查并显示当前加载和运行在系统上的BPF程序的信息。BPF程序是由用户编写的自定义程序，用于内核中的各种目的，例如数据包过滤或跟踪。

此命令的输出通常包括以下详细信息：

程序ID
程序的名称
程序类型（例如，socket_filter，xdp）
附加类型（程序如何在内核中附加的位置）
附加目标（程序附加的位置，例如网络接口）
运行此命令有助于用户监视系统上处于活动状态的BPF程序，检查其状态并收集有关其配置的信息。

# 显示指定id的BPF程序的详细信息，和上面那个输出一样
sudo bpftool prog show id 472


# 通过--json使输出为json格式
sudo bpftool prog show id 472 --json
{"id":472,"type":"cgroup_skb","tag":"6deef7357e7b4530","gpl_compatible":true,"loaded_at":1701989953,"uid":0,"bytes_xlated":64,"jited":true,"bytes_jited":58,"bytes_memlock":4096,"pids":[{"pid":1,"comm":"systemd"}]}


sudo bpftool prog show id 472 --json | jq
{
  "id": 472,
  "type": "cgroup_skb",
  "tag": "6deef7357e7b4530",
  "gpl_compatible": true,
  "loaded_at": 1701989953,
  "uid": 0,
  "bytes_xlated": 64,
  "jited": true,
  "bytes_jited": 58,
  "bytes_memlock": 4096,
  "pids": [
    {
      "pid": 1,
      "comm": "systemd"
    }
  ]
}


# 显示指定的信息
sudo bpftool prog show id 472 --json | jq -c '[.id, .type, .loaded_at]' 
[472,"cgroup_skb",1701989953]
```

`jq` 是一个强大的命令行 JSON 处理工具，用于解析、筛选、转换和格式化 JSON 数据。以下是一些 `jq` 命令的基本用法：

```
bashCopy code
jq [OPTIONS] FILTER [FILE...]
```

其中：

- `OPTIONS` 是可选的命令行选项，用于配置 `jq` 的行为。
- `FILTER` 是用于筛选和转换 JSON 数据的 `jq` 过滤器。
- `FILE...` 是包含 JSON 数据的文件的名称。如果未提供文件名，则 `jq` 将从标准输入读取 JSON 数据。

以下是一些常见的 `jq` 命令和用法：

1. **基本用法**：最简单的 `jq` 命令是提供一个基本的过滤器来选择或转换 JSON 数据。例如，要从 JSON 中选择一个字段：

   ```bash
   jq '.fieldname' filename.json
   ```

2. **格式化输出**：使用 `.` 作为过滤器，将 JSON 数据格式化为易读的形式：

   ```bash
   jq '.' filename.json
   ```

   或者使用 `jq` 的 `.` 选项：

   ```bash
   jq . filename.json
   ```

3. **遍历数组**：使用 `[]` 选择数组中的元素：

   ```bash
   jq '.arrayname[1]' filename.json
   ```

4. **条件筛选**：使用 `select` 进行条件筛选：

   ```bash
   jq 'select(.age > 30)' filename.json
   ```

5. **迭代对象**：使用 `..` 迭代对象的所有键和值：

   ```bash
   jq '.. | .key?' filename.json
   ```

6. **从标准输入读取**：从标准输入读取 JSON 数据：

   ```bash
   echo '{"name": "John", "age": 25}' | jq '.name'
   ```

7. **输出为 JSON 字符串**：使用 `@json` 将结果输出为 JSON 字符串：

   ```bash
   jq -n --arg name "John" '{ "name": $name | @json }'
   ```

8. `jq -c` 是 `jq` 命令的一个选项，用于生成紧凑的输出。

9. **显示帮助信息**：显示 `jq` 命令的帮助信息：

   ```bash
   jq --help
   ```

这只是 `jq` 的一小部分功能示例，`jq` 支持复杂的过滤器、变量、函数等功能，以满足对 JSON 数据进行灵活处理和转换的需求。建议查阅 `jq` 的官方文档或运行 `jq --help` 以获取更多详细信息。

```bash

# 使用 BPFTool 获取整个程序的数据 。获取编译器生成的 BPF 字节码
sudo bpftool prog dump xlated id 472
   0: (bf) r6 = r1
   1: (69) r7 = *(u16 *)(r6 +180)
   2: (b4) w8 = 0
   3: (44) w8 |= 2
   4: (b7) r0 = 1
   5: (55) if r8 != 0x2 goto pc+1
   6: (b7) r0 = 0
   7: (95) exit

sudo bpftool prog dump jited id 472

# 如果想得到这个程序的更直观的表示(包括指令跳转) ，可以在命令中使用visual关键字，用于产生特定格式输出。我们可以使用诸如dotty之类的工具，或任何其他可以绘制图形的程序，将这个输出转换为图形表示:

# 以可视化的方式获取 ID 为 472 的 BPF 程序的已翻译信息，并将输出结果保存到名为 output.out 的文件中
prog dump 表示要展示 BPF 程序的信息。
xlated 表示要显示已翻译的信息。已翻译的信息包括 BPF 程序的指令等。
id 472 指定了要显示的 BPF 程序的 ID 为 472。
visual 表示以可视化的方式输出 BPF 程序的信息。
&> 表示将标准输出和标准错误都重定向。
output.out 表示将输出结果保存到名为 output.out 的文件中。这个文件将包含命令执行时产生的所有输出。

sudo bpftool prog dump xlated id 472 visual &> output.out

# -Tpng 指定输出图像的格式为 PNG 格式。这告诉 dot 将图形文件转换为 PNG 图像。
# output.out 是输入图形文件的名称。在上一个命令 sudo bpftool prog dump xlated id 472 visual &> output.out 中，我们已经将 BPF 程序的已翻译信息输出到 output.out 文件。
# -o visual-graph.png 指定输出图像文件的名称。在这里，visual-graph.png 是生成的 PNG 图像文件的名称。
dot -Tpng output.out -o visual-graph.png

firefox ./visual-graph.png
```

```bash

#启动统计信息。统计信息能告诉我们内核在BPF程序上花费的时长。获得另外两条信息:内核花费在运行该程序上的总时间(run_time_ns)，以及运行该程序的次数(run_cnt)
sudo sysctl -w kernel.bpf_stats_enabled=1

sudo bpftool prog show
```

```bash
# BPFTool不仅允许你检查程序的运行情况，它还允许你将新程序加载到内核中，并将它们附加到套接字和cgroup。例如，我们可以使用以下命令加载前面的程序并将其持久化到BPF文件系统:
sudo bpftool prog load bpf_prog.o /sys/fs/bpf/bpf_prog
```

### 检查BPF映射

```bash
sudo bpftool map show		# 列出所有映射以及使用标识符过滤映射。
145: hash  flags 0x0
	key 9B  value 1B  max_entries 500  memlock 8192B
390: array  name pid_iter.rodata  flags 0x480
	key 4B  value 4B  max_entries 1  memlock 4096B
	btf_id 713  frozen
	pids bpftool(273485)

sudo bpftool map show id 145
145: hash  flags 0x0
	key 9B  value 1B  max_entries 500  memlock 8192B

# 使用BPFTool创建和更新映射，以及列出映射中的所有元素。创建新映射需要提供的信息，与程序初始化映射要提供的信息相同。我们也需要指定要创建哪种类型的映射、键和值的大小及映射名。因为不在程序初始化时初始化映射，所以需要将映射持久化到 BPF 文件系统中，以便稍后使用:
sudo bpftool map create /sys/fs/bpf/counter type array key 4 value 4 entries 5 name counter

sudo bpftool map show
396: array  name counter  flags 0x0
	key 4B  value 4B  max_entries 5  memlock 4096B

# 如果你想要将新元素添加到映射中或者更新现有元素，可以使用map update
sudo bpftool map update id 396 key 1 0 0 0 value 1 0 0 0
# 如果你使用无效的键或值更新元素，BPFTool将返回错误:
sudo bpftool map update id 396 key 1 0 0 0 value 1 0 0
Error: value expected 4 bytes got 3
# 如果想要查看映射中元素的值，可以使用BPFTool的dump命令导出映射中所有元素的信息。
sudo bpftool map dump id 396
key: 00 00 00 00  value: 00 00 00 00
key: 01 00 00 00  value: 01 00 00 00
key: 02 00 00 00  value: 00 00 00 00
key: 03 00 00 00  value: 00 00 00 00
key: 04 00 00 00  value: 00 00 00 00
Found 5 elements

sudo bpftool map delete 396      # 删除map

sudo bpftool btf list      # 查看已加载的 BTF 对象。

# BPFTool提供最强大的选项之一是可以将预创建映射附加到新程序，使用这些预分配映射替换初始化的映射。这样，即使你没有编写从BPF文件系统中读取映射的程序，也可以从头开始让程序访问到保存的数据。为了实现这个目的， 当使用 BPFTool加载程序时，需要设置需要初始化的映射。当程序加载映射时，可以通过标识符的顺序来指定程序的映射，例如，0是第一个映射，1是第二个映射 ，以此类推。你也可以通过名字指定映射，这样通常更方便:
sudo bpftool prog load bpf_prog.o /sys/fs/bpf/bpf_prog_2 map name counter /sys/fs/bpf/counter
# 在这个示例中，我们将创建的新映射附加到程序上。在这种情况下，因为我们知道程序初始化的映射名为 counter，所以这里使用名字替换映射。如果更容易记住映射索引位置，你还可以使用映射索引位置关键字idx ，例如idx 0。
# 当需要实时的调试消息传递时，从命令行直接访问 BPF 映射是非常有用的。BPFTool提供了方便的方式直接访问 BPF 映射。除了查看程序和映射外，BPFTool还可以从内核获得更多信息。接下来，我们将看到通过 BPFTool 如何访问特定接口。
```

### 查看附加到特定接口的程序

有时你可能想要知道在特定接口上附加了哪些程序。 BPF 可以加载运行在cgroup 、 Perf 事件和网络数据包上的程序，反过来， BPFTool子命令 cgroup 、perf 和net 可以查看跟踪在这些接口上的附加程序 。

BPFTool的 perf子命令可以列出系统中附加到跟踪点的所有程序，例如，BPFTool的perf子命令可以列出附加到 kprobes 、 uprobes 和跟踪点上的所有程序。你可以通过运行命令 bpftool perf show 来查看 。

```bash
sudo bpftool perf show
```

BPFTool的 net 子命令可以列出附加到 XDP 和流量控制的程序。对于其他的像套接字过滤器和端口重用程序的附加程序，只能通过使用 iproute2 得到。与查看其他 BPF 对象一样，你可以通过使用命令 bpftool net show列出附加到 XDP 和 TC 的程序。

```bash
sudo bpftool net show
```

最后， BPFTool 的 cgroup 子命令可以列出附加到 cgroups 的所有程序。这个子命令与看到的其他命令有些不同。命令 bpf tool cgroup show 需要加上查看的 cgroup 路径。如果想要列出系统中所有 cgroup 上的附加程序，需要使用命令 bpftool cgroup tree

```bash
sudo bpftool cgroup tree
CgroupPath
ID       AttachType      AttachFlags     Name           
/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/snap.typora.typora-188de6a9-a964-46be-aefd-e7e49a90a229.scope
    783      cgroup_device                                                  
/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/snap.snap-store.ubuntu-software-dc87d1f3-7abc-4633-ab74-abb027791744.scope
    308      cgroup_device                                                  
/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/snap.snapd-desktop-integration.snapd-desktop-integration.service
    309      cgroup_device                                                  
/sys/fs/cgroup/system.slice/systemd-udevd.service
...
```

BPFTool 提供对 cgroups 、 Perf 和网络接口便捷查看 ，你可以验证程序是否成功地附加到内核中的任何接口上。

### 批量加载命令

当你打算分析一个或多个系统行为时，反复运行一些命令是很常见的。你可以收集 一些经常使用 的命令并放入你的工具箱中。如果不想每次都键入这些命令，可以使用 BPFTool 的批处理模式。

使用批处理模式，你可以将要执行的所有命令写在文件中，一起运行所有命令。你也可以通过以#开头的行在文件中增加注释。然而，这种执行模式不是原子的。 BPFTool 逐行执行命令，如果其中一个命令失败，它将终止执行。系统的状态会保持最新成功运行的命令后的状态。

下面是批处理模式能够处理的简短的文件示例:

```bash
# Create a new hash map
map create /sys/fs/bpf/hash_map type hash key 4 value 4 entries 5 name hash_map
# Now show all the maps in the system
map show
```

如果将这些命令保存在/tmp/batch_example.txt中，可以使用sudo bpftool batch file /tmp/batch_example.txt加载它。首次运行此命令时，会成功。但是，如果再次运行它，因为在系统中已经存在名为 hash_map 的映射，该命令将 退出，没有任何输出，批处理将在执行第一行时失败:

```bash
# 第一次运行输出：
sudo bpftool batch file example.txt                            39s 13:33:11
1: hash  flags 0x0
	key 9B  value 1B  max_entries 500  memlock 8192B
2: hash  flags 0x0
	key 9B  value 1B  max_entries 500  memlock 8192B
3: hash  flags 0x0
...
396: array  name counter  flags 0x0
	key 4B  value 4B  max_entries 5  memlock 4096B
406: hash  name hash_map  flags 0x0
	key 4B  value 4B  max_entries 5  memlock 4096B
...
# 第二次运行输出
 sudo bpftool batch file example.txt                                13:33:14
Error: can't pin the object (/sys/fs/bpf/hash_map): File exists
```

```bash
# 删除bpf映射
sudo rm /sys/fs/bpf/hash_map
sudo rm /sys/fs/bpf/counter
```

### 显示BTF信息

BPFTool 可以显示任何给定的二进制对象的 BPF 类型格式 (BTF) 信息。BTF 使用元数据 信息来注释程序结构，可以用来帮助调试程序。

例如，添加关键字 linum 到 prog dump 中，可以提供源文件和 BPF 程序中每条指令的行号。

最新版本的 BPFTool 包括新的子命令 btf ，用来帮助我们更加深入研究程序。该命令初始用于可视化结构类型。例如，bpftool btf dump id 54 ，显示程序 ID 为 54 的程序加载的所有 BTF 类型。

```bash
sudo bpftool btf list                                              14:02:07
1: name [vmlinux]  size 5532697B
2: name [wmi]  size 2890B
3: name [video]  size 4757B
4: name [hid]  size 13493B
5: name [xhci_pci_renesas]  size 512B
6: name [nvme_common]  size 1788B
7: name [typec]  size 13629B
9: name [i2c_piix4]  size 976B
...
163: name [nf_defrag_ipv6]  size 2167B
164: name [nf_conntrack]  size 26533B
165: name [nf_conntrack_netlink]  size 13359B
166: name [rfcomm]  size 23353B
167: name [nf_nat]  size 7868B
168: name [xt_MASQUERADE]  size 2361B
169: name [nft_chain_nat]  size 1715B
170: name [xt_conntrack]  size 3645B
294: name [tls]  size 14262B
821: name <anon>  size 39240B
	pids bpftool(276253)
	
sudo bpftool btf dump id 1

type_id=75717 offset=209984 size=40 (VAR 'rt_uncached_list')
type_id=46320 offset=210048 size=40 (VAR 'rt6_uncached_list')
type_id=105565 offset=212992 size=64 (VAR 'vmw_steal_time')
type_id=7940 offset=213056 size=8 (VAR 'kvm_apic_eoi')
type_id=7939 offset=213120 size=64 (VAR 'steal_time')
type_id=7938 offset=213184 size=68 (VAR 'apf_reason')

```

## BPFTrace

### 语言参考

BPFTrace 程序语能简洁。程序分为三个部分:头部 (header) 、操作块 (action block) 和尾部 (footer) 。头部是在加载程序时 BPFTrace 执行的特殊块。它通常用来打印在输出顶部的一些信息，例如前言。 同样，尾部是在程序终止前 BPFTrace 执行的特殊块。头部和尾部都是 BPFTrace 程序可选部分。一个BPFTrace 程序必须至少有一个操作块。操作块是指定我们要跟踪的探针的位置，以及基于探针内核触发事件执行的操作。以下代码段是一个基本示例，显示了这三部分:

```C
BEGIN
{
    printf("starting BPFTrace program\n")
}
kprobe:do_sys_open
{
    printf("opening file descriptor: %s\n", str(arg1))
}
END
{
    printf("exiting BPFTrace program\n")
}
```

头部用关键字 BEGIN 标记，尾部用关键字 END 标记。这些关键字是 BPF­Trace 保留关键字。操作块标识符定义要附加的 BPF 操作的探针。在上面的示例中，每次内核打开一个文件时，都会打印一条日志。

除了识别程序的各个部分外，在上面的示例中，我们还能看到一些关于BPFTrace 语言语法的更多细节。当在程序编译时， BPFTrace 提供一些帮助函数将其转换成 BPF 代码。帮助函数 printf 是 C 函数 printf 的包装器，当需要时可打印程序的详细信息。 str是 一个内置的帮助函数，将 C 指针转换为字符串表示。许多内核函数会向字符参数发送指针。这个帮助函数会将这些指针转换成字符串。

某种意义上讲， BPFTrace 可以被认为是一种动态语言，当程序在内核执行时，程序不知道探针可能收到的参数个数。 BPFTrace 提供了参数帮助函数来访问内核处理的信息。 BPFTrace 根据收到的参数个数动态生成这些帮助函数，你可以根据参数在参数列表的位置访问这些参数。在前面的示例中， arg1 是open 系统调用的第二个参数的引用，它是文件路径的引用 。

为了执行这个示例，你可以将程序保存在文件中，使用文件路径作为第一个参数来运行 BPFTrace:

```bash
sudo bpftrace example.bt
```

BPFTrace 语言是以脚本思想设计的。使用BPFTrace 编写的许多程序可以放在 一 行中。你无须将这些单行程序保存在文件中执行，可以在执行 BPFTrace 时，通过使用选项 -e 来执行。例如，在上一个计数器示例中将操作块折叠为一行变成单行代码，执行下面命令 :

```bash
sudo bpftrace -e "kprobe:do_sys_open { @opens[str(arg1)] = count() }"
```

### 过滤

运行前面的示例，你可能得到系统一直打开的文件的文件流，直到按 Ctrl+C退出程序。这是因为我们 一 直告诉 BPF 打印内核中打开的每个文件描述符。如果你只想在特定条件下执行操作块，则需要调用过滤功能。

你可以关联一个过滤器到每个操作块上，它们可以像操作块一样被编译执行。如果过滤返回 false ，操作块将不被执行 。 过滤器也可以访问 BPFTrace 语言提供的其他功能，例如探针参数和帮助函数。这些过滤器封装在操作头部后面的两个斜杠内:

```bash
kprobe:do_sys_open /str(arg1) == "/tmp/example.bt"/
{
	printf("opening file descriptor: %s\n", str(arg1))
}
```

在这个示例中，我们重构了操作块，仅在内核打开示fJú 文件时执行操作块。如果运行包含新的过滤器的程序，它会打印头部，之后停在那里。因为系统每次打开文件都会触发操作块，但因为包含新的过滤器，不符合过滤条件的文件会被跳过。如果在不同的终端中多次打开示例文件，当过滤器匹配到指定的文件路径时，你将看到内核是如何执行操作块的:

```bash
sudo bpftrace /tmp/example.bt
```

### 动态映射

BPFTrace 实现了一个动态映射关联的便捷功能。可以动态生成 BPF 映射，使用这些 BPF 映射可以执行本书中介绍的许多操作。所有映射关联都以字符@开头，后面跟着要创建的映射名。你还可以通过指定元素的值来更新映射中的元素。

如果我们使用本节开始的示例，能够聚合系统中打开指定文件的频率。为了实现该功能，我们需要计算内核在指定的文件上运行 open 系统调用的次数，之后将计数保存在映射中。为了识别这些聚合，可以将文件路径作为映射的键。下面是该示例的操作块:

```bash
kprobe:do_sys_open
{
	@opens[str(arg1)] = count()
}
```

```bash
如果再次运行程序，将得到类似下面的输出:
sudo bpftrace example.bt
Attaching 3 probes...
starting BPFTrace program
^Cexiting BPFTrace program
@opens[/var/lib/snapd/lib/gl/haswell/libd1.so.2]:1
...
```

你将看到当程序停止执行时， BPFTrace 将打印映射的内 容。 正如我们所料，它聚合了内核系统中打开文件的频率 。默认情况下，当 BPFTrace 终止时，总是会打印创建的每个映射的内容。你无须指明要打印映射， BPFTrace总是假定你需要打印映射。你也可以通过使用内置函数 clear 来清除 END 块中的映射，从而改变打印映射的行为。这是可行的，因为打印映射总是在BPFTrace 程序的页脚块执行完成后发生 。

BPFTrace 动态映射非常方便。它删除了处理映射时需要考虑的很多模板，可以专注于帮助你轻松地收集数据。

BPFTrace 是执行日常任务强大的工具。 BPFTrace 的脚本语言特性提供了足够的灵活性，可以访问系统每个方面。使用 BPFTrace ，你无须编译 BPF 程序及手工将 BPF 程序加载到内核中，这些特征可以帮助你从系统运行开始就跟踪和调试系统问题。你可以通过 Gi tH ub 上的参考指南，学习利用 BPFTracc 的所有内置功能，例如，自动的直方图和栈跟踪聚合。

## kubectl-trace

看不懂，以后再说

## eBPF Exporter

看不懂