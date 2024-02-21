# 解决特定内核版本加载ebpf失败的问题

[toc]

## 目的

- 分析特定内核版本加载ebpf失败的原因
- 使用 vscode 和 gdb 调试的方法



## 加载ebpf失败的现象

```
/home # ./kprobe 
libbpf: loading object 'kprobe_bpf' from buffer
libbpf: elf: section(2) .symtab, size 168, link 1, flags 0, type=2
libbpf: elf: section(3) kprobe/do_unlinkat, size 264, link 0, flags 6, type=1
libbpf: sec 'kprobe/do_unlinkat': found program 'do_unlinkat' at insn offset 0 (0 bytes), code size 33 insns (264 bytes)
libbpf: elf: section(4) kretprobe/do_unlinkat, size 200, link 0, flags 6, type=1
libbpf: sec 'kretprobe/do_unlinkat': found program 'do_unlinkat_exit' at insn offset 0 (0 bytes), code size 25 insns (200 bytes)
libbpf: elf: section(5) license, size 13, link 0, flags 3, type=1
libbpf: license of kprobe_bpf is Dual BSD/GPL
libbpf: elf: section(6) .rodata.str1.1, size 72, link 0, flags 32, type=1
libbpf: elf: section(7) .BTF, size 1351, link 0, flags 0, type=1
libbpf: elf: section(8) .BTF.ext, size 344, link 0, flags 0, type=1
libbpf: looking for externs among 7 symbols...
libbpf: collected 0 externs total
libbpf: map '.rodata.str1.1' (global data): at sec_idx 6, offset 0, flags 80.
libbpf: map 0 is ".rodata.str1.1"
libbpf: map '.rodata.str1.1': skipped auto-creating...
libbpf: prog 'do_unlinkat': BPF program load failed: Invalid argument
libbpf: prog 'do_unlinkat': failed to load: -22
libbpf: failed to load object 'kprobe_bpf'
libbpf: failed to load BPF skeleton 'kprobe_bpf': -22
Failed to open BPF skeleton
/home # 
```



## 调试环境

- 内核版本：**linux-4.19.304** （https://www.kernel.org/ 可以下载）
- 平台 arm64
- 在 ubuntu18.04 上使用 qemu虚拟机启动 **linux-4.19.304** 版本的内核 (用x86-64模拟arm64)

下面章节：qemu虚拟机 统称为 arm64 开发板



## 配置 vscode + gdb 的调试环境

远程gdb调试的命令行模式使用方法:

```shell
# arm64 板端
# gdbserver 是 gdb源码 交叉编译出来的可执行文件
# 192.168.3.6 是 arm64 开发板的IP地址
# 12345 是 arm64 开发板的端口, 在端口不冲突的情况下, 可以随意定
# kprobe 是 arm64 开发板的可执行文件
./gdbserver 192.168.3.6:12345 ./kprobe

# PC端
# aarch64-none-linux-gnu-gdb 是交叉编译工具链中的gdb工具
# kprobe 是交叉编译好并存放在PC端的可执行文件
aarch64-none-linux-gnu-gdb ./kprobe
# 进入 gdb 交互环境
	# 192.168.3.6:12345 是 arm64开发板的gdbserver的IP地址和端口号
	target remote 192.168.3.6:12345
```



使用vscode+gdb远程调试：

在 `libbpf-bootstrap/examples/c` 目录下创建 vscode project

- 点击vscode左侧边栏菜单的 `Run and Debug` 按钮

- 点击 `create a launch.json file`

- 在弹出来的 `Select debugger` 下拉框中选择 `C++(GDB/LLDB)`

- 点击 `launch.json` 文件中的右下角 `Add Configuration` 按钮，

  并在弹出来的下拉框中选择`C/C++: (gdb)Launch`

- 修改`launch.json`文件：

  修改 `program`选项，指定存放在PC端的可执行文件路径；

  增加 `miDebuggerPath` 选项，指定 PC 端的 gdb 调试工具的绝对路径

  增加 `miDebuggerServerAddress` 选项，指定 arm64 开发板的 gdbserver 的 ip地址 和 端口号

launch.json

```json
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": "(gdb) Launch",
            "type": "cppdbg",
            "request": "launch",
            
            "program": "${workspaceFolder}/kprobe", // 可执行文件路径
            
            "args": [],
            "stopAtEntry": false,
            "cwd": "${fileDirname}",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                },
                {
                    "description": "Set Disassembly Flavor to Intel",
                    "text": "-gdb-set disassembly-flavor intel",
                    "ignoreFailures": true
                }
            ],

            // gdb 配置
            "miDebuggerPath": "/home/zhanglong/Desktop/toolchain/arm64/aarch64-none-linux-gnu-gdb",
            "miDebuggerServerAddress": "192.168.3.6:12345"

        }

    ]
}
```

- 在 arm64 开发板开启 gdbserver：

  ```shell
  ./gdbserver 192.168.3.6:12345 ./kprobe
  ```

- 在 vscode 中按 `F5` 进入调试模式



## 调试ebpf加载错误

- 使用gdb跟踪到 `libbpf-bootstrap/libbpf/src/bpf.c` 文件中的 `sys_bpf_prog_load` 接口调用 

  `fd = sys_bpf_fd(BPF_PROG_LOAD, attr, size);` 出错了

- 在内核源码：`linux-4.19.304/kernel/bpf/syscall.c` 文件中的

  `static int bpf_prog_load(union bpf_attr *attr)` 接口中，`return -EINVAL;` 上下都加上打印信息，

  看具体是内核的哪里出问题了

- 重新编译内核并用 qemu 启动，不使用gdb，直接跑 kprobe 可执行文件，根据打印信息确定出问题的地方是：

  ```c
  	if (type == BPF_PROG_TYPE_KPROBE &&
  	    attr->kern_version != LINUX_VERSION_CODE)
  		return -EINVAL;
  ```

  查看内核文件：`linux-4.19.304/include/generated/uapi/linux/version.h` 中的 `LINUX_VERSION_CODE` 的宏定义：

  ```c
  #define LINUX_VERSION_CODE 267263
  #define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
  ```

  通过 `KERNEL_VERSION` 宏反向计算出 `267263` 对应的内核版本是：`4.19.255`

  内核版本的表示方法：`major`.`minor`.`patch`，即主版本=4，子版本=19，patch=255

  不应该是 `4.19.304` 吗？

  在 `linux-4.19.304/`目录下搜索 `LINUX_VERSION_CODE` 可知 `linux-4.19.304/include/generated/uapi/linux/version.h` 文件是 `linux-4.19.304/Makefile` 自动生成：

  ```makefile
  define filechk_version.h
          (echo \#define LINUX_VERSION_CODE $(shell                         \
          expr $(VERSION) \* 65536 + 0$(PATCHLEVEL) \* 256 + 255); \
          echo '#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))';)
  endef
  ```

  可以看到内核版本中的patch直接写死为 255，因为内核版本的 major, minor, patch 都是用8bit无符号来表示，最大范围[0, 255]，304已经超过255了，就只能给个最大值 255

- 在 `libbpf-bootstrap/` 目录下搜索 `kern_version`

  在 `libbpf-bootstrap/libbpf/src/libbpf.c` 文件的 `bpf_object__new` 接口中的：

  ```c
  obj->kern_version = get_kernel_version();
  ```

  打上断点

  通过 gdb 调试可以获取到 libbpf 获取到的内核版本是：`267312` 和 内核源码中定义的 `267263` 不一致，所以 ebpf 加载失败；



## 结论和解决办法

内核版本表示方法：`major`.`minor`.`patch` ，`major`,`minor`,`patch` 都是用8bit无符号表示，最大范围[0, 255]

**结论：**

通过上面的分析可知，`4.19.304`版本的内核源码中定义的版本是：`4.19.255`，304 被截断为 255

`libbpf-bootstrap` 中获取到的内核版本是: `4.19.304`

所以，只要内核版本中的 `patch` > 255 的内核都会导致 `kprobe` 相关的 `ebpf` 加载错误；



**解决办法：**

修改 `libbpf-bootstrap` 源码中的 `libbpf-bootstrap/libbpf/src/libbpf_probes.c` 文件，

在 `__u32 get_kernel_version(void)` 接口返回前，加入如下代码：

```c
patch = patch > 255 ? 255 : patch;
```

