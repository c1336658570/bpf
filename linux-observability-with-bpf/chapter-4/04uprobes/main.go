package main

import "fmt"

// uprobes

/*
一般来说，uprobes是内核在程序特定指令执行之前插入该指令集的钩子。当
附加uprobes到程序的不同版本时要注意，因为在不同版本之间函数签名可
能会有所变化。如果你想在程序不同版本上运行BPF程序，唯一的方法是确
保程序不同版本中函数签名是相同的。在Linux中你可以使用nm命令列出
ELF对象文件中包括的所有符号，并检查跟踪指令在程序中是否仍然存在。下面是示例程序:
使用go build -o hello-bpf main.go编译这个Go程序。

使用命令nm获取二进制文件中包括所有的指令点信息。
如果使用main关键字对符号进行过滤
nm hello-bpf | grep main

有了符号列表后，你可以在指令执行时进行跟踪，即使多个进程同时执行一个二进制程序，我们也能够使用该方桂对程序指令进行跟踪。

为了跟踪Go程序中的main函数什么时候执行，我们可以编写BPF程序井将其附加到uprobe上，在任何进程调用该指令之前uprobe将产生中断
*/

func main() {
	fmt.Println("Hello, BPF")
}
