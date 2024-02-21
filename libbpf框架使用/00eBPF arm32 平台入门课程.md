# eBPF arm32 平台入门课程

这个系列视频讲解下使用libbpf在 arm32 平台上开发eBPF工具的过程；



为什么会有这个系列视频？

​	目前工作中使用的比较多的是arm32平台的嵌入式Linux系统，eBPF这么好用，为什么不能移植到arm32平台？

​	

因为嵌入式系统上的资源有限，使用 C语言的 libbpf-bootstrap 来开发eBPF程序；

arm32平台使用的Linux内核版本： 4.9.88

在移植到arm32平台之前，会在x86-64平台上先跑通；



课程大纲(暂定)：

1. 基础

   讲解eBPF基础

2. 示例

   移植 libbpf-bootstrap 自带的示例程序到arm32平台

3. 实践

   3.1 简单版本的 内存泄露检测 eBPF工具

   3.2 调试驱动的eBPF工具

