系统延迟  中断延迟		重点



统计：系统调用（触发频率，统计）时间			调用较少的系统调用，实现同样的功能



块设备（存储效率）：server ----->send file to client，看发文件时间



延迟：server（多线程场景），运行时，个别线程可运行。	---->线程切换的延迟，线程运行的时间



网络流量：server（评判指标）->可从内核中获取->ebpf将信息拿出来->做处理



生成火焰图



ebpf应用



linux配置





load 和 attach分离，做持久化，bpf程序常驻内核

不要做分立工具，要做一个整体的工具

ls /boot/config-*

cat /boot/config-* | grep -i BPF

sudo tc qdisc add dev lo handle 0: ingress

sudo tc qdisc show dev lo

sudo tc qdisc del dev lo handle 0: ingress
sudo tc qdisc add dev lo handle 0: ingress