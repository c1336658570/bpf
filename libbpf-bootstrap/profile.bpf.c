// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "profile.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义 BPF 映射，用于存储环形缓冲区事件
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);			// 映射类型为环形缓冲区
	__uint(max_entries, 256 * 1024);				// 256K
} events SEC(".maps");

// 定义 BPF 程序，用于处理性能事件
SEC("perf_event")
int profile(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;			// 获取当前进程的 PID
	int cpu_id = bpf_get_smp_processor_id();				// 获取当前 CPU ID
	struct stacktrace_event *event;									// 定义事件结构体指针
	int cp;

	// 尝试从环形缓冲区中预留一个事件条目
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 1;			// 如果预留失败，返回 1 表示错误

	// 填充事件结构体的各个字段
	event->pid = pid;								// 记录进程 PID
	event->cpu_id = cpu_id;					// 记录 CPU ID

	// 获取当前进程的名称（命令行）
	if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
		event->comm[0] = 0;		// 如果获取失败，将 comm 字段置为空字符串

	// 获取内核栈信息，包括栈大小和栈内容
	event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	// 获取用户栈信息，包括栈大小和栈内容
	event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

	// 提交事件到环形缓冲区
	bpf_ringbuf_submit(event, 0);

	return 0;
}
