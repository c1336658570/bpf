// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Facebook */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "profile.skel.h"
#include "profile.h"
#include "blazesym.h"

// 这个函数来自于 libbpf，但它不是一个公共API，仅供演示目的使用。我们可以在这里使用它，因为在构建过程中我们是静态链接到从子模块构建的 libbpf。
// 一个字符串，表示 CPU 掩码文件的路径。该文件包含有关系统上哪些 CPU 处于在线状态的信息。
// 一个指向指针的指针，用于存储解析得到的 CPU 掩码信息。每个布尔值表示对应的 CPU 是否在线。
// 一个指向整数的指针，用于存储解析得到的 CPU 掩码的大小，即在线 CPU 的数量。
// 函数的返回值是一个整数，表示函数执行的结果。如果函数成功解析 CPU 掩码文件并填充了相关信息，则返回 0；否则，返回一个非零的错误码，表示解析过程中发生了错误。
extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

// 定义 perf_event_open 系统调用，因为该系统调用的号码在头文件中没有定义
// 指向 struct perf_event_attr 结构体的指针，该结构体包含了所要设置的性能事件的属性。
// 指定关联的进程的PID（Process ID）。如果设置为 -1，则表示将性能事件关联到所有进程。
// 指定关联的CPU。如果设置为 -1，则表示将性能事件关联到所有CPU。
// 指定事件组的文件描述符。如果不是事件组中的第一个事件，可以通过该参数指定事件组的文件描述符。
// 一组标志位，用于控制性能事件的行为。可能包含 PERF_FLAG_FD_CLOEXEC 等标志。
// 返回值是一个文件描述符，用于后续对性能事件的读取或控制，或者在发生错误时返回负数。
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
			    unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

// 全局变量，用于符号化函数调用栈
static struct blaze_symbolizer *symbolizer;

// 打印单个栈帧的信息
static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info)
{
    // 如果有输入地址，则有一个新的符号
    if (input_addr != 0) {
      printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
			if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
				printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
				printf(" %s:%u\n", code_info->file, code_info->line);
      } else {
				printf("\n");
      }
    } else {
      printf("%16s  %s", "", name);
			if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
				printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
				printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
      } else {
				printf("[inlined]\n");
      }
    }
}

// 显示栈跟踪信息
static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
  const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_result *result;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.pid = pid,
		};
		result = blaze_symbolize_process(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = {};
		result = blaze_symbolize_kernel(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}


	for (i = 0; i < stack_sz; i++) {
		if (!result || result->cnt <= i || result->syms[i].name == NULL) {
			printf(" %2d [<%016llx>]\n", i, stack[i]);
			continue;
		}

    sym = &result->syms[i];
    print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

    for (j = 0; j < sym->inlined_cnt; j++) {
      inlined = &sym->inlined[j];
      print_frame(sym->name, 0, 0, 0, &inlined->code_info);
    }
	}

	blaze_result_free(result);
}

// 处理从环形缓冲区接收到的事件
static int event_handler(void *_ctx, void *data, size_t size)
{
	struct stacktrace_event *event = data;

	if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
		return 1;

	printf("COMM: %s (pid=%d) @ CPU %d\n", event->comm, event->pid, event->cpu_id);

	if (event->kstack_sz > 0) {
		printf("Kernel:\n");
		show_stack_trace(event->kstack, event->kstack_sz / sizeof(__u64), 0);
	} else {
		printf("No Kernel Stack\n");
	}

	if (event->ustack_sz > 0) {
		printf("Userspace:\n");
		show_stack_trace(event->ustack, event->ustack_sz / sizeof(__u64), event->pid);
	} else {
		printf("No Userspace Stack\n");
	}

	printf("\n");
	return 0;
}

// 显示程序的使用方法
static void show_help(const char *progname)
{
	printf("Usage: %s [-f <frequency>] [-h]\n", progname);
}

int main(int argc, char *const argv[])
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	int freq = 1, pid = -1, cpu;
	struct profile_bpf *skel = NULL;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;
	struct ring_buffer *ring_buf = NULL;
	int num_cpus, num_online_cpus;
	int *pefds = NULL, pefd;
	int argp, i, err = 0;
	bool *online_mask = NULL;

	while ((argp = getopt(argc, argv, "hf:")) != -1) {
		switch (argp) {
		case 'f':
			freq = atoi(optarg);
			if (freq < 1)
				freq = 1;
			break;

		case 'h':
		default:
			show_help(argv[0]);
			return 1;
		}
	}

	// 从文件中解析在线 CPU 的掩码
	err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
	if (err) {
		fprintf(stderr, "Fail to get online CPU numbers: %d\n", err);
		goto cleanup;
	}

	// 获取系统中可用的 CPU 数量
	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		fprintf(stderr, "Fail to get the number of processors\n");
		err = -1;
		goto cleanup;
	}

	// 打开、加载并验证 BPF
	skel = profile_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Fail to open and load BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	// 创建符号化器	
	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto cleanup;
	}

	// 准备用于接收事件的环形缓冲区
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);
	if (!ring_buf) {
		err = -1;
		goto cleanup;
	}

	// 为每个 CPU 设置性能监视器
	pefds = malloc(num_cpus * sizeof(int));
	for (i = 0; i < num_cpus; i++) {
		pefds[i] = -1;
	}

	links = calloc(num_cpus, sizeof(struct bpf_link *));

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.sample_freq = freq;
	attr.freq = 1;

	for (cpu = 0; cpu < num_cpus; cpu++) {
		// 跳过离线/不存在的 CPU
		if (cpu >= num_online_cpus || !online_mask[cpu])
			continue;

		// 设置在 CPU/Core 上的性能监视
		pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
			err = -1;
			goto cleanup;
		}
		pefds[cpu] = pefd;

		// 将 BPF 程序附加到 CPU 上
		links[cpu] = bpf_program__attach_perf_event(skel->progs.profile, pefd);
		if (!links[cpu]) {
			err = -1;
			goto cleanup;
		}
	}

	// 等待并接收栈跟踪
	while (ring_buffer__poll(ring_buf, -1) >= 0) {
	}

cleanup:
	// 销毁 BPF 链接
	if (links) {
		for (cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(links[cpu]);
		free(links);
	}
	// 关闭性能监视器文件描述符
	if (pefds) {
		for (i = 0; i < num_cpus; i++) {
			if (pefds[i] >= 0)
				close(pefds[i]);
		}
		free(pefds);
	}
	// 释放环形缓冲区资源
	ring_buffer__free(ring_buf);
	// 销毁 BPF
	profile_bpf__destroy(skel);
	// 释放符号化器资源
	blaze_symbolizer_free(symbolizer);
	// 释放在线 CPU 掩码资源
	free(online_mask);
	return -err;
}
