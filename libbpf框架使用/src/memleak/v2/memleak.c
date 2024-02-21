// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "memleak.skel.h"
#include "memleak.h"
#include <assert.h>
#include "blazesym.h"

static const int perf_max_stack_depth = 127;    //stack id 对应的堆栈的深度
static const int stack_map_max_entries = 10240; //最大允许存储多少个stack_id（每个stack id都对应一个完整的堆栈）
static __u64 * g_stacks = NULL;
static size_t g_stacks_size = 0;
static const char * p_print_file = "/tmp/memleak_print";
static const char * p_quit_file = "/tmp/memleak_quit";

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static struct blaze_symbolizer *symbolizer;

static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
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
		if (!result || result->size <= i || !result->entries[i].size) {
			printf(" %2d [<%016llx>]\n", i, stack[i]);
			continue;
		}

		if (result->entries[i].size == 1) {
			sym = &result->entries[i].syms[0];

			if (sym->dir && sym->dir[0] != '\0' && sym->file && sym->file[0] != '\0') {
				printf(" %2d [<%016llx>] %s+0x%lx %s/%s:%u\n", i, stack[i],
				       sym->name, sym->offset, sym->dir, sym->file, sym->line);
			} else if (sym->file && sym->file[0] != '\0') {
				printf(" %2d [<%016llx>] %s+0x%lx %s:%u\n", i, stack[i],
				       sym->name, sym->offset, sym->file, sym->line);
			} else {
				printf(" %2d [<%016llx>] %s+0x%lx\n", i, stack[i], sym->name, sym->offset);
			}
			continue;
		}

		printf(" %2d [<%016llx>]\n", i, stack[i]);
		for (j = 0; j < result->entries[i].size; j++) {
			sym = &result->entries[i].syms[j];
			if (sym->dir && sym->dir[0] != '\0' && sym->file && sym->file[0] != '\0') {
				printf("        %s+0x%lx %s/%s:%u\n", sym->name,
				       sym->offset, sym->dir, sym->file, sym->line);
			} else if (sym->file && sym->file[0] != '\0') {
				printf("        %s+0x%lx %s:%u\n", sym->name,
				       sym->offset, sym->file, sym->line);
			} else {
				printf("        %s+0x%lx\n", sym->name, sym->offset);
			}
		}
	}

	blaze_result_free(result);
}

int print_outstanding_combined_allocs(struct memleak_bpf * skel, pid_t pid)
{
	const size_t combined_allocs_key_size = bpf_map__key_size(skel->maps.combined_allocs);
	const size_t stack_traces_key_size = bpf_map__key_size(skel->maps.stack_traces);

	for (__u64 prev_key = 0, curr_key = 0; ; prev_key = curr_key) {

		if (bpf_map__get_next_key(skel->maps.combined_allocs, 
			&prev_key, &curr_key, combined_allocs_key_size)) {
			if (errno == ENOENT) {
				break; //no more keys, done!
			}
			perror("map get next key failed!");

			return -errno;
		}

		// stack_id = curr_key
		union combined_alloc_info cinfo;
		memset(&cinfo, 0, sizeof(cinfo));

		if (bpf_map__lookup_elem(skel->maps.combined_allocs, 
			&curr_key, combined_allocs_key_size, &cinfo, sizeof(cinfo), 0)) {
			if (errno == ENOENT) {
				continue;
			}

			perror("map lookup failed!");
			return -errno;
		}

		if (bpf_map__lookup_elem(skel->maps.stack_traces, 
			&curr_key, stack_traces_key_size, g_stacks, g_stacks_size, 0)) {
			perror("failed to lookup stack traces!");
			return -errno;
		}

		printf("stack_id=0x%llx with outstanding allocations: total_size=%llu nr_allocs=%llu\n",
			curr_key, (__u64)cinfo.total_size, (__u64)cinfo.number_of_allocs);
		
		int stack_sz = 0;
		for (int i = 0; i < perf_max_stack_depth; i++) {
			if (0 == g_stacks[i]) {
				break;
			}

			// printf("[%3d] 0x%llx\n", i, g_stacks[i]);
			stack_sz++;
		}

		show_stack_trace(g_stacks, stack_sz, pid);

	}

	return 0;
}

int main(int argc, char **argv)
{
	struct memleak_bpf *skel;
	int err, i;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	int attach_pid;
	char binary_path[128] = {0};

	if (2 != argc)
	{
		printf("usage:%s attach_pid\n", argv[0]);
		return -1;
	}

	attach_pid = atoi(argv[1]);
	strcpy(binary_path, "/lib/x86_64-linux-gnu/libc.so.6");

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = memleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	bpf_map__set_value_size(skel->maps.stack_traces, perf_max_stack_depth * sizeof(__u64));
	bpf_map__set_max_entries(skel->maps.stack_traces, stack_map_max_entries);

	err = memleak_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	uprobe_opts.func_name = "malloc";
	uprobe_opts.retprobe = false;
	skel->links.malloc_enter = bpf_program__attach_uprobe_opts(skel->progs.malloc_enter,
								 attach_pid, binary_path,
								 0,
								 &uprobe_opts);
	if (!skel->links.malloc_enter) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	uprobe_opts.func_name = "malloc";
	uprobe_opts.retprobe = true;
	skel->links.malloc_exit = bpf_program__attach_uprobe_opts(
		skel->progs.malloc_exit, attach_pid, binary_path,
		0, &uprobe_opts);
	if (!skel->links.malloc_exit) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	uprobe_opts.func_name = "free";
	uprobe_opts.retprobe = false;
	skel->links.free_enter = bpf_program__attach_uprobe_opts(skel->progs.free_enter,
								 attach_pid, binary_path,
								 0,
								 &uprobe_opts);
	if (!skel->links.free_enter) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = memleak_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	g_stacks_size = perf_max_stack_depth * sizeof(*g_stacks);
	g_stacks = (__u64 *)malloc(g_stacks_size);
	memset(g_stacks, 0, g_stacks_size);

	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto cleanup;
	}

	// printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	//        "to see output of the BPF programs.\n");

	for (i = 0;; i++) {
		if (0 == access(p_quit_file, F_OK)) {
			remove(p_quit_file);
			break;
		}
		else if (0 == access(p_print_file, F_OK)) {
			remove(p_print_file);
			print_outstanding_combined_allocs(skel, attach_pid);
		}

		usleep(100000);
	}

cleanup:
	memleak_bpf__destroy(skel);
	blaze_symbolizer_free(symbolizer);
	free(g_stacks);
	return -err;
}
