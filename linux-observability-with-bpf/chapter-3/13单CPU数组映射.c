/*
 * 这种类型的映射也是BPF_MAP_TYPE_ARRAY的改进版本。映射类型定义为BPF_MAP_TYPE_PERCPU_ARRAY。
 * 像上一个映射一样，我们可以给该类型映射分配CPU，那么每个CPU会看到自己独立的映射版本，这样对于高性能查找和聚合更有效。
 *
 * 1. 高性能查找和更新： 类似于
 * BPF_MAP_TYPE_PERCPU_HASH，BPF_MAP_TYPE_PERCPU_ARRAY
 * 允许并行地在多个CPU核心上进行操作，而不需要锁定整个数据结构。
 * 这在高并发和高性能的场景下特别有用，例如网络数据包处理或其他需要快速访问和更新数组元素的任务。
 *
 * 2.指标收集和聚合：
 * 如果你的eBPF程序需要收集每个CPU核心的统计信息或指标，BPF_MAP_TYPE_PERCPU_ARRAY
 * 是一个有效的选择。每个核心可以独立地累积统计信息，避免了共享数据结构的锁竞争。
 *
 * 3.避免伪共享： 与 BPF_MAP_TYPE_ARRAY 相比，BPF_MAP_TYPE_PERCPU_ARRAY
 * 可以减少伪共享问题。每个核心对自己的独立数组进行操作，降低了不同核心之间争夺同一缓存行的可能性。
 */