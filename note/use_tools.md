```bash
# 使用readelf查看BPF字节码节的信息
readelf -S 01bpf_program_kern.o                                           17:25:39
There are 24 section headers, starting at offset 0xaf8:

节头：
  [号] 名称              类型             地址              偏移量
       大小              全体大小          旗标   链接   信息   对齐
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .strtab           STRTAB           0000000000000000  00000a00
       00000000000000f4  0000000000000000           0     0     1
  [ 2] .text             PROGBITS         0000000000000000  00000040
       0000000000000000  0000000000000000  AX       0     0     4
  [ 3] kprobe/sys_bpf    PROGBITS         0000000000000000  00000040
       0000000000000070  0000000000000000  AX       0     0     8
  [ 4] .rodata.str1.16   PROGBITS         0000000000000000  000000b0
       0000000000000012  0000000000000001 AMS       0     0     16
  [ 5] license           PROGBITS         0000000000000000  000000c2
       0000000000000004  0000000000000000  WA       0     0     1

...

Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)
readelf：警告： unable to apply unsupported reloc type 3 to section .debug_info
```

```bash
llvm-readelf -S 01bpf_program_kern.o   
```





```bash
# 使用llvm-objdump反汇编BPF字节码
!w /usr/sr/linux-s/l/samples/bpf > llvm-objdump -d 01bpf_program_kern.o                                      17:24:24

01bpf_program_kern.o:   file format elf64-bpf

Disassembly of section kprobe/sys_bpf:

0000000000000000 <bpf_prog>:
       0:       b7 01 00 00 21 00 00 00 r1 = 33
       1:       6b 1a f0 ff 00 00 00 00 *(u16 *)(r10 - 16) = r1
       2:       18 01 00 00 50 46 20 57 00 00 00 00 6f 72 6c 64 r1 = 7236284523806213712 ll
       4:       7b 1a e8 ff 00 00 00 00 *(u64 *)(r10 - 24) = r1
       5:       18 01 00 00 48 65 6c 6c 00 00 00 00 6f 2c 20 42 r1 = 4764857262830019912 ll
       7:       7b 1a e0 ff 00 00 00 00 *(u64 *)(r10 - 32) = r1
       8:       bf a1 00 00 00 00 00 00 r1 = r10
       9:       07 01 00 00 e0 ff ff ff r1 += -32
      10:       b7 02 00 00 12 00 00 00 r2 = 18
      11:       85 00 00 00 06 00 00 00 call 6
      12:       b7 00 00 00 00 00 00 00 r0 = 0
      13:       95 00 00 00 00 00 00 00 exit
```

