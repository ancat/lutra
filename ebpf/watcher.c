#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#include <linux/ptrace.h>
#include <linux/bpf_perf_event.h>
#pragma clang diagnostic pop
#include <linux/version.h>
#include <linux/bpf.h>
#include <strings.h>
#include "bpf_helpers.h"

#include <linux/sched.h>
#include <linux/fdtable.h>

struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct event_t {
    u64 pid;
    u64 ppid;
    char comm[16];
    char filename[256];
    u32 uid;
    u64 argv;
    u64 envp;
    umode_t mode;
    unsigned long inode;
} __attribute__((packed));

# define printk(fmt, ...)                        \
        ({                            \
            char ____fmt[] = fmt;                \
            bpf_trace_printk(____fmt, sizeof(____fmt),    \
                     ##__VA_ARGS__);            \
        })

__attribute__((section("kretprobe/sys_execve")))
int kretprobe__sys_execve(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct event_t event = {0};
    event.pid = (u32) bpf_get_current_pid_tgid();
    event.uid = (u32) bpf_get_current_uid_gid();

	struct mm_struct *mm;
    struct file *exe;
    struct inode *inode;
    unsigned long exe_inode = 1;
    bpf_probe_read(&mm, sizeof(mm), (void*) &task->active_mm);
    bpf_probe_read(&exe, sizeof(exe), (void*) &mm->exe_file);
    bpf_probe_read(&inode, sizeof(inode), (void*) &exe->f_inode);
    bpf_probe_read(&exe_inode, sizeof(exe_inode), (void*) &inode->i_ino);
    event.inode = exe_inode;

    u32 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &events, cpu, &event, sizeof(event));
    printk("execvexit pid=%d inode=%d\n", event.pid, exe_inode);

    return 0;
}

__attribute__((section("kprobe/sys_execve")))
int kprobe__sys_execve(struct pt_regs *ctx) {
    char* filename = (char *)ctx->di;
    u64 argv = (u64)ctx->si;
    u64 envp = (u64)ctx->dx;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 cpu = bpf_get_smp_processor_id();
    umode_t mode = 0;

    struct event_t event = {0};
    event.pid = (u32) bpf_get_current_pid_tgid();
    event.argv = argv;
    event.envp = envp;
    event.uid = (u32) bpf_get_current_uid_gid();
    bzero(event.filename, sizeof(event.filename));
    bpf_probe_read_str(event.filename, sizeof(event.filename)-1, filename);

    struct files_struct* f = {0};
    struct fdtable* fdt;
    struct file** fdd;
    struct file* file;
    struct inode* f_inode;

    bpf_probe_read(&f, sizeof(f), (void*)&task->files);
    bpf_probe_read(&fdt, sizeof(fdt), (void*)&f->fdt);
    bpf_probe_read(&fdd, sizeof(fdd), (void*)&fdt->fd);
    bpf_probe_read(&file, sizeof(file), (void*)&fdd[0]);
    bpf_probe_read(&f_inode, sizeof(f_inode), (void*)&file->f_inode);
    bpf_probe_read(&mode, sizeof(mode), (void*)&f_inode->i_mode);
    event.mode = mode;

    bpf_perf_event_output(ctx, &events, cpu, &event, sizeof(event));

    return 0;
}

char _license[] SEC("license") = "GPL";
unsigned int _version SEC("version") = 0xFFFFFFFE;
