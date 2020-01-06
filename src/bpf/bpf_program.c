#include "src/bpf/bpf_program.h"

/* LRU_HASH just in case we are dealing with more than 10240 processes (i.e. fork bomb or something) */
BPF_TABLE("lru_hash", u64, struct ps_process, processes, 10240);

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();

    processes.delete(&pid_tgid);

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u64 syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();

#ifdef SINCE_START
    /* User only cares about programs that have forked or execve'd since we started */
    if (syscall == __NR_execve || processes.lookup(&pid_tgid))
    {
        /* PASS */
    }
    else
    {
        return 0;
    }
#endif

    struct ps_process *p = processes.lookup_or_try_init(&pid_tgid, &(struct ps_process){  });
    if (!p)
    {
        bpf_trace_printk("ERROR: Unable to lookup_or_try_init ps_process\n");
        return 0;
    }

    p->pid = (u32)(pid_tgid >> 32);
    p->tid = (u32)pid_tgid;
    bpf_get_current_comm(p->comm, sizeof(p->comm));

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u64 syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();

#ifdef SINCE_START
    /* User only cares about programs that have forked or execve'd since we started */
    if (syscall == __NR_fork || syscall == __NR_vfork || syscall == __NR_clone)
    {
        /* PASS */
    }
    else
    {
        return 0;
    }
#endif

    /* sys_enter tracepoint already captured details if we're in a process we already know about */
    if (processes.lookup(&pid_tgid))
    {
        return 0;
    }

    struct ps_process *p = processes.lookup_or_try_init(&pid_tgid, &(struct ps_process){  });
    if (!p)
    {
        bpf_trace_printk("ERROR: Unable to lookup_or_try_init ps_process\n");
        return 0;
    }

    p->pid = (u32)(pid_tgid >> 32);
    p->tid = (u32)pid_tgid;
    bpf_get_current_comm(p->comm, sizeof(p->comm));

    return 0;
}
