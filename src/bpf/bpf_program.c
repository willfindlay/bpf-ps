#include "src/bpf/bpf_program.h"

BPF_TABLE("lru_hash", u64, struct ps_process, processes, 10240);

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();

    //struct ps_process *p = processes.lookup_or_try_init(&pid_tgid, &(struct ps_process){  });
    //if (!p)
    //{
    //    bpf_trace_printk("ERROR: Unable to lookup_or_try_init ps_process\n");
    //    return 0;
    //}

    processes.delete(&pid_tgid);

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();

    /* Process already exists */
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

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{

    return 0;
}
