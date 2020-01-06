#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

#include <linux/sched.h>
#include <linux/unistd.h>

struct ps_process
{
    u32 pid; /* kernel tgid */
    u32 tid; /* kernel pid */
    char comm[TASK_COMM_LEN];
};

#endif /* BPF_PROGRAM_H */
