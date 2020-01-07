import os, sys
import time
import atexit
import signal

from bcc import BPF

import defs

class BPFProgram:
    """
    Class to help manage BPF program.
    Includes various helper functions to be invoked by control class.
    """
    def __init__(self, args):
        self.args = args
        self.bpf = None

        self.load_bpf_program()
        self.register_exit_hooks()

    def load_bpf_program(self):
        """
        Load BPF program and set self.bpf to that program.
        """
        assert self.bpf is None

        with open(os.path.join(defs.project_path, 'src/bpf/bpf_program.c'), 'r') as f:
            text = f.read()

        flags = []
        if self.args.since_start:
            flags.append('-DSINCE_START')
        # Include project path for finding headers
        flags.append('-I{defs.project_path}')

        self.bpf = BPF(text=text, cflags=flags)

    def get_header(self):
        """
        Return the header for process output.
        """
        return f"{'COMM':16} {'PID':>8} {'TID':>8}"

    def get_process_info(self, sort_key='pid'):
        """
        Return a list of formatted process info for output.
        """
        processes = self.bpf["processes"].itervalues()
        if sort_key and sort_key != 'comm':
            processes = sorted(processes, key=lambda item: item.__getattribute__(sort_key))
        elif sort_key == 'comm':
            processes = sorted(processes, key=lambda item: item.comm.decode('utf-8'))
        process_info = []
        for p in processes:
            process_info.append(f"{p.comm.decode('utf-8'):16} {p.pid:8} {p.tid:8}")
        return process_info

    def cleanup(self):
        """
        Any cleanup will go here later.
        """
        pass

    def register_exit_hooks(self):
        """
        Handle signals gracefully and register cleanup hook.
        """
        signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
        signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))
        atexit.register(self.cleanup)

    def on_tick(self):
        """
        Run this on every tick in control class.
        """
        if self.args.printk:
            self.bpf.trace_print()
        self.bpf.perf_buffer_poll(30)
