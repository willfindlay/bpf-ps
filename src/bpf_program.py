import os, sys
import time
import curses

from bcc import BPF

import defs

class BPFProgram:
    def __init__(self, args):
        self.args = args
        self.bpf = None

    def load_bpf_program(self):
        assert self.bpf is None

        with open(os.path.join(defs.project_path, 'src/bpf/bpf_program.c'), 'r') as f:
            text = f.read()

        flags = []
        if self.args.since_start:
            flags.append('-DSINCE_START')
        # Include project path for finding headers
        flags.append('-I{defs.project_path}')

        self.bpf = BPF(text=text, cflags=flags)

    def print_header(self):
        header = f"{'COMM':16} {'PID':>8} {'TID':>8}"
        print(header)

    def print_processes(self):
        processes = self.bpf["processes"].iteritems()
        processes = sorted(processes, key=lambda item: item[1].pid)
        for k,v in processes:
            info = f"{v.comm.decode('utf-8'):16} {v.pid:8} {v.tid:8}"
            print(info)

    def event_loop(self, screen):
        k = 0
        cursor_x = 0
        cursor_y = 0

        screen.clear()
        screen.refresh()
        #curses.start_color()

        while ord(k) != 'q':
            time.sleep(defs.sleep)

            screen.clear()
            if self.args.printk:
                self.bpf.trace_print()
            #self.bpf.perf_buffer_poll(30)
            self.print_header()
            self.print_processes()

            screen.refresh()

    def main(self):
        self.load_bpf_program()
        curses.wrapper(self.event_loop)

