#! /usr/bin/env python3

import os, sys
import argparse

from bpf_program import BPFProgram

DESCRIPTION="""
A reimplentation of ps in eBPF.
By: William Findlay
"""

EPILOG="""
The motivation of this project is to understand tracking process lifespan in eBPF.
"""

def is_root():
    return os.geteuid() == 0

def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(prog="bpf-ps", description=DESCRIPTION,
            epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)

    # Debugging info
    parser.add_argument("--printk", action="store_true",
            help="Print output from bpf_trace_printk (for debugging purposes).")

    parser.add_argument("--since-start", dest='since_start', action="store_true",
            help="Only care about processes/threads that either execve or spawn after running bpf-ps.")

    args = parser.parse_args(args)

    # Check UID
    if not is_root():
        parser.error("You must run this script with root privileges.")

    return args

if __name__ == '__main__':
    args = parse_args()
    prog = BPFProgram(args)
    prog.main()
