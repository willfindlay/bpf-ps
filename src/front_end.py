import os, sys
import curses
import time
import traceback
import threading

from bpf_program import BPFProgram

import defs

class CursesFrontEnd:
    def __init__(self, args):
        self.args = args
        self.bpf_program = BPFProgram(args)

        self.key = 0
        self.y_scroll = 0
        self.top = 0
        self.bottom = 0

    def cleanup(self):
        self.screen.keypad(0)
        curses.echo()
        curses.nocbreak()
        curses.curs_set(1)
        curses.endwin()

    def get_key_forever(self):
        while True:
            self.key = self.screen.getch()
            self.handle_input()

    def check_scroll_bounds(self):
        if self.y_scroll < self.top:
            self.y_scroll = self.top
        if self.y_scroll > self.bottom:
            self.y_scoll = self.bottom

    def maybe_scroll(self):
        if self.key == curses.KEY_DOWN:
            self.y_scroll += 1
        if self.key == curses.KEY_UP:
            self.y_scroll -= 1

    def handle_input(self):
        self.maybe_scroll()

    def main(self):
        try:
            # Curses stuff
            self.screen = curses.initscr()
            self.screen.keypad(1)
            curses.noecho()
            curses.cbreak()

            self.input_thread = threading.Thread(target=self.get_key_forever, daemon=True)
            self.input_thread.start()

            while True:
                self.screen.clear()

                h, w = self.screen.getmaxyx()
                lines = self.bpf_program.get_process_info()

                self.bottom = len(lines)

                # Handle input
                self.check_scroll_bounds()

                # Draw header
                self.screen.erase()
                self.screen.addstr(0, 0, self.bpf_program.get_header())
                offset = 1
                for line in lines[self.y_scroll:(self.y_scroll + (h - 2))]:
                    self.screen.addstr(offset, 0, line)
                    offset +=1

                self.screen.refresh()
                time.sleep(defs.sleep)
        finally:
            self.cleanup()
