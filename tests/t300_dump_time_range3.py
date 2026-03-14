#!/usr/bin/env python3

# When using 'uftrace dump --time-range', raw dump (do_dump_file) simply
# filters out records outside the range without emitting synthetic entry
# events.  Functions entered before range_start (main, a, b) will have
# their exit records present but no matching entry records.
#
# This test records the abc call chain (main -> a -> b -> c -> getpid),
# then dumps with --time-range starting at c's entry.  The raw dump output
# must start from c's entry and include the orphaned exits for b, a, main.

import re
import subprocess as sp

from runtest import TestBase

START = '0'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
[entry] depth: 3 c
[entry] depth: 4 getpid
[exit ] depth: 4 getpid
[exit ] depth: 3 c
[exit ] depth: 2 b
[exit ] depth: 1 a
[exit ] depth: 0 main
""")

    def prerun(self, timeout):
        global START

        self.subcmd = 'record'
        record_cmd = self.runcmd()
        sp.call(record_cmd.split())

        # Find the entry timestamp of 'c' so the time range starts after
        # main, a, and b have already been entered.
        self.subcmd = 'replay'
        self.option = '-f time -F main'
        replay_cmd = self.runcmd()

        p = sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        r = p.communicate()[0].decode(errors='ignore')
        lines = r.split('\n')
        if len(lines) < 5:
            return TestBase.TEST_DIFF_RESULT
        START = lines[4].split()[0]  # skip header, main, a, b (= 4 lines)
        p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'dump'
        self.option = '-r %s~' % START

    def sort(self, output):
        result = []
        # Raw dump format: "timestamp tid: [entry|exit ] func(addr) depth: N"
        raw_patt = re.compile(r'[^[]*(?P<type>\[(entry|exit )\]) (?P<func>[_a-z0-9]*)\([0-9a-f]+\) (?P<depth>.*)')
        # Already-processed format (expected string): "[entry|exit ] depth: N func"
        proc_patt = re.compile(r'\[(entry|exit )\] depth: \d+ [_a-z0-9]+')
        for ln in output.split('\n'):
            m = raw_patt.match(ln)
            if m:
                if m.group('func').startswith('__'):
                    continue
                result.append('%s %s %s' % (m.group('type'), m.group('depth'), m.group('func')))
            elif proc_patt.match(ln.strip()):
                result.append(ln.strip())
        return '\n'.join(result)
