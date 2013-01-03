#!/usr/bin/python

import os
import sys
import re
import subprocess

#-A nova-compute-local -d 172.16.10.60/32 -j nova-compute-inst-9007 
re_chain='''-[PN] (?P<chain>\S+)( .*)?'''
re_chain = re.compile(re_chain)

re_rule='''-A (?P<chain>\S+)( (?P<conditions>.*))? -j (?P<target>\S*)'''
re_rule = re.compile(re_rule)

def iptables(*args):
    p = subprocess.Popen(['/sbin/iptables'] + list(args),
            stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return stdout.split('\n')

def main():
    chains = {}
    for line in iptables('-S'):
        mo = re_chain.match(line)
        if mo:
            chains[mo.group('chain')] = []
            continue

        mo = re_rule.match(line)
        if mo is None:
            continue
        if mo.group('target').isupper():
            continue

        chains[mo.group('chain')].append(mo.group('target'))

    print 'digraph iptables {'
    print 'rankdir=LR'
    for chain in chains.keys():
        with open('%s.txt' % chain, 'w') as fd:
            fd.write('\n'.join(iptables('-S', chain)))
        print '"%s" [URL="%s.txt"]' % (chain, chain)

    for chain, targets in chains.items():
        for target in targets:
            print '"%s" -> "%s"' % (chain, target)

    print '}'

if __name__ == '__main__':
        main()

