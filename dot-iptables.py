#!/usr/bin/python

import os
import sys
import re
import subprocess
import argparse

from jinja2 import Template

re_chain=''':(?P<chain>\S+) (?P<policy>\S+) (?P<counters>\S+)'''
re_chain = re.compile(re_chain)

re_rule='''-A (?P<chain>\S+)( (?P<conditions>.*))? -j (?P<target>\S*)( (?P<extra>.*))?'''
re_rule = re.compile(re_rule)

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--outputdir', '-d', default='.')
    p.add_argument('input', nargs='?')

    return p.parse_args()

def sanitize(s):
    return s.translate(''.join(chr(x) if chr(x).isalnum() else '_' for x in range(0,256)))

def stripped(fd):
    for line in fd:
        yield line.strip()

def read_chains(input):
    relationships = {}
    rules = {}
    policies = {}
    for line in stripped(input):
        mo = re_chain.match(line)
        if mo:
            relationships[mo.group('chain')] = []
            rules[mo.group('chain')] = []
            policies[mo.group('chain')] = mo.group('policy')
            continue

        mo = re_rule.match(line)
        if mo is None:
            continue

        fields = mo.groupdict()
        for k,v in fields.items():
            if v is None:
                fields[k] = ''

        rules[mo.group('chain')].append(fields)
        if mo.group('target').isupper():
            continue

        relationships[mo.group('chain')].append(mo.group('target'))

    return policies, rules, relationships

def output_rules(policies, rules, opts):
    tmpl = Template(open('rules.html').read())
    for chain, rules in rules.items():
        with open(os.path.join(opts.outputdir, '%s.html' % chain), 'w') as fd:
            fd.write(tmpl.render(chain=chain, rules=rules,
                policy=policies[chain]))

def output_dot(relationships, opts):
    dot = [
            'digraph iptables {',
            'rankdir=LR;',
            ]

    for chain in relationships.keys():
        dot.append('"%s" [URL="%s.html"];' % (chain, chain))

    for chain, targets in relationships.items():
        for target in targets:
            dot.append('"%s" -> "%s";' % (chain, target))

    dot.append('}')

    with open(os.path.join(opts.outputdir, 'iptables.dot'), 'w') as fd:
        fd.write('\n'.join(dot))
        fd.write('\n')

def main():
    opts = parse_args()
    print opts

    if not os.path.isdir(opts.outputdir):
        print >>sys.stderr, (
                'ERROR: output directory %s does not exist.' %
                (opts.outputdir)
                )
        sys.exit(1)

    policies, rules, relationships = read_chains(sys.stdin)

    output_rules(policies, rules, opts)
    output_dot(relationships, opts)

if __name__ == '__main__':
        main()

