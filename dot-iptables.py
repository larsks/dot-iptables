#!/usr/bin/python

import os
import errno
import sys
import re
import subprocess
import argparse
import pprint

from jinja2 import Template

re_table='''\*(?P<table>\S+)'''
re_table = re.compile(re_table)

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

def handle_table(iptables, mo, line):
    iptables[mo.group('table')] = {}
    iptables['_table'] = iptables[mo.group('table')]

def handle_chain(iptables, mo, line):
    policy = mo.group('policy')
    if policy == '-':
        policy = None

    iptables['_table'][mo.group('chain')] = {
            'policy': policy,
            'rules': [],
            'targets': set(),
            }

def handle_rule(iptables, mo, line):
    fields = dict( (k, v if v else '') for k,v in mo.groupdict().items())
    iptables['_table'][fields['chain']]['rules'].append(fields)

    if mo.group('target') and not mo.group('target').isupper():
        iptables['_table'][fields['chain']]['targets'].add(mo.group('target'))

def handle_commit(iptables, mo, line):
    iptables['_table'] = None

def read_chains(input):
    iptables = {
            '_table': None,
            }

    for line in stripped(input):
        mo = re_table.match(line)
        if mo:
            handle_table(iptables, mo, line)
            continue

        mo = re_chain.match(line)
        if mo:
            handle_chain(iptables, mo, line)
            continue

        mo = re_rule.match(line)
        if mo:
            handle_rule(iptables, mo, line)
            continue

        if line == 'COMMIT':
            handle_commit(iptables, None, line)
            continue

        print 'skip:', line

    del iptables['_table']
    return iptables

def output_rules(iptables, opts):
    tmpl = Template(open('rules.html').read())
    for table, chains in iptables.items():
        if table.startswith('_'):
            continue

        dir = os.path.join(opts.outputdir, table)
        try:
            os.mkdir(dir)
        except OSError, detail:
            if detail.errno == errno.EEXIST:
                pass
            else:
                raise

        for chain, data in chains.items():
            with open(os.path.join(dir, '%s.html' % chain), 'w') as fd:
                fd.write(tmpl.render(
                    table=table,
                    chain=chain,
                    rules=data['rules'],
                    policy=data['policy']))

def output_dot_table(iptables, opts, table):
    tmpl = Template(open('rules.html').read())

    dot = [
            'digraph table_%s {' % table,
            'rankdir=LR;',
            ]

    for chain, data in iptables[table].items():
        dot.append('"%s" [URL="%s/%s.html"]' % (
                chain,
                table,
                chain))

    dot.append('')

    for chain, data in iptables[table].items():
        for target in data['targets']:
            dot.append('"%s" -> "%s"' % (
                chain, target))

    dot.append('}')

    with open(os.path.join(opts.outputdir, '%s.dot' % table), 'w') as fd:
        fd.write('\n'.join(dot))
        fd.write('\n')

def output_dot(iptables, opts):
    tmpl = Template(open('index.html').read())
    with open(os.path.join(opts.outputdir, 'index.html'), 'w') as fd:
        fd.write(tmpl.render(tables=iptables.keys()))

    for table in iptables:
        if table.startswith('_'):
            continue

        output_dot_table(iptables, opts, table)
        continue

def main():
    opts = parse_args()

    if not os.path.isdir(opts.outputdir):
        print >>sys.stderr, (
                'ERROR: output directory %s does not exist.' %
                (opts.outputdir)
                )
        sys.exit(1)

    iptables = read_chains(sys.stdin)
    output_rules(iptables, opts)
    output_dot(iptables, opts)

if __name__ == '__main__':
        main()

