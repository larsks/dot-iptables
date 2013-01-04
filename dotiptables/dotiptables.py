#!/usr/bin/python

import os
import errno
import sys
import re
import subprocess
import argparse
import pprint

import jinja2
from jinja2 import Template
from jinja2.loaders import PackageLoader

env = jinja2.Environment(
        loader=PackageLoader('dotiptables', 'templates'))

re_table='''^\*(?P<table>\S+)'''
re_table = re.compile(re_table)

re_chain='''^:(?P<chain>\S+) (?P<policy>\S+) (?P<counters>\S+)'''
re_chain = re.compile(re_chain)

re_rule='''^-A (?P<chain>\S+)( (?P<conditions>.*))?( -j (?P<target>\S*))?( (?P<extra>.*))?'''
re_rule = re.compile(re_rule)

re_commit='''^COMMIT'''
re_commit=re.compile(re_commit)

re_comment='''^#(?P<comment>.*)'''
re_comment=re.compile(re_comment)

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--outputdir', '-d', default='.')
    p.add_argument('--render', action='store_true')
    p.add_argument('input', nargs='?')

    return p.parse_args()

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

    actions = (
            (re_table,   handle_table),
            (re_chain,   handle_chain),
            (re_rule,    handle_rule),
            (re_commit,  handle_commit),
            (re_comment, None),
            )

    for line in stripped(input):
        try:
            for pattern, action in actions:
                mo = pattern.match(line)
                if mo:
                    if action is not None:
                        action(iptables, mo, line)
                    raise StopIteration()
        except StopIteration:
            continue

        # We should never get here.
        print >>sys.stderr, 'unrecognized line:', line

    del iptables['_table']
    return iptables

def output_rules(iptables, opts):
    tmpl = env.get_template('rules.html')
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
    tmpl = env.get_template('table.dot')

    with open(os.path.join(opts.outputdir, '%s.dot' % table), 'w') as fd:
        fd.write(tmpl.render(
            table=table,
            chains=iptables[table],
            ))
        fd.write('\n')

def output_dot(iptables, opts):
    tmpl = env.get_template('index.html')
    with open(os.path.join(opts.outputdir, 'index.html'), 'w') as fd:
        fd.write(tmpl.render(tables=iptables.keys()))

    for table in iptables:
        output_dot_table(iptables, opts, table)
        continue

def render_svg(iptables, opts):
    for table in iptables:
        p = subprocess.Popen(['dot', '-T', 'svg', '-o',
                os.path.join(opts.outputdir, '%s.svg' % table),
                os.path.join(opts.outputdir, '%s.dot' % table)])
        p.communicate()

def main():
    opts = parse_args()

    if not os.path.isdir(opts.outputdir):
        print >>sys.stderr, (
                'ERROR: output directory %s does not exist.' %
                (opts.outputdir)
                )
        sys.exit(1)

    print 'Reading iptables data.'
    iptables = read_chains(sys.stdin)

    print 'Generating DOT output.'
    output_rules(iptables, opts)
    output_dot(iptables, opts)

    if opts.render:
        print 'Generating SVG output.'
        render_svg(iptables, opts)

if __name__ == '__main__':
        main()

