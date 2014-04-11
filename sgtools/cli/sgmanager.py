from __future__ import print_function
import sys
import os
import logging
from argparse import ArgumentParser
from itertools import chain
from sgtools.abstractions.sgmanager import Parser
from sgtools.abstractions.sgengine import read_rules
from acky.aws import AWS


def render_rules(args):
    """Render a symbolic ruleset to raw rules"""
    log = logging.getLogger(__name__)
    try:
        parser = Parser(args.vars_files, args.account)
    except IOError as e:
        log.error(e)
        return 1
    print(parser.dump(args.account))


def reverse_rules(args):
    """Given a variables file and raw rules, try to build a symbolic ruleset"""
    log = logging.getLogger(__name__)
    if args.vars_files:
        try:
            parser = Parser(args.vars_files, args.account)
        except IOError as e:
            log.error(e)
            return 1
        vrev = parser.vars_reverse
        vfwd = parser.variables
    else:
        vrev = {}
        vfwd = {}
    account = str(vfwd.get(args.account))
    if not account:
        log.error('Account {} is not defined'.format(args.account))
        return 1

    try:
        rules, errors = read_rules(args.input_files)
    except IOError as e:
        log.error(e)
        return 1

    if errors:
        map(log.error, errors)
        return 1

    for rule in rules:
        owner = vrev.get(rule['GroupId'])
        if not owner:
            log.warning("Could not resolve owner: {}".format(rule['GroupId']))
            owner = "unknown({})".format(rule['GroupId'])

        other_raw = rule.get('OtherCidrIp')
        if not other_raw:
            other_raw = rule.other()
            if '/' in other_raw:
                if other_raw.split('/', 1)[0] == account:
                    other_raw = other_raw.split('/', 1)[1]
        other = vrev.get(other_raw)
        if not other:
            log.warning("Could not resolve other: {}".format(other_raw))
            other = "unknown({})".format(other_raw)

        proto_raw = "{} {} {}".format(rule['IpProtocol'], rule['FromPort'], rule['ToPort'])
        proto = vrev.get(proto_raw)
        if not proto:
            log.warning("Could not resolve protocol: {}".format(proto_raw))
            proto = "unknown({}/{}/{})".format(rule['IpProtocol'],
                                               rule['FromPort'],
                                               rule['ToPort'])

        print('rule {} {} {} {}'.format(rule['Direction'], owner, other, proto))


def groupdefs(args):
    """Produce a set of group definitions for an account/region/vpc"""
    log = logging.getLogger(__name__)
    aws = AWS(args.region, args.profile)
    if args.vpc == 'classic':
        exclude_vpc = True
        filters = {}
    else:
        exclude_vpc = False
        filters = {'vpc-id': args.vpc}
    groups = aws.ec2.SecurityGroups.get(filters=filters, exclude_vpc=exclude_vpc)
    for group in groups:
        if not Parser.VARIABLE.match(group['GroupName']):
            log.warning("Group name '{}' is not a valid variable name".format(group['GroupName']))
        print('sg {} {}'.format(group['GroupName'], group['GroupId']))


def define_arguments():
    ap = ArgumentParser()
    sp = ap.add_subparsers(title="Subcommands", dest="subcommand")
    sp.required = True

    #=====
    grpscmd = sp.add_parser("groupdefs",
                            description=groupdefs.__doc__)
    grpscmd.add_argument("profile", help="AWS profile (from ~/.aws/config)")
    grpscmd.add_argument("region", help="AWS region")
    grpscmd.add_argument("vpc", help="VPC ID or 'classic'")
    grpscmd.set_defaults(do=groupdefs)

    std_args = ArgumentParser(add_help=False)
    std_args.add_argument("account")
    std_args.add_argument('--tty', action='store_true', default=False,
                          help="Allow input from a tty (default=False)")

    #=====
    rndrcmd = sp.add_parser("render", parents=[std_args],
                            description=render_rules.__doc__)
    rndrcmd.add_argument("vars_files", nargs="*", metavar="FILE", default=[])
    rndrcmd.set_defaults(do=render_rules)

    #=====
    rvrscmd = sp.add_parser("reverse", parents=[std_args],
                            description=reverse_rules.__doc__)
    rvrscmd.add_argument("--vars-files", nargs="*", metavar="VARS_FILE", default=[])
    rvrscmd.add_argument("--input-files", nargs="+", metavar="RULES_FILE", default=[])
    rvrscmd.set_defaults(do=reverse_rules)

    return ap


def resolve_arguments(ap, arg_list=sys.argv[1:]):
    args = ap.parse_args(arg_list)
    all_files = []
    for files_list in ("input_files", "vars_files"):
        files = getattr(args, files_list, [])
        if '-' in files and '-' in all_files:
            ap.error('Cannot read from stdin more than once')
        all_files = chain(all_files, files)
    if '-' in all_files and sys.stdin.isatty() and not args.tty:
        ap.error("Input is a TTY")
    return args


def configure_logging():
    logging.basicConfig(level=os.environ.get('LOGLEVEL', 'WARNING'))


def main():
    configure_logging()
    args = resolve_arguments(define_arguments())
    return args.do(args)
