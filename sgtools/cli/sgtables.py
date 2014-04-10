from __future__ import print_function
import sys
import os
from argparse import ArgumentParser
from acky import AWS
from acky.api import AWSCallError
from sgtools.abstractions.sgengine import (
    RuleSet,
    RuleFormatter,
    read_rules,
)
import logging

log = logging.getLogger(os.path.basename(sys.argv[0]))


def change_rules(args, rules, verb, warn=None):
    error = 0
    if not rules:
        log.info("Nothing to {}".format(verb))
        return 0
    for rule in rules:
        if rule["GroupId"] not in args.groups:
            log.debug("Skipping rule for excluded group: {}".format(rule))
            continue
        if args.noop:
            log.info("NOOP: {} {}".format(verb, RuleFormatter(args.aws.account_id).format_rule(rule)))
            continue
        try:
            action = getattr(args.aws.ec2.IpPermissions, verb)
            action(rule["GroupId"], rule.other(), rule.proto_spec(), rule["Direction"])
            log.info("{} rule: {}".format(verb, RuleFormatter(args.aws.account_id).format_rule(rule)))
        except AWSCallError as e:
            if warn and e.code in warn:
                log.warn("Warning: {}".format(e))
                log.warn("         {}".format(rule))
            else:
                log.error("Error: {}".format(e))
                error = 1
    return error


def groups_for(profile, region, vpc):
    filters = {}
    exclude_vpc = False
    if vpc == 'classic':
        exclude_vpc = True
    else:
        filters['vpc-id'] = vpc
    aws = AWS(region, profile)
    return aws.ec2.SecurityGroups.get(filters=filters, exclude_vpc=exclude_vpc)


###############################################################################
# subcommands
###############################################################################

def do_add_rules(args):
    log.info("Operation: add")
    rules, errors = read_rules(args.files)
    if errors:
        map(log.error, errors)
        return 1
    return change_rules(args, rules, "add", ("InvalidPermission.Duplicate",))


def do_remove_rules(args):
    log.info("Operation: remove")
    rules, errors = read_rules(args.files)
    if errors:
        map(log.error, errors)
        return 1
    return change_rules(args, rules, "remove", ("InvalidPermission.NotFound",))


def do_update_rules(args):
    log.info("Operation: update")
    rules, errors = read_rules(args.files)
    if errors:
        map(log.error, errors)
        return 1

    log.debug("Collecting active rules")
    group_args = (args.profile, args.region, args.vpc)
    remote_groups = groups_for(*group_args)
    if args.obliterate:
        log.warning("Obliterate: Updating all groups in {} {} {}".format(*group_args))
    else:
        affected_groups = list(set(args.groups).intersection(set(g['GroupId'] for g in rules)))
        if not affected_groups:
            log.warning("No affected groups")
            return 0
        log.debug("Affected groups: {}".format(", ".join(affected_groups)))
        remote_groups = [g for g in remote_groups if g['GroupId'] in affected_groups]

    remote_rules = RuleSet().flatten_groups(remote_groups)
    add_set = rules - remote_rules
    remove_set = remote_rules - rules
    if args.add_before_remove:
        error = change_rules(args, add_set, "add")
        if error != 0:
            return error
        return change_rules(args, remove_set, "remove")
    else:
        error = change_rules(args, remove_set, "remove")
        if error != 0:
            return error
        return change_rules(args, add_set, "add")


def do_list_rules(args):
    groups = args.aws.ec2.SecurityGroups.get(filters={'group-id': args.groups})
    rs = RuleSet()
    rs.flatten_groups(groups)
    for rule in rs:
        print(RuleFormatter(args.aws.account_id).format_rule(rule), file=args.outfile)
    return 0


###############################################################################
# main program
###############################################################################

def define_arguments():
    std_args = ArgumentParser(add_help=False)
    std_args.add_argument("profile", help="(aka environment)")
    std_args.add_argument("region", help="e.g. us-east-1, us-west-2, etc.")
    std_args.add_argument("vpc", help="VPC ID or 'classic'")

    logging = std_args.add_mutually_exclusive_group()
    logging.add_argument("--verbose", action="store_true", default=False)
    logging.add_argument("--debug", action="store_true", default=False)

    group_selection = std_args.add_mutually_exclusive_group()
    group_selection.add_argument("--groups", nargs="*", metavar="GROUP", default=[],
                                 help="Only list/modify these groups")

    ap = ArgumentParser()
    sp = ap.add_subparsers(title="Subcommands")

    #=====
    listcmd = sp.add_parser("list", parents=[std_args],
                            description="List current rules")
    listcmd.add_argument("--names", action='store_true', default=False)
    listcmd.set_defaults(do=do_list_rules)

    # the rest of the command require file input ...
    std_args.add_argument("--files", nargs="*", metavar="FILE", default=["-"],
                          help="Read rules from FILE instead of stdin. To include stdin explicitly, use '-'")
    std_args.add_argument("--tty", action="store_true", default=False,
                          help="Allow input from a tty")
    # ... and can make changes
    std_args.add_argument("--noop", action="store_true", default=False,
                          help="Don't change anything, just print what would have changed")

    #=====
    addcmd = sp.add_parser("add", parents=[std_args],
                           description="Add given rules")
    addcmd.add_argument("--create", help="Create named groups if needed")
    addcmd.set_defaults(do=do_add_rules)

    #=====
    delcmd = sp.add_parser("remove", parents=[std_args])
    delcmd.set_defaults(do=do_remove_rules)

    #=====
    upd_order = std_args.add_mutually_exclusive_group()
    upd_order.add_argument("--add-before-remove", action='store_true', default=True)
    upd_order.add_argument("--remove-before-add", action='store_false',
                           dest="add_before_remove")
    group_selection.add_argument("--obliterate", action="store_true", default=False,
                                 help="Remove all rules from groups not mentioned in the rule set")

    updcmd = sp.add_parser("update", parents=[std_args])
    updcmd.set_defaults(do=do_update_rules)

    return ap


def configure_logging(args):
    if args.debug:
        loglevel = "DEBUG"
    elif args.verbose:
        loglevel = "INFO"
    else:
        loglevel = "WARNING"
    logging.basicConfig(level=loglevel)
    logging.getLogger('botocore').setLevel("WARNING")


def resolve_arguments(ap, arg_list=sys.argv[1:]):
    args = ap.parse_args(arg_list)
    if hasattr(args, "files") and '-' in args.files and sys.stdin.isatty() and not args.tty:
        ap.error("Input is a TTY")
    args.aws = AWS(args.region, args.profile)
    args.outfile = sys.stdout

    all_group_ids = [g['GroupId'] for g in groups_for(args.profile, args.region, args.vpc)]
    if args.groups:
        args.groups = list(set(all_group_ids).intersection(set(args.groups)))
    else:
        args.groups = all_group_ids
    if not args.groups:
        ap.error("None of the specified groups exist in the given profile/region/vpc")
    return args


def main():
    args = resolve_arguments(define_arguments())
    configure_logging(args)
    return args.do(args)


if __name__ == '__main__':
    sys.exit(main())
