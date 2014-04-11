from unittest import TestCase
from StringIO import StringIO
from situ.abstractions.sgengine import (
    RawSecurityGroupRule,
    RawRuleFormatter,
)
from sgtools.cli import sgtables
from mock import (
    MagicMock,
    patch,
)
from itertools import chain

INPUT = u"""
in sg-12345678 sg-98765432 tcp 22 22
in sg-12345678 sg-98765432 udp 0 65535
in sg-12345678 sg-98765432 icmp -1 -1
in sg-12345678 sg-98765432 17 1024 65535
in sg-12345678 sg-98765432 2 None None
# this is a comment
in sg-12345678 1.2.3.4/32 tcp 0 65535
in sg-12345678(foo) sg-98765432 tcp 0 65535
in sg-12345678 sg-98765432(bar) tcp 0 65535
in sg-12345678(foo) sg-98765432(bar) tcp 0 65535
in (foo) sg-98765432 tcp 0 65535
in sg-12345678 (bar) tcp 0 65535
in (foo) (bar) tcp 0 65535
in (foo) 3.4.5.6/24 tcp 0 65535
"""
INPUT_RULE_COUNT = 13

CURRENT_RULES = {
    "sg-12345678": (
        RawSecurityGroupRule("sg-12345678", "sg-88888888", dst_name="foo", src_name="baz", proto="udp"),
        RawSecurityGroupRule("sg-12345678", "sg-98765432", dst_name="foo", src_name="bar", proto="icmp", low_port="-1", high_port="-1"),
        RawSecurityGroupRule("sg-12345678", "sg-88888888", dst_name="foo", src_name="baz", proto="17", low_port="1024", high_port="65535"),
        RawSecurityGroupRule("sg-12345678", "sg-88888888", dst_name="foo", src_name="baz", proto="2"),
        RawSecurityGroupRule("sg-12345678", "111.222.111.222/32", dst_name="foo"),
    ),
    "sg-99999999": (
        RawSecurityGroupRule("sg-99999999", "sg-98765432", dst_name="qux", src_name="bar"),
        RawSecurityGroupRule("sg-99999999", "sg-98765432", dst_name="qux", src_name="bar", proto="icmp"),
    ),
}


class Namespace(object):
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class SgtablesTests(TestCase):
    def setUp(self):
        super(SgtablesTests, self).setUp()
        self.new_rules = StringIO(INPUT)

    def get_args(self, argv):
        return sgtables.resolve_arguments(sgtables.define_arguments(), arg_list=argv,
                                          prog="sgtables_unit_tests")

    def test_arguments(self):
        pass

    @patch('sgtools.abstractions.sgengine.sgid_to_name')
    def test_reads_rules(self, _lookup):
        filenames = ("-")
        conn = MagicMock()
        _lookup.side_effect = lambda _, n: {"foo": "sg-12345678", "bar": "sg-98765432"}[n]
        with patch("sgtools.cli.sgtables.sys.stdin", StringIO(INPUT)):
            rules, error = sgtables.read_rules(conn, filenames)
        self.assertEqual(len(rules), INPUT_RULE_COUNT)

    def test_list_arguments(self):
        pass

    @patch("sgtools.cli.sgtables.RawSecurityGroup")
    def dolist(self, groups, names, _rsg):
        args = MagicMock()
        args.outfile = StringIO()
        args.ec2sg.group_ids.return_value = tuple(CURRENT_RULES.keys())
        _rsg.side_effect = lambda _, sgid: Namespace(current_rules=CURRENT_RULES[sgid],
                                                     refresh=lambda: None)

        args.groups = groups
        args.names = names
        sgtables.do_list_rules(args)
        args.outfile.seek(0)
        return list(l.strip() for l in args.outfile.readlines())

    def test_list(self):
        fmtr = RawRuleFormatter()

        # list all rules
        for names in (True, False):
            lines = self.dolist([], names)
            for rule in chain.from_iterable(CURRENT_RULES.values()):
                self.assertIn(fmtr.format_rule(rule, include_groupnames=names), lines)

        # one group
        groups = [CURRENT_RULES.keys()[0]]
        for names in (True, False):
            lines = self.dolist(groups, names)
            for rule in CURRENT_RULES[groups[0]]:
                self.assertIn(fmtr.format_rule(rule, include_groupnames=names), lines)

    def test_add_arguments(self):
        pass

    def test_add(self):
        pass

    def test_add_invalid(self):
        pass

    def test_remove_arguments(self):
        pass

    def test_remove(self):
        pass

    def test_remove_invalid(self):
        pass

    def test_update_arguments(self):
        pass

    def test_update(self):
        pass

    def test_update_invalid(self):
        pass

    def test_obliterate_arguments(self):
        pass

    def test_obliterate(self):
        pass

    def test_obliterate_invalid(self):
        pass
