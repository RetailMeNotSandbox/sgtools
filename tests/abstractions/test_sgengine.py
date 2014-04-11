from unittest import TestCase
from random import choice
import logging
from sgtools.abstractions.sgengine import (
    RuleFormatter,
    Rule,
    RuleSet,
    InvalidRule,
    MultipleNameMatches,
    sgid_to_name,
    name_to_sgid,
    _groupname_cache,
)
from itertools import (
    combinations_with_replacement,
    chain,
)
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock


class SgidToNameTests(TestCase):
    def setUp(self):
        super(SgidToNameTests, self).setUp()
        self.aws = MagicMock()
        self.group = MagicMock()
        self.group["GroupName"] = "foo"
        self.sgid = "sg-123456"
        self.aws.ec2.SecurityGroups.get.return_value = [self.group]

    def test_sgid_to_name(self):
        _groupname_cache.pop(self.sgid, None)  # make sure test group isn't in the cache
        sg_name = sgid_to_name(self.aws, self.sgid)
        self.aws.SecurityGroups.get.called_with(filters={'group-id': self.sgid})
        self.assertEqual(self.group["GroupName"], sg_name)

    def test_lookup_caches_name(self):
        _groupname_cache.pop(self.sgid, None)  # make sure test group isn't in the cache
        sgid_to_name(self.aws, self.sgid)
        self.assertIn(self.sgid, _groupname_cache)

    def test_lookup_uses_cache(self):
        # prime the cache
        _groupname_cache[self.sgid] = self.group["GroupName"]
        sgid_to_name(self.aws, self.sgid)
        self.assertFalse(self.aws.get_all_security_groups.called)


class NameToSgidTests(TestCase):
    def setUp(self):
        super(NameToSgidTests, self).setUp()
        self.aws = MagicMock()
        self.group = MagicMock()
        self.group["GroupId"] = "sg-12345678"
        self.sg_name = "foo"
        self.aws.ec2.SecurityGroups.get.return_value = [self.group]

    def test_name_to_sgid(self):
        _groupname_cache.pop(self.sg_name, None)  # make sure test group isn't in the cache
        sg_name = name_to_sgid(self.aws, self.sg_name)
        self.aws.SecurityGroups.get.called_with(filters={'group-name': self.sg_name})
        self.assertEqual(self.group["GroupName"], sg_name)

    def test_multiple_matches(self):
        self.aws.ec2.SecurityGroups.get.return_value = [self.group, self.group]
        _groupname_cache.pop(self.sg_name, None)  # make sure test group isn't in the cache
        with self.assertRaises(MultipleNameMatches):
            name_to_sgid(self.aws, self.sg_name)

    def test_lookup_caches_name(self):
        _groupname_cache.pop(self.sg_name, None)  # make sure test group isn't in the cache
        name_to_sgid(self.aws, self.sg_name)
        self.assertIn(self.sg_name, _groupname_cache)

    def test_lookup_uses_cache(self):
        # prime the cache
        _groupname_cache[self.sg_name] = self.group["GroupName"]
        name_to_sgid(self.aws, self.sg_name)
        self.assertFalse(self.aws.get_all_security_groups.called)


class SgengineTest(TestCase):
    def setUp(self):
        super(SgengineTest, self).setUp()
        self.good_gids = (
            'sg-12345678',
            'sg-abcdef12',
            'sg-98765432',
            'sg-a1b2c3d4',
        )
        self.bad_sgid = 'blahblahblah'
        self.good_account = "123456"
        self.bad_account = "abcdefg"
        self.good_cidr = '1.2.3.4/22'
        self.bad_cidr = '1.2.3/0'
        self.min_port = 0
        self.max_port = 65535
        self.undef_port = -1
        self.vpc_id = "vpc-987654"
        self.rule_params = {
            "Direction": "in",
            "GroupId": self.good_gid,
            "IpProtocol": "tcp",
            "FromPort": "22",
            "ToPort": "22",
        }
        self.grpsrc_param = {
            "OtherGroupId": self.good_gid,
        }
        self.grpuser_param = {
            "OtherUserId": self.good_account,
        }
        self.cidrsrc_param = {
            "OtherCidrIp": self.good_cidr,
        }
        self.ignored_params = {
            "Description": "foo",
            "GroupName": "bar",
            "OwnerId": "123456789",
            "VpcId": "vpc-12345678",
            "OtherUserId": "987654321",
            "OtherGroupName": "baz",
        }

    @property
    def good_gid(self):
        return choice(self.good_gids)


class RuleTest(SgengineTest):
    def test_hashing(self):
        # Rule should be hashable (have a callable __hash__ attribute)
        params = dict(chain(self.rule_params.items(), self.grpsrc_param.items()))
        rule = Rule(params)
        self.assertTrue(hasattr(getattr(rule, '__hash__', None), '__call__'))
        self.assertEqual(rule.__hash__(), Rule(params).__hash__())

    def test_hash_ignores_peripheral_fields(self):
        # hash should only consider the following fields when determining Rule
        # identity:
        # - GroupId
        # - (IpProtocol, FromPort, ToPort)
        # - (Direction, OtherGroupId)
        # - (Direction, OtherCidrIp)
        # specifically, the following fields should be IGNORED: GroupName,
        # Description, OwnerId, VpcId, OtherUserId, OtherGroupName
        params = dict(chain(self.rule_params.items(), self.grpsrc_param.items()))
        rule1 = Rule(params)
        params.update(self.ignored_params)
        rule2 = Rule(params)
        self.assertEqual(rule1, rule2)

    def test_equality(self):
        # ensure that two identically-constructed Rules are equal
        params = dict(chain(self.rule_params.items(), self.grpsrc_param.items()))
        self.assertEqual(Rule(params), Rule(params))

    def test_generates_other_string(self):
        # ensure that Rule.other() returns a string representation of the other
        # CIDR or group (possibly with account) as appropriate
        params = dict(chain(self.rule_params.items(), self.grpsrc_param.items()))
        rule = Rule(params)
        self.assertEqual(rule.other(), "{OtherGroupId}".format(**params))

        params.update(self.grpuser_param)
        rule = Rule(params)
        self.assertEqual(rule.other(), "{OtherUserId}/{OtherGroupId}".format(**params))

        params = dict(chain(self.rule_params.items(), self.cidrsrc_param.items()))
        rule = Rule(params)
        self.assertEqual(rule.other(), "{OtherCidrIp}".format(**params))

    def test_portnums_converted_to_ints(self):
        # ensure that FromPort and ToPort are stored as ints
        params = dict(chain(self.rule_params.items(), self.grpsrc_param.items()))
        rule = Rule(params)
        for field in ("FromPort", "ToPort"):
            self.assertEqual(rule[field], int(params[field]))

    def test_known_proto_numbers_converted_to_names(self):
        # ensure that icmp (1), tcp (6), and udp (17) protocol number are
        # converted to names
        params = dict(chain(self.rule_params.items(), self.grpsrc_param.items()))
        params['IpProtocol'] = "1"
        self.assertEqual(Rule(params)["IpProtocol"], "icmp")

        params['IpProtocol'] = "6"
        self.assertEqual(Rule(params)["IpProtocol"], "tcp")

        params['IpProtocol'] = "17"
        self.assertEqual(Rule(params)["IpProtocol"], "udp")

    def test_generates_proto_spec(self):
        # ensure that Rule.proto_spec() returns a tuple (IpProtocol, FromPort,
        # ToPort)
        params = dict(chain(self.rule_params.items(), self.grpsrc_param.items()))
        proto_spec = (params["IpProtocol"], int(params["FromPort"]), int(params["ToPort"]))
        self.assertEqual(Rule(params).proto_spec(), proto_spec)

    def test_sortable(self):
        # ensure that Rules are sortable on a key consisting of
        # (
        #   GroupId,
        #   (IpProtocol, FromPort, ToPort),
        #   (Direction, OtherGroupId),
        #   (Direction, OtherCidrIp)
        # )
        keys = ("GroupId", "IpProtocol", "FromPort", "ToPort", "Direction", "OtherCidrIp", "Direction", "OtherGroupId")
        rule2 = None
        for values in combinations_with_replacement(("0", "1"), len(keys)):
            rule1 = rule2
            rule2 = Rule(zip(keys, values))
            if rule1:
                self.assertTrue(rule1 <= rule2)


class RuleSetTest(SgengineTest):
    def setUp(self):
        super(RuleSetTest, self).setUp()
        self.groups = [{
            "GroupId": "sg-12345678",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "UserIdGroupPairs": [{
                    "GroupId": "sg-abcdef12",
                }],
                "IpRanges": [{
                    "CidrIp": "0.0.0.0/0",
                }],
            }],
            "IpPermissionsEgress": [],
        }, {
            "GroupId": "sg-23456789",
            "IpPermissions": [],
            "IpPermissionsEgress": [{
                "IpProtocol": "udp",
                "FromPort": 0,
                "ToPort": 65535,
                "UserIdGroupPairs": [{
                    "GroupId": "sg-bcdef123",
                }],
                "IpRanges": [{
                    "CidrIp": "1.2.3.4/8",
                }],
            }],
        }]
        self.flat = [{
            "Direction": "in",
            "GroupId": "sg-12345678",
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "OtherGroupId": "sg-abcdef12",
        }, {
            "Direction": "in",
            "GroupId": "sg-12345678",
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "OtherCidrIp": "0.0.0.0/0",
        }, {
            "Direction": "out",
            "GroupId": "sg-23456789",
            "IpProtocol": "udp",
            "FromPort": 0,
            "ToPort": 65535,
            "OtherGroupId": "sg-bcdef123",
        }, {
            "Direction": "out",
            "GroupId": "sg-23456789",
            "IpProtocol": "udp",
            "FromPort": 0,
            "ToPort": 65535,
            "OtherCidrIp": "1.2.3.4/8",
        }]

    def test_add_rule(self):
        # ensure that rules are coerced to Rules
        rs = RuleSet()
        rs.add(dict(chain(self.rule_params.items(), self.cidrsrc_param.items())))
        self.assertIsInstance(rs.pop(), Rule)

    def test_flatten_groups(self):
        # ensure that a group structure is flattened to the equivalent set of Rules
        rs = RuleSet()
        rs.flatten_groups(self.groups)
        for group in rs:
            self.assertIn(dict(group), self.flat)

    def test_adds_missing_ports(self):
        groups = [{
            "GroupId": "sg-23456789",
            "IpPermissions": [{
                "IpProtocol": -1,
                "UserIdGroupPairs": [],
                "IpRanges": [{
                    "CidrIp": "5.6.7.8/32",
                }],
            }],
            "IpPermissionsEgress": [],
        }]
        rs = RuleSet()
        rs.flatten_groups(groups)
        for group in rs:
            self.assertEqual(group["FromPort"], -1)
            self.assertEqual(group["ToPort"], -1)

    def test_render_groups(self):
        # ensure that a given rule set is converted to the equivalent security
        # group hierachy
        rs = RuleSet()
        for flat in self.flat:
            rs.add(Rule(flat))
        self.assertEqual(self.groups, rs.render_groups())


class RuleFormatterTest(SgengineTest):
    def test_parses_group(self):
        formatter = RuleFormatter()
        gid = self.good_gid
        self.assertEqual({'GroupId': gid}, formatter.parse_group(gid))

    def test_parses_other(self):
        formatter = RuleFormatter()
        gid = self.good_gid
        account = self.good_account
        self.assertEqual({'OtherGroupId': gid, 'OtherUserId': account},
                         formatter.parse_other("{}/{}".format(account, gid)))

    def test_parses_valid_rules(self):
        logger = logging.getLogger(__name__)
        lines = (
            "in sg-12345abc sg-def98765 tcp 0 65535",
            "in sg-12345abc sg-def98765 udp 0 65536",
            "in sg-12345abc sg-def98765 -1 0 65536",
            "in sg-12345abc sg-def98765 17 0 65536",
            "in sg-12345abc sg-def98765 tcp -1 65535",
            "in sg-12345abc 0.0.0.0/0 tcp -1 65535",
            "in sg-12345abc 1.2.3.4 tcp -1 65535",
            "in sg-12345abc sg-def98765 tcp 0 -1",
            "in sg-12345abc sg-def98765 tcp -1 -1",
            "in sg-12345abc sg-def98765 tcp 22 22",
            "in sg-12345abc 123456/sg-def98765 tcp 22 22",
            "in sg-12345abc sg-def98765 17 -1 -1",
        )

        formatter = RuleFormatter()
        for line in lines:
            logger.debug(line)
            rule = formatter.parse_string(line)
            self.assertIsInstance(rule, Rule, msg="Failed on {}".format(line))

    def test_fails_parse_invalid(self):
        logger = logging.getLogger(__name__)
        lines = ("in sg-12345abc sg-def98765 tcp a 65535",
                 "in sg-12345abc sg-def98765 udp 0 a"
                 "in sg-12345abc sg-def98765 fail 0 65536",
                 "in sg-12345abc sg-def98765 None None None",
                 "in sg-12345abc(foo baz) sg-def98765(bar) tcp 0 65535",
                 "in sg-12345abc(foo baz) sg-def98765(bar qux) tcp 0 65535",
                 "eg sg-12345abc sg-def98765 tcp 0 65535")
        formatter = RuleFormatter()
        for line in lines:
            logger.debug(line)
            self.assertRaises(InvalidRule, formatter.parse_string, line)

    def test_formats_rule(self):
        this = self.good_gid
        other = self.good_gid
        rule_fmt = "{Direction} {GroupId} {OtherGroupId}{OtherCidrIp} " + \
                   "{IpProtocol} {FromPort} {ToPort}"
        rule_fmt_with_acc = "{Direction} {GroupId} {OtherUserId}/{OtherGroupId} " + \
                            "{IpProtocol} {FromPort} {ToPort}"
        formatter = RuleFormatter()

        rule_data = {
            'Direction': 'in',
            'GroupId': this,
            'IpProtocol': 'tcp',
            'FromPort': 0,
            'ToPort': 65535,
            'OtherGroupId': other,
            'OtherUserId': '',
            'OtherCidrIp': '',
        }
        self.assertEqual(formatter.format_rule(Rule(rule_data)),
                         rule_fmt.format(**rule_data))

        rule_data['OtherUserId'] = self.good_account
        self.assertEqual(formatter.format_rule(Rule(rule_data)),
                         rule_fmt_with_acc.format(**rule_data))

        rule_data['OtherCidrIp'] = self.good_cidr
        rule_data['OtherGroupId'] = ''
        rule_data['OtherUserId'] = ''
        self.assertEqual(formatter.format_rule(Rule(rule_data)), rule_fmt.format(**rule_data))
