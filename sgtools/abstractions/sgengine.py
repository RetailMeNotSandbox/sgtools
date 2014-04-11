# -*- coding: iso-8859-15 -*-
"""Handling for raw EC2 security group rules"""

from sgtools import utils
from operator import itemgetter
from functools import total_ordering
import fileinput
import re


class InvalidRule(Exception):
    pass


class MultipleNameMatches(Exception):
    pass


# Module-level cache for group names. In a long-running process, this could be
# problematic as group names can change. When/if such an application arises,
# this simple dictionary-based cache should be replaced with one whose values
# can expire.
_groupname_cache = {}


def _prime_name_cache(aws):
    groups = aws.ec2.SecurityGroups.get()
    # add id => name mappings
    _groupname_cache.update(dict((g["GroupId"], g["GroupName"]) for g in groups if g["GroupName"]))

    # add name => id mappings
    group_names = {}
    for group in groups:
        group_names.setdefault(group["GroupName"], []).append(group["GroupId"])
    for group_name, group_ids in group_names:
        if len(group_ids) == 1:
            _groupname_cache[group_name] = group_ids[0]


def sgid_to_name(aws, group_id):
    """Find the group name for the given group ID"""
    global _groupname_cache
    if group_id not in _groupname_cache:
        groups = aws.ec2.SecurityGroups.get(filters={'group-id': group_id})
        if groups:
            _groupname_cache[group_id] = groups[0]['GroupName']
    return _groupname_cache.get(group_id, None)


def read_rules(filenames):
    rules = RuleSet()
    errors = []
    fmtr = RuleFormatter()
    for line in fileinput.input(filenames):
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                rules.add(fmtr.parse_string(line))
            except InvalidRule as e:
                errors.append(e)
    return rules, errors


def name_to_sgid(aws, name):
    """Find the group ID for the named security group. If more than one group
       matches, MultipleNameMatches is raised."""
    global _groupname_cache
    if name not in _groupname_cache:
        groups = aws.ec2.SecurityGroups.get(filters={'group-name': name})
        if groups:
            if len(groups) > 1:
                raise MultipleNameMatches("{} has more than one EC2 security group "
                                          "with the name '{}'".format(aws.region, name))
            _groupname_cache[name] = groups[0]['GroupId']
    return _groupname_cache.get(name, None)


class RuleFormatter(object):
    """Parse and format rules."""
    patterns = {'Direction': "(?P<Direction>in|out)",
                'Group': "(?P<Group>[^ ]+)",
                'Other': "(?P<Other>[^ ]+)",
                'IpProtocol': "(?P<IpProtocol>tcp|udp|icmp|[0-9-]+)",
                'FromPort': "(?P<FromPort>None|[0-9-]+)",
                'ToPort': "(?P<ToPort>None|[0-9-]+)"}
    default_format = "{Direction} {Group} {Other} {IpProtocol} {FromPort} {ToPort}"

    def __init__(self, for_account=None):
        self.account = for_account

    def parse_group(self, group):
        """Disassemble the other field into a dict of Rule fields."""
        return {"GroupId": group}

    def parse_other(self, other):
        """Disassemble the other field into a dict of Rule fields."""
        if utils.parse_cidr(other):
            return {"OtherCidrIp": other}
        else:
            before, sep, after = other.rpartition("/")
            if before and before != self.account:
                return {
                    'OtherUserId': before,
                    'OtherGroupId': after,
                }
            else:
                return {'OtherGroupId': after}

    def parse_string(self, rule_string, patt=default_format):
        """Create a Rule from a string"""
        rule_string = rule_string.strip()
        rule_re = re.compile(patt.format(**self.patterns))
        match = rule_re.match(rule_string)
        if not match:
            raise InvalidRule("Rule string format invalid: {}".format(rule_string))
        parts = match.groupdict()
        parts.update(self.parse_group(parts["Group"]))
        parts.update(self.parse_other(parts["Other"]))
        return Rule(**parts)

    def format_group(self, rule):
        """Assemble a group string using Rule fields."""
        return rule["GroupId"]

    def format_other(self, rule):
        """Assemble an other string using Rule fields."""
        other = rule.other()
        acct_prefix = "{}/".format(self.account)
        if other.startswith(acct_prefix):
            return other[len(acct_prefix):]
        return other

    def format_rule(self, rule, fmt=default_format):
        """Produce a string representation of a Rule"""
        rule['Group'] = self.format_group(rule)
        rule['Other'] = self.format_other(rule)
        return fmt.format(**rule)


@total_ordering
class Rule(dict):
    """A distinct security group rule. A Rule may have the following keys:
       - Direction
       - GroupId
       - OtherCidrIp
       - OtherGroupId
       - IpProtocol
       - FromPort
       - ToPort
    """
    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def update(self, *args, **kwargs):
        # force everything through __setitem__
        if len(args) > 1:
            raise TypeError("update expected at most 1 arguments, got {}".format(len(args)))
        other = dict(*args, **kwargs)
        for key in other:
            self[key] = other[key]

    @property
    def _key(self):
        gid = self["GroupId"]
        perm = (self["IpProtocol"], self["FromPort"], self["ToPort"])
        srcc = (self["Direction"], self.get("OtherCidrIp", ''))
        srcg = (self["Direction"], self.get("OtherGroupId", ''))
        return (gid, perm, srcc, srcg)

    def __lt__(self, other):
        # note that test coverage for this method is dependent on the operator
        # used in the test. Use < to keep your numbers up.
        return self._key < other._key

    def __le__(self, other):
        return self._key <= other._key

    def __eq__(self, other):
        # This implementation assumes that GroupId is unique across all
        # accounts in the region.
        #
        # GroupId is the canonical group-level identifier. Others are ignored:
        # - Description
        # - GroupName
        # - OwnerId
        # - VpcId
        #
        # OtherGroupId is the canonical other group identifier. Others are ignored:
        # - OtherUserId
        # - OtherGroupName
        return self._key == other._key

    def __hash__(self):
        return hash(self._key)

    def __setitem__(self, key, value):
        if key in ("FromPort", "ToPort"):
            value = int(value)
        protos = {
            '1': 'icmp',
            '6': 'tcp',
            '17': 'udp',
        }
        if key == 'IpProtocol':
            value = protos.get(value, value)
        super(Rule, self).__setitem__(key, value)

    def other(self):
        if "OtherCidrIp" in self and self["OtherCidrIp"]:
            return self['OtherCidrIp']
        else:
            if "OtherUserId" in self and self["OtherUserId"]:
                return "{}/{}".format(self['OtherUserId'], self['OtherGroupId'])
            else:
                return self['OtherGroupId']

    def proto_spec(self):
        return itemgetter("IpProtocol", "FromPort", "ToPort")(self)


class RuleSet(set):
    grp_flds = ('Description', 'GroupId', 'GroupName', 'OwnerId', 'VpcId')
    perm_flds = ('IpProtocol', 'FromPort', 'ToPort')
    perm_dft = {'FromPort': -1, 'ToPort': -1}
    othergrp_flds = ('UserId', 'GroupId', 'GroupName')
    othercidr_flds = ('CidrIp',)
    flat_othergrp_flds = list("Other" + f for f in othergrp_flds)
    flat_othercidr_flds = list("Other" + f for f in othercidr_flds)

    def add(self, rule):
        if not isinstance(rule, Rule):
            # coerce mapping types to Rules
            rule = Rule(rule)
        super(RuleSet, self).add(rule)

    def flatten_groups(self, groups):
        directional_lists = (("IpPermissions", "in"), ("IpPermissionsEgress", "out"))

        for group in groups:
            for perm_list, direction in directional_lists:
                for perm in group[perm_list]:
                    for other in perm['UserIdGroupPairs']:
                        rule = Rule(Direction=direction)
                        utils.copy_fields(group, rule, self.grp_flds)
                        utils.copy_fields(perm, rule, self.perm_flds, defaults=self.perm_dft)
                        utils.copy_fields(other, rule, self.othergrp_flds, self.flat_othergrp_flds)
                        self.add(rule)
                    for other in perm['IpRanges']:
                        rule = Rule(Direction=direction)
                        utils.copy_fields(group, rule, self.grp_flds)
                        utils.copy_fields(perm, rule, self.perm_flds, defaults=self.perm_dft)
                        utils.copy_fields(other, rule, self.othercidr_flds, self.flat_othercidr_flds)
                        self.add(rule)
        return self

    def render_groups(self):
        groups = []

        rules = sorted(list(self))

        # assumes sorting by these keys:
        # - GroupId
        # - (IpProtocol, FromPort, ToPort)
        # - (Direction, OtherGroupId)
        # - (Direction, OtherCidrIp)
        current_group = None
        current_perm = None
        for rule in rules:
            new_group = rule["GroupId"]
            if new_group != current_group:
                group = {}
                utils.copy_fields(rule, group, self.grp_flds)
                group['IpPermissions'] = []
                group['IpPermissionsEgress'] = []
                groups.append(group)
                current_group = new_group

            new_perm = (rule["IpProtocol"], rule["FromPort"], rule["ToPort"])
            if new_perm != current_perm:
                perm = dict(zip(self.perm_flds, new_perm))
                perm['IpRanges'] = []
                perm['UserIdGroupPairs'] = []
                if rule["Direction"] == "in":
                    group['IpPermissions'].append(perm)
                else:
                    group['IpPermissionsEgress'].append(perm)
                current_perm = new_perm

            if "OtherCidrIp" in rule:
                perm['IpRanges'].append({"CidrIp": rule['OtherCidrIp']})
            else:
                group = {}
                utils.copy_fields(rule, group, self.flat_othergrp_flds, self.othergrp_flds)
                perm['UserIdGroupPairs'].append(group)

        return groups
