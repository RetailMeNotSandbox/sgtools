from __future__ import print_function
import re
import fileinput
from sgtools.utils import parse_cidr
import logging


HEXINT = re.compile('[0-9a-f]+')


def file_line(fileinput_obj):
    return "{} [{}]".format(fileinput_obj.filename(), fileinput_obj.filelineno())


###############################################################################
# Datatypes
###############################################################################


class Account(object):
    ACCT_ID = re.compile("[0-9]+")

    def __init__(self, value):
        if value != 'amazon-elb' and not self.ACCT_ID.match(value):
            raise ValueError("Invalid account number: {}".format(value))
        self.acct_id = value

    def __str__(self):
        return self.acct_id


class SecurityGroup(object):
    """Security Groups take the form [<account>/]<group-id>. Account must be
       a symbolic name registered with the Accounts collection."""
    SGID = re.compile("sg-[0-9a-f]{8}")

    def __init__(self, value, for_account, vars):
        self.account = None
        if '/' in value:
            account, value = value.split("/", 1)
            if account != for_account:
                self.account = vars.get(account)
                if not self.account or not isinstance(self.account, Account):
                    raise ValueError("'{}' is not a known account".format(account))

        if not self.SGID.match(value):
            raise ValueError("Invalid security group ID: {}".format(value))

        self.sgid = value

    def __str__(self):
        if self.account:
            return "/".join((str(self.account), self.sgid))
        else:
            return self.sgid


class Cidr(object):
    def __init__(self, value):
        addr_info = parse_cidr(value)
        if not addr_info:
            raise ValueError("Invalid CIDR: '{}'".format(value))
        for field, value in addr_info.items():
            setattr(self, field, value)

    def __str__(self):
        return "/".join((self.address, self.mask))


class Protocol(object):
    PROTO = re.compile("(tcp|udp|icmp|(-)?[0-9]+)")

    def __init__(self, value):
        parts = value.split()
        if len(parts) != 3:
            raise ValueError("Invalid protocol spec: {}".format(value))

        if not self.PROTO.match(parts[0]):
            raise ValueError("Invalid protocol: {}".format(parts[0]))

        for port in parts[1:]:
            try:
                int(port)
            except:
                raise ValueError("Invalid port number: {}".format(port))

        self.proto = parts[0]
        self.lport = parts[1]
        self.hport = parts[2]

    def __str__(self):
        return " ".join((self.proto, self.lport, self.hport))


class Rule(object):
    def __init__(self, line, variables):
        self.variables = variables
        parts = line.split()
        if not len(parts) == 4:
            raise ValueError("Malformed rule (wrong number of arguments)")
        self.direction = parts[0]
        self.owner = parts[1]
        self.other = parts[2]
        self.proto = parts[3]

    @property
    def direction(self):
        return self._direction

    @direction.setter
    def direction(self, value):
        if value not in ('in', 'out'):
            raise ValueError("Invalid direction '{}'. Must be either 'in' or "
                             "'out'.".format(value))
        self._direction = value

    @property
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, value):
        owner = self.variables.get(value)
        if not owner:
            raise ValueError("The security group {} is undefined".format(value))
        if not isinstance(owner, SecurityGroup):
            raise ValueError("The rule owner must be a security group, "
                             "not a {}".format(type(owner).__name__))
        self._owner = owner

    @property
    def other(self):
        return self._other

    @other.setter
    def other(self, value):
        other = self.variables.get(value)
        if not other:
            raise ValueError("The entity {} is undefined".format(value))
        if not isinstance(other, (SecurityGroup, Cidr)):
            raise ValueError("The rule owner must be a security group or CIDR, "
                             "not a {}".format(type(other).__name__))
        self._other = other

    @property
    def proto(self):
        return self._proto

    @proto.setter
    def proto(self, value):
        proto = self.variables.get(value)
        if not proto:
            raise ValueError("The entity {} is undefined".format(value))
        if not isinstance(proto, Protocol):
            raise ValueError("The rule proto must be a protocol, "
                             "not a {}".format(type(proto).__name__))
        self._proto = proto

    def __str__(self):
        return " ".join(map(str, (self.direction,
                                  self.owner,
                                  self.other,
                                  self.proto)))


###############################################################################
# Configuration Parsers
###############################################################################


class Parser(object):
    VARIABLE = re.compile('^[a-zA-Z][a-zA-Z0-9-_]*$')
    msgs = {
        'invalid_statement': "Statement is invalid",
        'invalid_type': "Invalid statement type: {}",
        'bad_variable': "Invalid variable name '{}' (must match '{}')",
        'reassign_fwd': "Variable '{}' has changed from '{}' to '{}'",
        'reassign_rev': "Reverse mapping of '{}' has changed from '{}' to '{}'",
    }

    def __init__(self, file_list, account=None):
        self.errors = []
        self.warnings = []
        self.log = logging.getLogger(__name__)
        self.input = fileinput.input(file_list)
        self.account = account
        self.variables = {}
        self.vars_reverse = {}
        self.rules = []
        self.parse()

    def _format_error_message(self, msg, msgargs):
        message = self.msgs.get(msg, msg).format(*msgargs)
        return "{} [{}]: {}".format(self.input.filename(),
                                    self.input.filelineno(),
                                    message)

    def warn(self, message, *msgargs):
        warning = self._format_error_message(message, msgargs)
        self.warnings.append(warning)
        self.log.warning(warning)

    def error(self, message, *msgargs):
        error = self._format_error_message(message, msgargs)
        self.errors.append(error)
        self.log.error(error)

    def clean_line(self, line):
        """Remove comments and trailing whitespace from a line, leaving only
           the variable definition (or an empty string)"""
        line = line.strip()
        if "#" in line:
            line = line.split("#", 1)[0]
        return line

    def parse(self):
        for line in self.input:
            line = self.clean_line(line).split(None, 1)
            if not line:
                continue
            if len(line) != 2:
                self.error('invalid_statement')
                continue

            handler = getattr(self, 'parse_{}'.format(line[0]), None)
            if not handler:
                self.error('invalid_type', line[0])
                continue
            handler(line[1])

    def _parsevar(self, stmt, var_class, *args):
        vardef = stmt.split(None, 1)
        if not len(vardef) == 2:
            self.error('invalid_statement')

        varname, value = vardef
        if not self.VARIABLE.match(varname):
            self.error('bad_variable', varname, self.VARIABLE.pattern)
            return
        try:
            variable = var_class(value, *args)
        except ValueError as e:
            self.error(e.message)
            return

        if varname in self.variables:
            self.warn('reassign_fwd', varname, self.variables[varname], value)
        self.variables[varname] = variable

        revname = str(variable)
        if revname in self.vars_reverse:
            self.warn('reassign_rev', revname, self.vars_reverse[revname], varname)
        self.vars_reverse[revname] = varname

    def parse_acct(self, stmt):
        self._parsevar(stmt, Account)

    def parse_sg(self, stmt):
        self._parsevar(stmt, SecurityGroup, self.account, self.variables)

    def parse_cidr(self, stmt):
        self._parsevar(stmt, Cidr)

    def parse_proto(self, stmt):
        self._parsevar(stmt, Protocol)

    def parse_rule(self, stmt):
        try:
            self.rules.append(Rule(stmt, self.variables))
        except ValueError as e:
            self.error(e.message)

    def dump(self, account):
        return "\n".join(map(str, self.rules))
