%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
Security Group Management Rule Management in sgtools
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

Concepts
********

Security Groups rules in AWS have four basic components. In sgtools and this
documentation, we refer to them as follows:

* A *direction*, "in" (ingress) or "out" (egress)
* An *owner*, the group to whom the rule belongs
* An *other*, the subject of the rule, which may be a security group or CIDR
* A *portspec*, consisting of an IP protocol, low port, and high port

Included Tools
**************

sgtools includes two tools for managing security group rules: ``sgtables`` and
``sgmanager``.

``sgmanager`` is a higher-level tool used for managing more human-friendly rule
representations. ``sgmanager`` depends on ``sgtables`` to make changes in AWS.

``stgables`` is a low-level (*raw*) rule processor. It consumes and generates
basic rule definitions, and is capable of modifying rulesets in AWS.

These tools only manage security group *rules*. They do not create or remove
the groups themselves.

Using ``sgmanager``
*******************

.. hint::
    You can type ``sgmanager --help`` for detailed help about the ``sgmanager`` CLI.

There are currently three ``sgmanager`` subcommands:

* *groupdefs*, a tool for extracting group definitions in the ``sgmanager``
* format *render*, which accepts one or more configuration files and renders
  them to raw rules suitable for consumption by ``sgtables``
* *reverse*, which can help you convert ``sgtables`` output to a set of rules

When using ``sgmanager``, *vars_files* are files in the ``sgmanager``
configuration format as outlined below. *input_files* refer to files containing
raw rules as output by ``sgtables``.

.. hint::
    ``sgmanager`` configurations can be broken into several files for
    flexibility. Consider storing accounts, CIDRs, and portspecs separately
    from group definitions and rules.

``sgmanager`` Configuration
---------------------------

There are four entity types that can be defined in an sgmanager configuration:

* Rule - represents a single IpPermission on a SecurityGroup
* SecurityGroup - represents a single AWS SecurityGroup
* Cidr - An IPv4 CIDR address/mask
* Account - an AWS account


The syntax of an sgmanager configuration is::

    <rule>          ::= "rule " <Direction> " " <SecurityGroup:NAME> " " ( <SecurityGroup:NAME> | <Cidr:NAME> ) " " <PortSpec:NAME>

    <SecurityGroup> ::= "sg " NAME " " SG_ID

    <Cidr>          ::= "cidr " NAME " " IPADDR "/" INT_MASK
    
    <Account>       ::= "acct " NAME " " ACCOUNT_ID

    <PortSpec>      ::= "proto " NAME " " <Protocol> " " <Lport> " " <Hport>
    <Protocol>      ::= ( "icmp" | "tcp" | "udp" | -1 | 0 | POSITIVE_INTEGER )
    <Lport>         ::= -1 | 0 | POSITIVE_INTEGER
    <Hport>         ::= -1 | 0 | POSITIVE_INTEGER

Where:

* ``SG_ID`` is an AWS security group id
* ``IPADDR`` is an IPv4 address
* ``INT_MASK`` is an integer between 0 and 32 (inclusive)
* ``ACCOUNT_ID`` is an AWS numeric account ID

For port numbers, ``POSITIVE_INTEGER`` can be between 1 and 65535, and -1 means *all*.


Example
-------

Suppose you have a sgmanager configuration file named "myrules" containing the following::

    acct prd 11223344556677
    
    cidr prd-w1 10.208.0.0/16
    
    sg prd-w1-eop sg-12345678
    sg prd-w1-app sg-abcdef12
    
    proto ssh tcp 22 22
    
    rule in prd-w1-eop prd-w1-app ssh
    rule in prd-w1-eop prd-w1 ssh

Running ``sgmanager prd myrules`` would produce the following output::

    in sg-12345678 sg-abcdef12 tcp 22 22
    in sg-12345678 10.208.0.0/16 tcp 22 22

Using ``sgtables``
******************

.. hint::
    See the output of ``sgtables --help`` for complete, current information
    about available options.

``sgtables`` has four functions: *list*, *add*, *remove*, and *update*

``sgtables`` always requires an AWS profile (from ~/.aws/config), a region, and
a specific VPC to operate against (or the special name 'classic' for EC2
Classic). ``sgtables`` only operates on one network at a time. EC2 classic is
handled as its own network/VPC.

All data-modification commands (everything except *list*) accept a ``--noop``
argument (for no-op) that prevents any real changes from taking place. You can
use the ``--verbose`` flag to see more detail about the operations performed by
the command. ``--debug`` will also include low-level details.

The *add* command will try to add all rules passed to it (so long as the group
exists in the VPC). Similarly, *remove* will try to remove all rules passed to
it. You will be warned if the given rule already exists (for *add*) or if it is
not found (for *remove*), but this will not cause ``sgtables`` to fail.

*update* behaves somewhat differently than the other two. Before making changes,
*update* inspects the current ruleset and compares it to the input given. For
any security group **mentioned as an owner in the rules list**, rules are added
if needed, then rules are removed. To put it another way, *update* expects that
the rules passed to it are the **only** rules that should be in those groups.

*Mentioned*, in this context, means that any rule not listed as an owner in the
ruleset will not be updated. ``sgtables`` can update all rules in all security
groups in a VPC if passed the ominuously-named ``--obliterate`` flag to
*update*. When ``--obliterate`` is specified, ``sgtables`` assumes that the
rules given to it are the **only** rules that should exist in the VPC. If a
group exists but no rules are defined for it, that group will have all of its
rules removed.
