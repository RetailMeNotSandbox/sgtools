import re

cidr_v4_re = re.compile("^(?P<address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})($|/(?P<mask>[0-9]{1,2})$)")


def copy_fields(src, dest, fields=None, dest_fields=None, defaults=None):
    """Copy the k/v pairs from one dict into another"""
    if not fields:
        fields = src.keys()
    if not dest_fields:
        dest_fields = fields
    if not defaults:
        defaults = {}
    for field, dest_field in zip(fields, dest_fields):
        value = src.get(field, None)
        if value is None:
            if field in defaults:
                dest[dest_field] = defaults[field]
        else:
            dest[dest_field] = value


def parse_cidr(addr_string):
    m = cidr_v4_re.match(addr_string.strip())
    if not m:
        return None
    addr_info = m.groupdict()
    if not addr_info['mask'] or int(addr_info['mask']) not in range(32):
        addr_info['mask'] = '32'
    # Provide a dotted representation of the subnet mask. You know, for kids.
    mask_val = int(addr_info['mask'])
    mask_segments = []
    while mask_val > 0:
        if mask_val > 8:
            mask_segments.append('255')
            mask_val -= 8
        else:
            mask_segments.append(str(int("1" * mask_val, 2)))
            mask_val = 0
    if len(mask_segments) < 4:
        mask_segments.extend(['0'] * (4 - len(mask_segments)))
    addr_info['mask_dotted'] = ".".join(mask_segments)
    return addr_info
