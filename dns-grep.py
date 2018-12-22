#!/usr/bin/env python3
#
#   Copyright 2018 Hakan Lindqvist <dnstools@qw.se>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#
# dns-grep.py filters DNS zone data in master file format
# and optionally projects records to a custom output format.
#
# Prerequisites:
# * Python (3?)
# * dnspython (http://www.dnspython.org/, typically installed from pip)
#
# Project home: https://github.com/hlindqvist/dnstools
#

import sys
import optparse
import re
from collections import namedtuple
from copy import copy
from pprint import pprint

import dns.zone
import dns.name
import dns.rdataclass
import dns.rdatatype


RRTuple = namedtuple('RRTuple', 'name, ttl, rrclass, rrtype, rdata')


def read_zone_from_stdin(zonename):
    return dns.zone.from_file(sys.stdin, origin = zonename, relativize=False, check_origin=False)


def get_value(o, path):
    path_components = path.split(".")
    
    for c in path_components:
        try:
            o = getattr(o, c)
        except AttributeError:
            return None

    return o


def filter_rrs(rds, must):
    for rd in rds:
        rr = RRTuple._make((rd[0], rd[1], dns.rdataclass.to_text(rd[2].rdclass), dns.rdatatype.to_text(rd[2].rdtype), rd[2]))
    
        if all([ f["comparer"](f["value"], str(get_value(rr, f["field"]))) for f in must ]): 
            yield rr


def project_rr(rr, template):
    def repl(match):
        return str(get_value(rr, match.group(1)))

    return(re.sub("{(.+?)}", repl, template))


def filter_dnssec(rds):
    for rd in rds:
        if rd[2].rdtype == dns.rdatatype.RRSIG or rd[2].rdtype == dns.rdatatype.NSEC or rd[2].rdtype == dns.rdatatype.NSEC3:
            continue

        yield rd


def verbose_print(rr):
    print("-" * 20)

    print("name = %s" % ( rr.name ))
    print("ttl = %s" % ( rr.ttl ))
    print("rrclass = %s" % ( rr.rrclass ))
    print("rrtype = %s" % ( rr.rrtype ))

    for attr in dir(rr.rdata):
        if attr[0] == "_":
            continue

        val = getattr(rr.rdata, attr)
        if callable(val):
            continue

        print("rdata.%s = %s" % (attr, str(val)))

    print("-" * 20)
        


def main():
    usage="Usage: %prog [OPTION]..."
    description="Filter DNS records from zone data on stdin, output results on stdout."
    epilog="""
Examples:

dig @nameserver example.com AXFR | dns-grep.py -f "name=~^www\." -f "rrtype==A"
cat db.example.com | dns-grep.py -o example.com -f "rrtype==MX" -t "{rdata.exchange}"

"""

    class DnsGrepOption (optparse.Option):
        def parse_filter(option, opt, value):
            comparers = { "==": lambda x, y: x == y,
                          "!=": lambda x, y: x != y,
                          "=~": lambda x, y: re.search(x, y) != None,
                          "!~": lambda x, y: re.search(x, y) == None }
            
            m = re.match("^(.+)([=!][=~])(.*)$", value)
            if (m):
                return { "field": m.group(1), "comparer": comparers[m.group(2)], "value": m.group(3) }

            raise optparse.OptionValueError("option %s: invalid filter value: %s" % (opt, value))

        TYPES = optparse.Option.TYPES + ("filter",)
        TYPE_CHECKER = copy(optparse.Option.TYPE_CHECKER)
        TYPE_CHECKER["filter"] = parse_filter
    
    parser = optparse.OptionParser(option_class=DnsGrepOption, usage = usage, description = description, epilog = epilog)
    parser.format_epilog = lambda formatter: epilog

    parser.add_option("-f", "--filter", action="append", type="filter", dest="filter",
                        help="""Filter specified on format <field><comparison><value>, 
                                available operators are ==, !=, =~, !~.
                                Eg 'name==example.com' or 'rdata.target=~^ns1'.
                                (Use -v for exploring available rdata subfields, or refer to the dnspython docs).""")
    parser.add_option("-t", "--output-template", action="store", type="string", dest="output_template", default="{name} {ttl} {rrclass} {rrtype} {rdata}",
                        help="""Project the resource records to a custom output format, field names inside {}.
                                Eg '{name}' or (the default) '{name} {ttl} {rrclass} {rrtype} {rdata}'.
                                (Use -v for exploring available rdata subfields, or refer to the dnspython docs).""")
    parser.add_option("-o", "--origin", action="store", type="string", dest="origin", default=".",
                        help="Origin to use when interpreting relative names. By default . (the root) is used.")
    parser.add_option("-s", "--include-dnssec", action="store_true", dest="include_dnssec", default=False,
                        help="Include RRSIG/NSEC/NSEC3 records. By default these are filtered out.")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False,
                        help="Verbose output, particularly helpful for field discovery purposes.")

    options, args = parser.parse_args()

    if len(args) != 0:
        parser.error("incorrect number of arguments")


    zone = read_zone_from_stdin(options.origin)
    rdatas = zone.iterate_rdatas()

    if not options.include_dnssec:
        rdatas = filter_dnssec(rdatas)

    matching = filter_rrs(rdatas, options.filter or [])

    for rr in matching:
        print(project_rr(rr, options.output_template))
        
        if options.verbose:
            verbose_print(rr)


if (__name__ == "__main__"):
    main()

