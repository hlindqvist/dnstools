#!/usr/bin/env python
#
#   Copyright 2011-2012 Hakan Lindqvist <dnstools@qw.se>
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
# ddns-edit-zone.py is a tool for doing "traditional" editing of 
# DNS zone data via dynamic updates (RFC 2136).
#
# This tool will fetch the existing zone contents via AXFR (RFC 1034),
# save it to a regular "master" zone file (RFC 1035) which it opens in 
# your editor of choice.
# When said editor exits the updated file will be read and a dynamic 
# update generated based on the diff compared to the original file 
# contents.
# By default this dynamic update also includes the original SOA value
# in the prerequisite section as a safeguard in case of conflicting 
# changes.
#
# Notes:
# * If you update the SOA you must also update its serial manually.
# * You can not set different TTLs for records with the same owner
#   and rrtype combination (same RRset).
# * Use absolute names if specifying a new $ORIGIN value, currently (1.9.4)
#   dnspython does not appear to handle relative names for new origin
#   values correctly and affected records may end up out of zone(?).
#
# Prerequisites:
# 1) A TSIG key that allows you to perform AXFR and dynamic updates of
#    your zone.
# 2) The TSIG key must be provided in the form of a file with a single
#    KEY record (what dnssec-keygen(8) generates).
#    Alternatively the bind9 session key file can be used.
# 3) Python 2.6(?) or later
# 4) Dnspython (http://www.dnspython.org/) 1.9.0 or later
#    Please see this mail for a patch if you want to try using this
#    with version 1.8.0 of dnspython:
#    http://permalink.gmane.org/gmane.comp.python.dnspython.user/104
#
# Project home: https://github.com/hlindqvist/dnstools
#


import sys
import optparse
import os.path
import base64
import tempfile
import subprocess
import re

import dns.query
import dns.zone
import dns.update
import dns.tsigkeyring
import dns.name
import dns.rcode


def get_tsig_algorithm_name(algo):
    # Mapping between the algorithm id from the KEY record to the 
    # algorithm name, I did not find anything doing this in dnspython

    algorithms = { 157: "HMAC-MD5", 161: "HMAC-SHA1", 162: "HMAC-SHA224",
                   163: "HMAC-SHA256", 164: "HMAC-SHA384",
                   165: "HMAC-SHA512" }
    return algorithms.get(algo)


def get_default_editor():
    return (os.environ.get('DNSEDITOR') or os.environ.get('VISUAL') or
            os.environ.get('EDITOR') or 'vi')


def read_tsig_key_from_file(filename):
    key_zone = dns.zone.from_file(filename, origin = ".",
                                  check_origin = False, relativize = False)

    key = get_single_record(key_zone.iterate_rdatas(), dns.rdatatype.KEY)

    keyring = dns.tsigkeyring.from_text({ key[0].to_text(): 
                                          base64.b64encode(key[2].key) })
    keyalgo = get_tsig_algorithm_name(key[2].algorithm)

    return [keyring, keyalgo]


def read_tsig_key_from_session(filename):

    # Attempt to parse the bind session.key file.

    # Read the whole file (expected to be small).
    session_key_file = open(filename, "r")
    session_key = session_key_file.read()
    session_key_file.close()

    # Remove any comments.
    session_key = re.sub(re.compile(r'/\*.*?\*/', re.S), '', session_key)
    session_key = re.sub(re.compile(r'//.*$', re.M), '', session_key)
    session_key = re.sub(re.compile(r'#.*$', re.M), '', session_key)

    # Try to find the "key" statement and get the key_id and contents.
    m = re.search(r'(?:^|;)\s*key\s+((?:"[^"]+")|(?:[^"]\S*))\s*{(.*?)}\s*;',
                  session_key, flags = re.S)

    if (m is None):
        raise Exception('No "key" statement found in %(file)s.' %
                        { "file": filename })

    key_id = m.group(1).strip('"')
    key_contents = m.group(2)

    # Inside the key statement, try to find the "algorithm" value.
    m = re.search(r'(?:^|;)\s*algorithm\s+((?:"[^"]+")|(?:[^"]\S*))\s*;',
                  key_contents)

    if (m is None):
        raise Exception('No "algorithm" statement found inside the "key" \
statement in %(file)s.' % { "file": filename})

    keyalgo = m.group(1).strip('"')

    # Inside the key statement, try to find the "secret" value.
    m = re.search(r'(?:^|;)\s*secret\s+((?:"[^"]+")|(?:[^"]\S*))\s*;',
                  key_contents)

    if (m is None):
        raise Exception('No "secret" statement found inside the "key" \
statement in %(file)s.' % { "file": filename})

    secret = m.group(1).strip('"')

    keyring = dns.tsigkeyring.from_text({ key_id: secret })
    return [keyring, keyalgo]


def read_zone_via_axfr(serveraddress, zonename, keyring, keyalgo, timeout):
    return dns.zone.from_xfr(dns.query.xfr(serveraddress, zonename, 
                                           keyring = keyring,
                                           keyalgorithm = keyalgo,
                                           timeout = timeout))


def read_zone_from_file(filename, zonename):
    return dns.zone.from_file(filename, origin = zonename)


def write_zone_to_file(zone_file, zone, absolute_names):
    zone.to_file(zone_file, sorted = True, relativize = (not absolute_names))


def get_zone_diff(original_zone, updated_zone):
    original = list(original_zone.iterate_rdatas())
    updated = list(updated_zone.iterate_rdatas())

    added = filter(lambda record: record not in original, updated)
    removed = filter(lambda record: record not in updated, original)

    return [added, removed]


def get_single_record(rdatas, rdtype):
    records = filter(lambda record: record[2].rdtype == rdtype, rdatas)

    if (len(records) != 1):
        raise Exception("Expected exactly one record of type %(type)s \
but found %(count)d, aborting..." % 
                         { "type": dns.rdatatype.to_text(rdtype), 
                           "count": len(records) })
    return records[0]


def remove_dnssec_from_zone(zone):
    for record in list(zone.iterate_rdatas()):
        zone.delete_rdataset(record[0], dns.rdatatype.RRSIG,
                             covers=record[2].rdtype)
        zone.delete_rdataset(record[0], dns.rdatatype.NSEC)
        zone.delete_rdataset(record[0], dns.rdatatype.NSEC3)
        zone.delete_rdataset(record[0], dns.rdatatype.NSEC3PARAM)
        zone.delete_rdataset(record[0], dns.rdatatype.DNSKEY)


def generate_update_from_diff(zonename, original_zone, updated_zone,
                              keyring, keyalgo, force_conflicts):
    update = dns.update.Update(zonename, keyring = keyring,
                               keyalgorithm = keyalgo)

    if (not force_conflicts):
        # Require the old SOA to still be present
        # (Essentially requires that the zone hasn't changed while editing)
        oldsoa = get_single_record(original_zone.iterate_rdatas(), 
                                   dns.rdatatype.SOA)
        update.present(oldsoa[0], oldsoa[2])

    added, removed = get_zone_diff(original_zone, updated_zone)

    for (name, ttl, rdata) in removed:
        update.delete(name, rdata)

    for (name, ttl, rdata) in added:
        update.add(name, ttl, rdata)

    return [update, len(added), len(removed)]


def send_query(query, serveraddress, timeout):
    return dns.query.tcp(query, serveraddress, timeout = timeout)


def verbose_print(header, obj):
    print
    print header + ":"
    print "-" * 20
    print obj
    print "-" * 20


def clean_exit(filename):
    os.unlink(filename)
    exit(0)


def main():

    # Process command-line arguments

    usage = "Usage: %prog [OPTION]... NAMESERVER ZONENAME KEYFILE"

    description = "Edit ZONENAME hosted on NAMESERVER, authenticate AXFR and \
update request with the key from KEYFILE"

    epilog="The editor will be chosen based on the environment variables \
DNSEDITOR, VISUAL or EDITOR in that order or default to 'vi' if none of them \
were set. KEYFILE is expected to contain exactly one KEY record suitable for \
TSIG use (what dnssec-keygen(8) generates)"

    parser = optparse.OptionParser(usage = usage, description = description,
                                   epilog = epilog)

    parser.add_option("-a", "--absolute-names", action = "store_true",
                      dest = "absolute_names", default = False,
                      help = "use absolute names instead of names relative \
to zone apex")
    parser.add_option("-s", "--include-dnssec", action = "store_true",
                      dest = "include_dnssec", default = False,
                      help = "include RRSIG/NSEC/NSEC3/NSEC3PARAM/DNSKEY \
records when editing")
    parser.add_option("-c", "--force-conflicts", action = "store_true",
                      dest = "force_conflicts", default = False,
                      help = "apply local changes even if zone has been \
updated while editing")
    parser.add_option("-t", "--timeout", action = "store", type = "float",
                      dest = "timeout", default = 10,
                      help = "query timeout (in seconds), default value \
%default")
    parser.add_option("-l", "--use-session-key", action = "store_true",
                      dest = "use_session_key", default = False, 
                      help = "use bind9 session key")
    parser.add_option("--session-key-path", action = "store", 
                      dest = "session_key", 
                      default = "/var/run/named/session.key", 
                      help = "override path to bind9 session key, default \
value %default")
    parser.add_option("-q", "--quiet", action = "store_true", dest = "quiet",
                      default = False, help = "do not print status messages")
    parser.add_option("-v", "--verbose", action = "store_true",
                      dest = "verbose", default=False, help="print verbose \
messages suitable for troubleshooting")
    parser.add_option("--dry-run", action = "store_true", dest = "dry_run",
                      default = False, help = "do not actually send update")

    options, args = parser.parse_args()

    if ((not options.use_session_key and len(args) != 3)
        or (options.use_session_key and len(args) != 2)):
        parser.print_help();
        exit(-1)

    serveraddress = args[0]
    zonename = args[1]

    if (not options.use_session_key):
        keyring, keyalgo = read_tsig_key_from_file(args[2])
    else:
        keyring, keyalgo = read_tsig_key_from_session(options.session_key)

    editor = get_default_editor()



    # Fetch original zone data end put it in a temp file

    temp_file = tempfile.NamedTemporaryFile(delete = False)

    original_zone = read_zone_via_axfr(serveraddress, zonename, keyring,
                                       keyalgo, options.timeout)

    if (not options.include_dnssec):
        remove_dnssec_from_zone(original_zone)

    write_zone_to_file(temp_file, original_zone, options.absolute_names)

    temp_file.close()


    # Open temp file in editor

    subprocess.call([editor, temp_file.name])


    # Read back the updated zone data from temp file

    updated_zone = read_zone_from_file(temp_file.name, zonename)


    # Generate and send dynamic update based on zone changes

    update, num_added, num_removed = generate_update_from_diff(
                                                zonename, original_zone,
                                                updated_zone, keyring,
                                                keyalgo, 
                                                options.force_conflicts)

    if (num_added == 0 and num_removed == 0):
        if (not options.quiet):
            print "No changes detected."
        clean_exit(temp_file.name)

    if (not options.quiet):
        print ("Adding %(added)d records, deleting %(removed)d records." %
               { "added": num_added, "removed": num_removed })

    if (options.verbose):
        verbose_print("Request", update)

    if (options.dry_run):
        if (not options.quiet):
            print ("Dry run mode, exiting.")
        clean_exit(temp_file.name)

    response = send_query(update, serveraddress, options.timeout)

    if (options.verbose):
        verbose_print("Response", response)


    # Print summary of results

    if (not options.quiet):
        print ("Update sent. Return code: %(rcode)s" % 
               { "rcode": dns.rcode.to_text(response.rcode()) })
        print

    if (response.rcode() == dns.rcode.NXRRSET):
        print >> sys.stderr, "Error: It appears that the zone was updated \
while editing. Specify --force-conflicts on the command-line if you find this \
an acceptable risk."

    if (response.rcode() != dns.rcode.NOERROR):
        print >> sys.stderr, "Update failed, leaving temp file with your \
changes at: %(tempfile)s" % { "tempfile": temp_file.name }
        exit(1000 + response.rcode())


    # Clean up temp file and exit cleanly if we got this far

    clean_exit(temp_file.name)



if (__name__ == "__main__"):
    main()
