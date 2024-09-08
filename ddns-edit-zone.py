#!/usr/bin/env python3
#
#   Copyright 2011-2020 Hakan Lindqvist <dnstools@qw.se>
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
# 3) Python 3
# 4) Dnspython (http://www.dnspython.org/)
# 5) Click (https://click.palletsprojects.com/en/7.x/)
#
#
# Project home: https://github.com/hlindqvist/dnstools
#


import sys
import os.path
import tempfile
import subprocess
import re

import dns.query
import dns.zone
import dns.update
import dns.tsigkeyring
import dns.name
import dns.rcode
import dns.exception

import click


def get_tsig_algorithm_name(algo):
    # Mapping between the algorithm id from the KEY record to the
    # algorithm name, I did not find anything doing this in dnspython

    algorithms = {157: "HMAC-MD5.SIG-ALG.REG.INT",
                  161: "HMAC-SHA1",
                  162: "HMAC-SHA224",
                  163: "HMAC-SHA256",
                  164: "HMAC-SHA384",
                  165: "HMAC-SHA512"}
    return algorithms.get(algo)


def get_default_editor():
    return (os.environ.get('DNSEDITOR') or os.environ.get('VISUAL') or
            os.environ.get('EDITOR') or 'vi')


def get_default_session_key_path():
    return (os.environ.get("BIND_SESSION_KEY_PATH") or
            "/var/run/named/session.key")


def read_tsig_key_from_file(filename):
    # try to read either a tsig-keygen style or
    # (old) dnssec-keygen style file

    try:
        return read_tsig_key_from_keyfile(filename)
    except Exception:
        return read_tsig_key_from_configfile(filename)


def read_tsig_key_from_keyfile(filename):

    # Try to read a file with a DNS KEY record
    # (ie what dnssec-keygen produces)

    # Read the whole file (expected to be small).
    key_file = open(filename, "r")
    key = key_file.read()
    key_file.close()

    # Somewhat simplistic view of what a KEY record looks like
    # Dnspython removed KEY support as it's not really used in DNS itself
    m = re.search(
        r'^(\S+)\s+(?:\d+\s+)?IN\s+KEY\s+\d+\s+\d+\s+(\d+)\s+(.*)$', key,
        flags=re.M)

    if (m is None):
        raise Exception('No "KEY" record found in %(file)s.' %
                        {"file": filename})

    keyring = dns.tsigkeyring.from_text({m.group(1): m.group(3)})

    keyalgo = get_tsig_algorithm_name(int(m.group(2)))

    return [keyring, keyalgo]


def read_tsig_key_from_session(filename):
    return read_tsig_key_from_configfile(filename)


def read_tsig_key_from_configfile(filename):

    # Attempt to parse the bind config file.
    # (session file or tsig-keygen created key)

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
                  session_key, flags=re.S)

    if (m is None):
        raise Exception('No "key" statement found in %(file)s.' %
                        {"file": filename})

    key_id = m.group(1).strip('"')
    key_contents = m.group(2)

    # Inside the key statement, try to find the "algorithm" value.
    m = re.search(r'(?:^|;)\s*algorithm\s+((?:"[^"]+")|(?:[^"]\S*))\s*;',
                  key_contents)

    if (m is None):
        raise Exception('No "algorithm" statement found inside the "key" '
                        'statement in %(file)s.' % {"file": filename})

    keyalgo = m.group(1).strip('"')

    # Inside the key statement, try to find the "secret" value.
    m = re.search(r'(?:^|;)\s*secret\s+((?:"[^"]+")|(?:[^"]\S*))\s*;',
                  key_contents)

    if (m is None):
        raise Exception('No "secret" statement found inside the "key" '
                        'statement in %(file)s.' % {"file": filename})

    secret = m.group(1).strip('"')

    keyring = dns.tsigkeyring.from_text({key_id: secret})
    return [keyring, keyalgo]


def read_zone_via_axfr(serveraddress, zonename, keyring, keyalgo, timeout):
    return dns.zone.from_xfr(dns.query.xfr(serveraddress, zonename,
                                           keyring=keyring,
                                           keyalgorithm=keyalgo,
                                           timeout=timeout, lifetime=timeout,
                                           relativize=False),
                             relativize=False)


def read_zone_from_file(filename, zonename):
    return dns.zone.from_file(filename, origin=zonename, relativize=False)


def write_zone_to_file(zone_file, zone, absolute_names):
    zone.to_file(zone_file, sorted=True, relativize=(not absolute_names))


def get_zone_diff(original_zone, updated_zone):
    original = list(original_zone.iterate_rdatas())
    updated = list(updated_zone.iterate_rdatas())

    added = list(filter(lambda record: record not in original, updated))
    removed = list(filter(lambda record: record not in updated, original))

    return [added, removed]


def get_single_record(rdatas, rdtype):
    records = list(filter(lambda record: record[2].rdtype == rdtype, rdatas))

    if (len(records) != 1):
        raise Exception("Expected exactly one record of type %(type)s but "
                        "found %(count)d, aborting..." %
                        {"type": dns.rdatatype.to_text(rdtype),
                         "count": len(records)})
    return records[0]


def remove_dnssec_from_zone(zone, only_remove_sigs):
    for record in list(zone.iterate_rdatas()):
        zone.delete_rdataset(record[0], dns.rdatatype.RRSIG,
                             covers=record[2].rdtype)
        zone.delete_rdataset(record[0], dns.rdatatype.NSEC)
        zone.delete_rdataset(record[0], dns.rdatatype.NSEC3)
        if (not only_remove_sigs):
            zone.delete_rdataset(record[0], dns.rdatatype.NSEC3PARAM)
            zone.delete_rdataset(record[0], dns.rdatatype.DNSKEY)


def generate_update_from_diff(zonename, added, removed, oldsoa,
                              keyring, keyalgo, force_conflicts):

    update = dns.update.Update(zonename, keyring=keyring,
                               keyalgorithm=keyalgo)

    if (not force_conflicts):
        # Require the old SOA to still be present
        # (Essentially requires that the zone hasn't changed while editing)

        update.present(oldsoa[0], oldsoa[2])


    # RFC2136 has some unfortunate requirements regarding changes to the
    # apex NS RRset that we need to work around in one way or another:
    #
    # * The server must silently skip removing the last apex NS RR
    #   (even if the transaction has additions later on!)
    # * There is an asymmetry between additions and deletions, such that
    #   deletions cannot remove only a matching RR with a specific TTL
    #
    # So we face an issue where, depending on whether you do add,remove
    # or remove,add, you get one of these problems:
    # * TTL-only change of the RRSet deletes all but one NS RR
    # * changing RData of every NS leaves one of the old RDatas behind
    #
    # To work around this, when the apex NS RRSet is being edited,
    # we add a nonsense NS RR (pointing to invalid.) at the start
    # of the transaction, and then delete it again at the end.
    # This avoids the "skip removing last NS" from triggering, allowing
    # all our changes to complete, and the nonsense RR is removed as part
    # of the same transaction, so it should never be seen outside of the
    # UPDATE message itself.


    # start apex ns hack
    dns_zonename = dns.name.from_text(zonename)
    invalid_ns_rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, "invalid.")

    def is_apex_ns(rr):
        (name, ttl, rdata) = rr
        return name == dns_zonename and rdata.rdtype == dns.rdatatype.NS

    is_editing_apex_ns = any(is_apex_ns(x) for x in added) and any(is_apex_ns(x) for x in removed)

    if is_editing_apex_ns:
        update.add(dns_zonename, 1, invalid_ns_rdata)
    # end apex ns hack


    for (name, ttl, rdata) in removed:
        update.delete(name, rdata)

    for (name, ttl, rdata) in added:
        update.add(name, ttl, rdata)


    # start apex ns hack
    if is_editing_apex_ns:
        update.delete(dns_zonename, invalid_ns_rdata)
    # end apex ns hack

    return update


def send_query(query, serveraddress, timeout):
    return dns.query.tcp(query, serveraddress, timeout=timeout)


def print_rr_diff(added, removed):
    def make_rr_string(rr):
        return ("%(name)s %(ttl)d %(class)s %(type)s %(rdata)s" %
                {"name": str(rr[0]),
                 "ttl": rr[1],
                 "class": dns.rdataclass.to_text(rr[2].rdclass),
                 "type": dns.rdatatype.to_text(rr[2].rdtype),
                 "rdata": str(rr[2])})

    rrs = sorted(sorted([rr + ('-',) for rr in removed] +
                        [rr + ('+',) for rr in added],
                        key=lambda rr: rr[2].rdtype),
                 key=lambda rr: rr[0])

    for rr in rrs:
        print(rr[3] + " " + make_rr_string(rr))


def verbose_print(header, obj):
    print()
    print(header + ":")
    print("-" * 20)
    print(obj)
    print("-" * 20)


def cleanup_and_exit(filename, success, rcode=None):
    if success or click.confirm("Delete temporary file %(filename)s?" %
                                {"filename": filename}, default=True):
        os.unlink(filename)

    exit(0 if success else 1000 + rcode)


@click.command()
@click.option("-a", "--absolute-names", default=False, is_flag=True,
              help="use absolute names instead of names relative to zone apex")
@click.option("-S", "--include-dnssec-nonsigs", default=False, is_flag=True,
              help="include NSEC3PARAM/DNSKEY records when editing")
@click.option("-s", "--include-dnssec", default=False, is_flag=True,
              help="include RRSIG/NSEC/NSEC3/NSEC3PARAM/DNSKEY records when "
                   "editing")
@click.option("-c", "--force-conflicts", default=False, is_flag=True,
              help="apply local changes even if zone has been updated while "
                   "editing")
@click.option("-t", "--timeout", type=float, default=10,
              help="query timeout (in seconds)", show_default=True)
@click.option("-l", "--use-session-key", default=False, is_flag=True,
              help="use bind9 session key")
@click.option("--session-key-path",
              default=get_default_session_key_path(),
              help="override path to bind9 session key, also picked up from "
                   "environment BIND_SESSION_KEY_PATH", show_default=True,
              type=click.Path(exists=False))
@click.option("-q", "--quiet", default=False, is_flag=True,
              help="do not print status messages")
@click.option("-v", "--verbose", default=False, is_flag=True,
              help="print verbose messages suitable for troubleshooting")
@click.option("--dry-run", default=False, help="do not actually send update")
@click.argument('nameserver')
@click.argument('zonename')
@click.argument('keyfile', type=click.Path(exists=True), default=None,
                required=False)
def main(absolute_names, include_dnssec_nonsigs, include_dnssec,
         force_conflicts, timeout, use_session_key, session_key_path, quiet,
         verbose, dry_run, nameserver, zonename, keyfile):

    if (not use_session_key and not keyfile) or (use_session_key and keyfile):
        print("Either specify KEYFILE or use --use-session-key",
              file=sys.stderr)
        exit(-1)

    if (not use_session_key):
        keyring, keyalgo = read_tsig_key_from_file(keyfile)
    else:
        keyring, keyalgo = read_tsig_key_from_session(session_key_path)

    editor = get_default_editor()

    # Fetch original zone data end put it in a temp file

    temp_file = tempfile.NamedTemporaryFile(delete=False)
    original_zone = read_zone_via_axfr(nameserver, zonename, keyring,
                                       keyalgo, timeout)

    if (not include_dnssec):
        remove_dnssec_from_zone(original_zone, include_dnssec_nonsigs)

    write_zone_to_file(temp_file, original_zone, absolute_names)
    temp_file.close()

    edit_file_again = True
    while edit_file_again:
        # Open temp file in editor
        subprocess.call([editor, temp_file.name])

        try:
            # Read back the updated zone data from temp file
            updated_zone = read_zone_from_file(temp_file.name, zonename)
        except dns.exception.DNSException as ex:
            print("Error reading updated zone file!")
            print(ex)

            edit_file_again = click.confirm("Open file again for editing?",
                                            default=True)
            if edit_file_again:
                continue
            else:
                cleanup_and_exit(temp_file.name, False, 0)

        # Generate and send dynamic update based on zone changes
        added, removed = get_zone_diff(original_zone, updated_zone)

        if (len(added) == 0 and len(removed) == 0):
            if (not quiet):
                print("No changes detected.")
            cleanup_and_exit(temp_file.name, True)

        oldsoa = get_single_record(original_zone.iterate_rdatas(),
                                   dns.rdatatype.SOA)

        update = generate_update_from_diff(
            zonename, added,
            removed, oldsoa, keyring,
            keyalgo,
            force_conflicts)

        if (not quiet):
            print("Adding %(added)d records, deleting %(removed)d records." %
                  {"added": len(added), "removed": len(removed)})

            while True:
                action = click.prompt("Action: (a)pply changes? "
                                      "view (d)etails? "
                                      "(e)dit file again? "
                                      "(q)uit? ",
                                      type=click.Choice(["a", "d", "e", "q"]),
                                      default="d", show_choices=True)

                if action == "d":
                    print_rr_diff(added, removed)
                elif action == "e":
                    edit_file_again = True
                    break
                elif action == "a":
                    edit_file_again = False
                    break
                elif action == "q":
                    cleanup_and_exit(temp_file.name, False, 0)
                else:
                    raise Exception("Unknown action '%(action)s'" %
                                    {"action": action})

    if (verbose):
        verbose_print("Request", update)

    if (dry_run):
        if (not quiet):
            print("Dry run mode, exiting.")
        cleanup_and_exit(temp_file.name, True)

    response = send_query(update, nameserver, timeout)

    if (verbose):
        verbose_print("Response", response)

    # Print summary of results
    if (not quiet):
        print("Update sent. Return code: %(rcode)s" %
              {"rcode": dns.rcode.to_text(response.rcode())})
        print()

    if (response.rcode() == dns.rcode.NXRRSET):
        print("Error: It appears that the zone was updated while editing. "
              "Specify --force-conflicts on the command-line if you find this "
              "an acceptable risk.", file=sys.stderr)

    if (response.rcode() != dns.rcode.NOERROR):
        print("Update failed with return code: %(rcode)s" %
              {"rcode": dns.rcode.to_text(response.rcode())}, file=sys.stderr)

    # Clean up temp file and exit cleanly if we got this far
    cleanup_and_exit(temp_file.name, response.rcode() == dns.rcode.NOERROR,
                     response.rcode())


if (__name__ == "__main__"):
    main()
