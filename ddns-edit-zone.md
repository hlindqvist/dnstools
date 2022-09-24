# ddns-edit-zone.py

This tool allows you to use an "edit the zone file" workflow for a nameserver where you have dynamic update
access (+ AXFR access).

The tool will fetch the existing zone contents via AXFR (RFC 1034), save it to a regular "master" zone file (RFC 1035) which it opens in your editor of choice for editing.  
When said editor exits the updated file will be read and a dynamic update (RFC 2136) generated based on the diff compared to the original file contents.  
By default this dynamic update also includes the old SOA value as a prerequisite for the update, as a safeguard in case of conflicting changes happening in parallel (this may or may not fit your workflow).

## Download

Get the current version of the [ddns-edit-zone.py script](https://raw.githubusercontent.com/hlindqvist/dnstools/master/ddns-edit-zone.py).

## Installing prerequisites

Ensure you have a python3 installation with [dnspython](http://www.dnspython.org/) and
[click](https://click.palletsprojects.com/en/7.x/).

### Examples using packaged versions of prerequisites

Debian/Ubuntu:

    # apt-get install python3-dnspython python3-click

RHEL/Centos/Fedora:

    # yum install python3-dns python3-click

### Example using pip to install the prerequisites

Using pip:

    # pip install dnspython click


## Set up TSIG-based AXFR and dynamic update access.

Ensure that the nameserver is capable of supporting TSIG, AXFR and Dynamic Updates (RFC2136).

After that it essentially comes down to:
* Setting up a TSIG key
* Allowing AXFR and dynamic updates access for this key


### Example with BIND 9:

Use [`tsig-keygen`](https://bind9.readthedocs.io/en/latest/manpages.html#tsig-keygen-tsig-key-generation-tool) to generate a TSIG key:

    $ tsig-keygen my-key
    key "my-key" {
        algorithm hmac-sha256;
        secret "L/FTU92hSZGjkRtaHIBbWuUkUFyoPY2wT4hAmkx1syk=";
    };
    $

Also save this to a file (eg dnsedit.key) with restrictive permissions.

In [`named.conf`](https://bind9.readthedocs.io/en/latest/reference.html):

    key "my-key" {
        algorithm hmac-sha256;
        secret "L/FTU92hSZGjkRtaHIBbWuUkUFyoPY2wT4hAmkx1syk=";
    };

    zone example.com {
        type master;
        file "/var/lib/named/db.example.com";
        allow-transfer { key my-key.; };
        update-policy { grant my-key. zonesub any; };
    };


### Example with PowerDNS authoritative 4:

> Note: PowerDNS authoritative 4.x provides [`pdnsutil edit-zone`](https://doc.powerdns.com/authoritative/manpages/pdnsutil.1.html) which provides similar end-results if your goal is local editing.

In [`pdns.conf`](https://doc.powerdns.com/authoritative/settings.html):

    dnsupdate=yes

Use [`pdnsutil`](https://doc.powerdns.com/authoritative/manpages/pdnsutil.1.html) to generate a key and configure key-based authentication:

    # pdnsutil generate-tsig-key my-key hmac-sha256
    Generating new key with 64 bytes (this can take a while)
    Create new TSIG key my-key hmac-sha256 JNWyqXwYMHs/tcbUp4rPxwZQUcumosC1fdzK84/2kbdzbCoYQuNMq7Sr0dSM/9YwLspga28kHlLmhFZVWielUw==
    # pdnsutil set-meta example.com TSIG-ALLOW-AXFR my-key
    Set 'example.com' meta TSIG-ALLOW-AXFR = my-key
    # pdnsutil set-meta example.com TSIG-ALLOW-DNSUPDATE my-key
    Set 'example.com' meta TSIG-ALLOW-DNSUPDATE = my-key
    #

(If you want to create a key file based on the generate-tsig-key output, it would be in the format from the BIND section.)


## Run the script

To get the list of command-line options:

    $ ./ddns-edit-zone.py --help
    Usage: ddns-edit-zone.py [OPTIONS] NAMESERVER ZONENAME [KEYFILE]
    
    Options:
      -a, --absolute-names          use absolute names instead of names relative
                                    to zone apex
      -S, --include-dnssec-nonsigs  include NSEC3PARAM/DNSKEY records when editing
      -s, --include-dnssec          include RRSIG/NSEC/NSEC3/NSEC3PARAM/DNSKEY
                                    records when editing
      -c, --force-conflicts         apply local changes even if zone has been
                                    updated while editing
      -t, --timeout FLOAT           query timeout (in seconds)  [default: 10]
      -l, --use-session-key         use bind9 session key
      --session-key-path PATH       override path to bind9 session key, also
                                    picked up from environment
                                    BIND_SESSION_KEY_PATH  [default:
                                    /var/run/named/session.key]
      -q, --quiet                   do not print status messages
      -v, --verbose                 print verbose messages suitable for
                                    troubleshooting
      --dry-run BOOLEAN             do not actually send update
      --help                        Show this message and exit.


Specifying a key file on the command line:

    $ ./ddns-edit-zone.py 192.0.2.7 example.com ~/keys/dnsedit.key


Using the BIND [session
key](https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-session-keyfile) locally (predefined TSIG key):

    $ ./ddns-edit-zone.py 192.0.2.7 example.com -l
