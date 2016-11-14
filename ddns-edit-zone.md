# ddns-edit-zone.py

This tool will fetch the existing zone contents via AXFR (RFC 1034), save it to a regular "master" zone file (RFC 1035) which it opens in your editor of choice.  
When said editor exits the updated file will be read and a dynamic update (RFC 2136) generated based on the diff compared to the original file
contents.  
By default this dynamic update also includes the original SOA value in the prerequisite section as a safeguard in case of conflicting changes.


## Installing prerequisites

Ensure you have a python installation with dnspython.

### Examples using packaged versions

Debian/Ubuntu:

    # apt-get install python-dnspython

RHEL/Centos/Fedora:

    # yum install python-dns

    # dnf install python2-dns

FreeBSD:

    # pkg install py27-dnspython

Pkgin/pkgsrc based (NetBSD, SmartOS, OSX*, ...):

    # pkgin install py27-dns

    # pkg_add py27-dns

### Example using pip

Using pip:

    # pip install dnspython


## Set up TSIG-based AXFR and dynamic update access.

Ensure that the nameserver is capable of supporting TSIG, AXFR and Dynamic Updates (RFC2136).

After that it essentially comes down to:
* Setting up a TSIG key
* Allowing AXFR and dynamic updates access for this key


### Example with BIND 9:

Use [`dnssec-keygen`](http://ftp.isc.org/isc/bind9/cur/9.11/doc/arm/man.dnssec-keygen.html) to generate a TSIG key:

    $ dnssec-keygen -a HMAC-SHA256 -b 256 -n USER my-key
    Kmy-key.+163+57361
    $ cat Kmy-key.+163+57361.key
    my-key. IN KEY 0 3 163 L/FTU92hSZGjkRtaHIBbWuUkUFyoPY2wT4hAmkx1syk=
    $

In [`named.conf`](http://ftp.isc.org/isc/bind9/cur/9.11/doc/arm/Bv9ARM.ch06.html):

    key my-key. {
        algorithm HMAC-SHA256;
        secret "L/FTU92hSZGjkRtaHIBbWuUkUFyoPY2wT4hAmkx1syk=";
    };

    zone example.com {
        type master;
        file "/var/lib/named/db.example.com";
        allow-transfer { key my-key.; };
        update-policy { grant my-key. zonesub any; };
    };


### Example with PowerDNS authoritative 4:

> Note: pdns-auth 4 provides [`pdnsutil edit-zone`](https://doc.powerdns.com/md/manpages/pdnsutil.1/) which provides similar end-results if your goal is local editing.

In [`pdns.conf`](https://doc.powerdns.com/md/authoritative/settings/):

    dnsupdate=yes

Use [`pdnsutil`](https://doc.powerdns.com/md/manpages/pdnsutil.1/) to generate a key and configure key-based authentication:

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

    $ ./ddns-edit-zone.py -h
    Usage: ddns-edit-zone.py [OPTION]... NAMESERVER ZONENAME KEYFILE
    
    Edit ZONENAME hosted on NAMESERVER, authenticate AXFR and update request with
    the key from KEYFILE
    
    Options:
      -h, --help            show this help message and exit
      -a, --absolute-names  use absolute names instead of names relative to zone
                            apex
      -S, --include-dnssec-nonsigs
                            include NSEC3PARAM/DNSKEY records when editing
      -s, --include-dnssec  include RRSIG/NSEC/NSEC3/NSEC3PARAM/DNSKEY records
                            when editing
      -c, --force-conflicts
                            apply local changes even if zone has been updated
                            while editing
      -t TIMEOUT, --timeout=TIMEOUT
                            query timeout (in seconds), default value 10
      -l, --use-session-key
                            use bind9 session key
      --session-key-path=SESSION_KEY
                            override path to bind9 session key, default value
                            BIND_SESSION_KEY_PATH or /var/run/named/session.key
      -q, --quiet           do not print status messages
      -v, --verbose         print verbose messages suitable for troubleshooting
      --dry-run             do not actually send update
    
    The editor will be chosen based on the environment variables DNSEDITOR, VISUAL
    or EDITOR in that order or default to 'vi' if none of them were set. KEYFILE
    is expected to contain exactly one KEY record suitable for TSIG use (what
    dnssec-keygen(8) generates)

Specifying a key file on the command line:

    $ ./ddns-edit-zone.py ns.example.com example.com ~/keys/Kedit-zone.+161+38418.key


Using the BIND [session key](http://ftp.isc.org/isc/bind9/cur/9.11/doc/arm/Bv9ARM.ch06.html#dynamic_update_policies) locally (predefined TSIG key):

    $ ./ddns-edit-zone.py ns.example.com example.com -l
