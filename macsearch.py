#!/usr/bin/python
#Copyright 2017 Krunoslav Pavic
import sys
import subprocess
import re
import time
import os
from datetime import datetime


VERSION = "MACsearch 1.1"

# Print formatting
CSI = "\x1B["
RESET = CSI + "0m"
UNDERLINE = CSI + '4m'
NORMAL = CSI + '0m'
GREY = CSI + '0;49;90m'
GREEN = CSI + '0;49;92m'
RED = CSI + '0;49;91m'
BLUE = CSI + '0;49;94m'
YELLOW = CSI + '0;49;93m'

# Set expired date
NEVER = datetime(
    *(time.strptime("2070/12/3123:59:59", "%Y/%m/%d%H:%M:%S")[0:6]))

UPPER = 'U'
LOWER = 'L'
DOT = 'D'
HYPEN = 'H'

oui_import = "Using OUI library"
try:
    from oui import oui_dict
except ImportError:
    oui_import = "Using local OUI information"
    oui_dict = {
        '001565': 'XIAMEN YEALINK',
        '7C2F80': 'Gigaset Communications',
        'E48D8C': 'Routerboard.com ',
        '4C5E0C': 'Routerboard.com ',
        'D4CA6D': 'Routerboard.com ',
        '000C42': 'Routerboard.com ',
        '0004F2': 'Polycom',
        '64167F': 'Polycom',
        '080023': 'Panasonic Communications',
        'B40EDC': 'LG-Ericsson Co.,Ltd.',
        '5404A6': 'ASUSTek COMPUTER',
        '00087B': 'RTX Telecom',
        '001827': 'NEC UNIFIED',
        '808287': 'ATCOM Technology',
        '000E08': 'Cisco-Linksys',
        '000ED7': 'Cisco Systems',
        '000E39': 'Cisco Systems',
        '000E84': 'Cisco Systems',
        '000ED6': 'Cisco Systems',
        '000E38': 'Cisco Systems',
        '000E83': 'Cisco Systems',
        'E8EDF3': 'Cisco Systems',
        '8843E1': 'Cisco Systems',
        '1CDF0F': 'Cisco Systems',
        '381C1A': 'Cisco Systems',
        'E02F6D': 'Cisco Systems',
        'C47295': 'Cisco Systems',
        '00024A': 'Cisco Systems',
        '0002BA': 'Cisco Systems',
        '00027D': 'Cisco Systems',
        '000216': 'Cisco Systems',
        '0002FC': 'Cisco Systems',
        '0002B9': 'Cisco Systems',
        '00027E': 'Cisco Systems',
        '00024B': 'Cisco Systems',
        '00023D': 'Cisco Systems',
        '0002FD': 'Cisco Systems',
        '000217': 'Cisco Systems',
        '887556': 'Cisco Systems',
        '346F90': 'Cisco Systems',
        'ACF2C5': 'Cisco Systems',
        '34DBFD': 'Cisco Systems',
        '54781A': 'Cisco Systems',
    }


def ext_command(cmd, args):
    p = subprocess.Popen([cmd, args], stdout=subprocess.PIPE)
    return p.communicate()[0]


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


def unique_dict(l):
    seen = set()
    new_l = []
    for d in l:
        t = tuple(d.items())
        if t not in seen:
            seen.add(t)
            new_l.append(d)
    return new_l


def find_duplicates(any_list):
    seen = set()
    seen2 = set()
    seen_add = seen.add
    seen2_add = seen2.add
    for item in any_list:
        if item in seen:
            seen2_add(item)
        else:
            seen_add(item)
    return list(seen2)


# Converts an IP address from its dotted-quad format to its
# 32 binary digit representation
def ip2bin(ip):
    b = ""
    in_quads = ip.split(".")
    out_quads = 4
    for q in in_quads:
        if q != "":
            b += dec2bin(int(q), 8)
            out_quads -= 1
    while out_quads > 0:
        b += "00000000"
        out_quads -= 1
    return b


# Converts a decimal number to binary representation
# if d is specified, left-pad the binary number with 0s to that length
def dec2bin(n, d=None):
    s = ""
    while n > 0:
        if n & 1:
            s = "1" + s
        else:
            s = "0" + s
        n >>= 1
    if d is not None:
        while len(s) < d:
            s = "0" + s
    if s == "": s = "0"
    return s


# Converts a binary string into an IP address
def bin2ip(b):
    ip = ""
    for i in range(0, len(b), 8):
        ip += str(int(b[i:i + 8], 2)) + "."
    return ip[:-1]


# Returns a list of IP addresses based on the CIDR block specified
def process_cidr(cidr):
    range_of_ips = []
    parts = cidr.split("/")
    base_ip = ip2bin(parts[0])
    subnet = int(parts[1])
    # if a subnet of 32 was specified simply return the single IP
    if subnet == 32:
        range_of_ips.append(bin2ip(base_ip))
    # for any other size subnet, return a list of IP addresses by concatenating
    # the prefix with each of the suffixes in the subnet
    else:
        ipPrefix = base_ip[:-(32 - subnet)]
        for i in range(2 ** (32 - subnet)):
            range_of_ips.append(bin2ip(ipPrefix + dec2bin(i, (32 - subnet))))

    return range_of_ips


# Pings all IPs in ip_full_list, returns list of available IPs
def ping_scan(ip_full_list, timeout="1", limiter=True):
    available_ips = []
    ping_results = {}
    overload = False

    if limiter:
        ip_sub_lists = [ip_full_list[x:x + 256] for x in
                       xrange(0, len(ip_full_list), 256)]
    else:
        ip_sub_lists = [ip_full_list[x:x + 1000] for x in
                       xrange(0, len(ip_full_list), 1000)]

    for ip_sublist in ip_sub_lists:
        if overload:
            break
        ip_results = {}
        for ip_addr in ip_sublist:
            try:
                cmd = 'exec /bin/ping -c 1 -W %s %s 2> /dev/null' % (timeout,
                                                                     str(ip_addr))
                ip_results[ip_addr] = subprocess.Popen([cmd], shell=True,
                                                       stdout=subprocess.PIPE,
                                                       close_fds=True)
                ping_results[ip_addr] = ""
            except OSError as e:
                overload = True
                # Try to close as many processes as possible
                for ip_addr, result in ip_results.items():
                    if result.poll is not None:
                        ping_results[ip_addr] = str(result.stdout.read())
                    try:
                        result.kill()
                    except AttributeError:
                        pass
                # Too many concurrent pings, exiting
                break

        while True:
            done = True

            for ip_addr, result in ip_results.items():
                if result.poll is None:
                    done = False
                else:
                    ping_results[ip_addr] = str(result.stdout.read())
                    try:
                        result.kill()
                    except AttributeError:
                        pass
            if done:
                break

    for ip_sublist in ip_sub_lists:
        for ip_addr in ip_sublist:
            if ping_results.get(ip_addr) and "0 received," not in \
                    ping_results[ip_addr] and "0 packets received," not in \
                    ping_results[ip_addr]:
                available_ips.append(ip_addr)

    return available_ips


# Ping sweep function - ping sweeps all interfaces and ips in supplied list
def ping_sweep(ip_list=None, timeout="1", limiter=True):
    possible_ips = []
    if ip_list is not None:
        possible_ips += ip_list

    try:
        int_list = ext_command("/sbin/ip", "addr").splitlines()
        limiter = False
    except OSError:
        int_list = ext_command("/bin/ip", "addr").splitlines()

    for int_addr in int_list:
        for ip_line in int_addr.splitlines():
            if "inet" in ip_line and "brd" in ip_line:
                cidr = ip_line.split("brd")[0].split()[1]

                if "127.0.0.1" in str(cidr):
                    continue

                ip_range = process_cidr(cidr)

                for ip in ip_range:
                    if ip != ip_range[0] and ip != ip_range[-1] and str(
                            ip) not in possible_ips:
                        possible_ips.append(str(ip))

    pingable_ips = ping_scan(possible_ips, timeout, limiter)
    if not pingable_ips:
        pingable_ips = ping_scan(possible_ips, timeout, limiter=True)

    return pingable_ips


class NetworkHost:
    def __init__(self, mac=None, ip=None, expires=None, manufacturer=None,
                 hostname=None, is_reachable=False, has_lease=False,
                 has_duplicate_ip=False):
        self.mac = mac
        self.ip = ip
        self.expires = expires
        self.manufacturer = manufacturer
        self.hostname = hostname
        self.is_reachable = is_reachable
        self.has_lease = has_lease
        self.has_duplicate_ip = has_duplicate_ip

    @property
    def json(self):
        return {'mac': self.mac,
                'ip': self.ip,
                'expires': self.expires,
                'manufacturer': self.manufacturer,
                'hostname:': self.hostname,
                'is_reachable': self.is_reachable}

    @property
    def lease_active(self):
        now = datetime.now()
        if self.expires is not None:
            return True if self.expires > now else False
        else:
            return False

    def matches_patterns(self, patterns, strict=False):
        for pattern in patterns:
            if strict:
                pattern = pattern.lower()
            else:
                pattern = re.sub('[:|-]', '', pattern).lower()

            if ((self.ip and pattern in self.ip) or
                (self.mac and pattern in self.mac) or
                (self.hostname and pattern in self.hostname.lower()) or
                (self.manufacturer and pattern in self.manufacturer.lower())):
                return True
        return False

    def format_mac(self, mac_format=LOWER):
        if self.mac:
            formatted_mac = self.mac
            if UPPER in mac_format:
                formatted_mac = formatted_mac.upper()
            if HYPEN in mac_format:
                t = iter(formatted_mac)
                formatted_mac = '-'.join(a+b for a,b in zip(t, t))
            elif DOT in mac_format:
                t = iter(formatted_mac)
                formatted_mac = ':'.join(a+b for a,b in zip(t, t))
            return formatted_mac
        else:
            return None

    def display(self, verbose=False, csv=False, delimiter=';',
                mac_format='LOWER'):
        if csv:
            return delimiter.join([self.ip or '',
                                   self.format_mac(mac_format) or '',
                                   self.hostname or '',
                                   self.manufacturer or '',
                                   self.expires or '',
                                   '1' if self.is_reachable else '0'])
        else:
            act_color = GREEN if self.lease_active else RED
            if self.has_lease:
                if verbose:
                    lease_info = str(self.expires)
                else:
                    lease_info = 'ACT' if self.lease_active else 'EXP'
            else:
                act_color = GREY
                lease_info = 'N/A'

            lease_display = '%s[ %s%s%s ]' % (NORMAL, act_color, lease_info,
                                              RESET)

            highlight = NORMAL if self.is_reachable else GREY

            host_info = '%-16s %-18s %-25s %-24s %-32s' % (self.ip or 'N/A',
                                                           self.format_mac(mac_format) or 'N/A',
                                                           self.hostname or 'N/A',
                                                           self.manufacturer or 'N/A',
                                                           lease_display)

            return '%s %s %s' % (highlight, host_info, RESET)


def macsearch(ping_check=True, arp_search=False, scan=False, sort_by_ip=False,
              patterns=None, timeout='1', network_scan=False):
    # Initialize lease dictionary and lists
    hosts = []
    patterns = patterns if patterns is not None else []
    reachable_ips = []

    dhcp = False
    dnsmasq = False
    leases = []

    # Getting list of dhcpd leases
    if os.path.exists("/var/lib/dhcpd/dhcpd.leases"):
        leases = ext_command("cat", "/var/lib/dhcpd/dhcpd.leases").split("}")
        dhcp = True
    elif os.path.exists("/var/log/dnsmasq.leases"):
        leases = ext_command("cat", "/var/log/dnsmasq.leases").splitlines()
        dnsmasq = True

    # Sort leases into host table - works with either DHCP or dnsmasq
    for lease in leases:
        lease_host = NetworkHost()
        if "lease" in lease and dhcp:
            lease = lease.splitlines()

            for line in lease:
                if "lease" in line:
                    lease_host.ip = line.split()[1]
                if "hardware ethernet" in line:
                    raw_mac = line.split()[2]
                    raw_mac = re.sub('[:]', '', raw_mac)
                    raw_mac = re.sub('[;]', '', raw_mac)
                    lease_host.mac = raw_mac.lower()
                if "hostname" in line:
                    lease_host.hostname = line.split()[1].strip('"').rstrip('";')
                if "ends" in line:
                    if "never" in line:
                        lease_host.expires = NEVER
                    else:
                        exp_date = line.split()[2]
                        exp_time = line.split()[3]
                        exp_time = re.sub('[;]', '', exp_time)
                        exp = exp_date + exp_time

                        try:
                            lease_host.expires = datetime.strptime(exp,
                                                                 "%Y/%m/%d%H:%M:%S")
                        except AttributeError:
                            lease_host.expires = datetime(
                                *(time.strptime(exp, "%Y/%m/%d%H:%M:%S")[0:6]))
            try:
                lease_host.manufacturer = oui_dict[lease_host.mac[:6].upper()]
            except KeyError:
                lease_host.manufacturer = None

        elif dnsmasq:
            lease = lease.split()

            raw_mac = lease[1]
            lease_host.mac = re.sub('[:]', '', raw_mac)
            lease_host.ip = lease[2]
            if lease[3] != "*":
                lease_host.hostname = lease[3]
            if lease[0] != "*":
                lease_host.expires = datetime.fromtimestamp(int(lease[0]))

            try:
                lease_host.manufacturer = oui_dict[lease_host.mac[:6].upper()]
            except KeyError:
                lease_host.manufacturer = None

        if lease_host.ip or lease_host.mac:
            lease_host.has_lease = True
            hosts.append(lease_host)

    if network_scan:
        ip_list = [h.ip for h in hosts]
        for pattern in patterns:
            try:
                ips_in_range = ping_scan(process_cidr(pattern), timeout)
                for ip_in_range in ips_in_range:
                    if ip_in_range not in ip_list:
                        hosts.append(NetworkHost(ip=ip_in_range,
                                                 is_reachable=True))
            except (IndexError, ValueError):
                # Pattern is not a valid CIDR
                pass

    # If scan option is enabled, scan all interfaces and fills the arp table
    if scan:
        ip_list = [h.ip for h in hosts]
        reachable_ips = ping_sweep([h.ip for h in hosts], timeout)
        for reachable_ip in reachable_ips:
            if reachable_ip not in ip_list:
                found_host = NetworkHost(ip=reachable_ip)
                hosts.append(found_host)

    # If arp option is enabled, check arp table for missing IP addresses,
    # update existing hosts with MAC addresses if missing
    if arp_search:
        mac_list = [h.mac for h in hosts]
        ip_list = [h.ip for h in hosts]
        try:
            arp_lines = ext_command("arp", "-an").splitlines()
            arp_success = True
        except OSError:
            arp_lines = ext_command("ip", "neighbour").splitlines()
            arp_success = False

        for arp_line in arp_lines:
            arp_host = NetworkHost()
            if arp_success:
                arp_host.ip = arp_line.split()[1][1:-1]
                raw_mac = arp_line.split()[3]
                arp_host.mac = re.sub('[:]', '', raw_mac).lower()
            else:
                arp_host.ip = arp_line.split()[0]
                try:
                    raw_mac = arp_line.split()[4]
                    arp_host.mac = re.sub('[:]', '', raw_mac).lower()
                except IndexError:
                    continue
            try:
                arp_host.manufacturer = oui_dict[arp_host.mac[:6].upper()]
            except KeyError:
                arp_host.manufacturer = None

            if arp_host.mac != "<incomplete>":
                if arp_host.ip in ip_list and arp_host.mac not in mac_list:
                    for test_host in hosts:
                        if arp_host.ip == test_host.ip:
                            test_host.mac = arp_host.mac
                            test_host.manufacturer = arp_host.manufacturer
                elif arp_host.mac not in mac_list or arp_host.ip not in ip_list:
                    hosts.append(arp_host)

    ip_list = [h.ip for h in hosts]
    reachable_ips = reachable_ips if scan else ip_list
    if ping_check:
        reachable_ips = ping_scan(ip_list, timeout)

    duplicate_ips = find_duplicates(ip_list)

    for host in hosts:
        if host.ip in reachable_ips:
            host.is_reachable = True
        if host.ip in duplicate_ips:
            host.has_duplicate_ip = True

    if sort_by_ip:
        sorted(hosts, key=lambda k: k.ip)
    else:
        sorted(hosts, key=lambda k: k.ip)

    return hosts


if __name__ == '__main__':
    patterns = []
    verbose = False
    ping_check = True
    mac_format = LOWER
    export = False
    arp_search = False
    scan = False
    sort_by_ip = False
    network_scan = False
    lease_count = 0
    active_count = 0
    sum_hosts = 0
    sum_avail = 0
    sum_unavail = 0
    timeout = '1'
    # Get search pattern if any
    for index, arg in enumerate(sys.argv):
        if index == 0:
            continue
        if arg.startswith('-'):
            if 'c' in arg:
                ping_check = False
            if 'a' in arg:
                arp_search = True
            if 't' in arg:
                timeout = '3'
            if 'v' in arg:
                verbose = True
            if 'e' in arg:
                export = True
            if 's' in arg:
                scan = True
                arp_search = True
                ping_check = False
            if 'u' in arg:
                mac_format += UPPER
            if 'd' in arg:
                mac_format += DOT
            if 'y' in arg:
                mac_format += HYPEN
            if 'i' in arg:
                sort_by_ip = True
            if 'n' in arg:
                network_scan = True
                arp_search = True
            if arg == '-h' or arg == '--help':
                print VERSION
                print 'Usage: macsearch [option(s)] [pattern(s)]'
                print ' Lists all dhcp leases and/or arp table members with following data: MAC address, IP address, hostname, manufacturer and expiry status of lease'
                print ' Checks if IP adresses are reachable by ping. Unreachable hosts are greyed out.'
                print ' Filters according to [pattern(s)]. Sorts by lease expiry.'
                print 'Options:'
                print ' -a      Search ARP table for addresses that are not in DHCP lease table'
                print ' -c      Do not CHECK if IP address is reachable by ping.'
                print ' -s      Ping SWEEP all directly connected subnets and known leases - fills ARP table and checks availability (slowest option)'
                print ' -n      Scan network(s) provided as pattern(s) in CIDR format (e.g 192.168.1.0/24)'
                print ' -t      Set TIMEOUT of all ping commands to 2 seconds instead of 1 (applies to -c and -s options)'
                print ''
                print ' -v      Set high VERBOSITY - display full hostnames, manufacturers, and end time of leases (instead of [ACT/EXP])'
                print ' -e      EXPORT all data in CSV form. If -c or -s options are used, a column with ping status [1/0] will be added'
                print ' -i      Sort by IP address instead of time of lease expiry'
                print ''
                print ' -u      Display MAC address in UPPERCASE'
                print ' -d      Display MAC address with \":\" (DOTS) every 2 characters'
                print ' -y      Display MAC address with \"-\" (HYPEN) every 2 characters'
                print ''
                raise SystemExit
        else:
            #arg = re.sub('[:|-]', '', arg).lower()
            patterns.append(arg)

    # Printing header
    if not export:
        print VERSION
        print oui_import
        if ping_check:
            print 'Checking address availability'
        if arp_search:
            print 'Checking arp table'
        if scan:
            print 'Scanning all available IP addresses'
        print ''
        print '%s %-16s %-18s %-25s %-24s %-32s %s' % (UNDERLINE, 'IP', 'MAC',
                                                       'HOSTNAME',
                                                       'MANUFACTURER',
                                                       'LEASE', RESET)
        print ''

    hosts = macsearch(scan=scan, ping_check=ping_check,
                      arp_search=arp_search, timeout=timeout,
                      sort_by_ip=sort_by_ip, patterns=patterns,
                      network_scan=network_scan)

    # Formatting and printing all available info
    if hosts:
        for host in hosts:
            if len(patterns) == 0 or host.matches_patterns(patterns) or network_scan:
                print host.display(verbose=verbose, csv=export,
                                   mac_format=mac_format)

    num_hosts_with_lease = len([h for h in hosts if h.has_lease])
    num_reachable_hosts = len([h for h in hosts if h.is_reachable])

    summary = 'Hosts: %s (%s leases)' % (str(len(hosts)),
                                         str(num_hosts_with_lease))
    if scan or ping_check:
        summary += ' - Available: %s, Unavaliable: %s' % (str(num_reachable_hosts),
                                                          str(len(hosts)))
    if not export:
        print ''
        print summary
        print ''
