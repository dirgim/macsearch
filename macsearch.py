#!/usr/bin/python
import sys
import subprocess
import re
import time
import os
import datetime

VERSION = "MACsearch 1.0"

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

    if limiter:
        ip_sub_lists = [ip_full_list[x:x + 256] for x in
                       xrange(0, len(ip_full_list), 256)]
    else:
        ip_sub_lists = [ip_full_list[x:x + 1024] for x in
                       xrange(0, len(ip_full_list), 1024)]

    for ip_sublist in ip_sub_lists:
        ip_results = {}
        for ip_addr in ip_sublist:
            try:
                cmd = 'exec /bin/ping -c 1 -W %s %s 2> /dev/null' % (timeout, str(ip_addr))
                ip_results[ip_addr] = subprocess.Popen([cmd], shell=True,
                                                       stdout=subprocess.PIPE,
                                                       close_fds=True)
                ping_results[ip_addr] = ""
            except OSError:
                # Too many concurrent pings, exiting to try with limiter
                return False

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
            if "0 received," not in ping_results[ip_addr] and \
               "0 packets received," not in ping_results[ip_addr]:
                available_ips.append(ip_addr)

    return available_ips


# Ping sweep function - ping sweeps all connected interfaces
def ping_sweep(ip_addresses=None, timeout="1", limiter=True):
    if ip_addresses is None:
        ip_addresses = []

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
                            ip) not in ip_addresses:
                        ip_addresses.append(str(ip))

    pingable_ips = ping_scan(ip_addresses, timeout, limiter)
    if not pingable_ips:
        pingable_ips = ping_scan(ip_addresses, timeout, limiter=True)

    return pingable_ips


# Setting print formatting
CSI = "\x1B["
RESET = CSI + "0m"
UNDERLINE = '4m'
NORMAL = "0m"
UNREG = '0;49;90m'
GREEN = '0;49;92m'
RED = '0;49;91m'
BLUE = '0;49;94m'
YELLOW = '0;49;93m'

# Set expired date
SEVENTIES = datetime.datetime(
    *(time.strptime("1972/01/0123:59:59", "%Y/%m/%d%H:%M:%S")[0:6]))
THIRTIES = datetime.datetime(
    *(time.strptime("2030/12/3123:59:59", "%Y/%m/%d%H:%M:%S")[0:6]))

# Initialize lease dictionary and lists
lease_dict = {}
patterns = []
ip_list = []
pingable_ips = []

# Set flags and counters
lease_count = 0
active_count = 0
sum_hosts = 0
sum_avail = 0
sum_unavail = 0
timeout = "1"
dhcp = False
dnsmasq = False
verbose = False
ping_check = True
mac_upper = False
export = False
arp_search = False
scan = False
dotted = False
hyphenated = False
sort_by_ip = False

# Getting current date and time
today = datetime.datetime.now()

# Get search pattern if any
for index, arg in enumerate(sys.argv):
    if index == 0:
        continue
    if arg.startswith("-"):
        if "c" in arg:
            ping_check = False
        if "a" in arg:
            arp_search = True
        if "t" in arg:
            timeout = "2"
        if "v" in arg:
            verbose = True
        if "e" in arg:
            export = True
        if "s" in arg:
            scan = True
            arp_search = True
            ping_check = False
        if "u" in arg:
            mac_upper = True
        if "d" in arg:
            dotted = True
        if "y" in arg:
            hyphenated = True
        if "i" in arg:
            sort_by_ip = True
        if arg == "-h" or arg == "--help":
            print VERSION
            print "Usage: macsearch [option(s)] [pattern(s)]"
            print " Lists all dhcp leases and/or arp table members with following data: MAC address, IP address, hostname, manufacturer and expiry status of lease"
            print " Checks if IP adresses are reachable by ping. Unreachable hosts are greyed out."
            print " Filters according to [pattern(s)]. Sorts by lease expiry."
            print "Options:"
            print " -a      Search ARP table for addresses that are not in DHCP lease table"
            print " -c      Do not CHECK if IP address is reachable by ping."
            print " -s      Ping SWEEP all directly connected subnets and known leases - fills ARP table and checks availability (slowest option)"
            print " -t      Set TIMEOUT of all ping commands to 2 seconds instead of 1 (applies to -c and -s options)"
            print ""
            print " -v      Set high VERBOSITY - display full hostnames, manufacturers, and end time of leases (instead of [ACT/EXP])"
            print " -e      EXPORT all data in CSV form. If -c or -s options are used, a column with ping status [1/0] will be added"
            print " -i      Sort by IP address instead of time of lease expiry"
            print ""
            print " -u      Display MAC address in UPPERCASE"
            print " -d      Display MAC address with \":\" (DOTS) every 2 characters"
            print " -y      Display MAC address with \"-\" (HYPEN) every 2 characters"
            print ""
            raise SystemExit
    else:
        arg = re.sub('[:|-]', '', arg).lower()
        patterns.append(arg)

# Printing header
if not export:
    print VERSION
    print oui_import
    if ping_check:
        print "Checking address availability"
    if arp_search:
        print "Checking arp table"
    if scan:
        print "Scanning all available IP addresses"
    print ""
    print CSI + UNDERLINE + " IP               MAC                HOSTNAME                  MANUFACTURER             LEASE                    " + RESET
    print ""

# Getting list of dhcpd leases
if os.path.exists("/var/lib/dhcpd/dhcpd.leases"):
    leases = ext_command("cat", "/var/lib/dhcpd/dhcpd.leases").split("}")
    dhcp = True
elif os.path.exists("/var/log/dnsmasq.leases"):
    leases = ext_command("cat", "/var/log/dnsmasq.leases").splitlines()
    dnsmasq = True
else:
    leases = []

# Sorting lease and arp entries into dictionary
for lease in leases:
    lease_success = False
    if "lease" in lease and dhcp:
        lease = lease.splitlines()
        hostname = "N/A"
        manufacturer = "N/A"
        expires = SEVENTIES

        for line in lease:
            if "lease" in line:
                ip = line.split()[1]
            if "hardware ethernet" in line:
                mac = line.split()[2]
                mac = re.sub('[:]', '', mac)
                mac = re.sub('[;]', '', mac)
                mac = mac.lower()
            if "hostname" in line:
                hostname = line.split()[1].strip('"').rstrip('";')
            if "ends" in line:
                if "never" in line:
                    expires = THIRTIES
                else:
                    exp_date = line.split()[2]
                    exp_time = line.split()[3]
                    exp_time = re.sub('[;]', '', exp_time)
                    exp = exp_date + exp_time

                    try:
                        expires = datetime.datetime.strptime(exp,
                                                             "%Y/%m/%d%H:%M:%S")
                    except AttributeError:
                        expires = datetime.datetime(
                            *(time.strptime(exp, "%Y/%m/%d%H:%M:%S")[0:6]))
        try:
            manufacturer = oui_dict[mac[:6].upper()]
        except KeyError:
            manufacturer = "N/A"

        lease_success = True

    elif dnsmasq:
        lease = lease.split()
        hostname = "N/A"
        manufacturer = "N/A"
        expires = SEVENTIES

        mac = lease[1]
        mac = re.sub('[:]', '', mac)
        ip = lease[2]
        if lease[3] != "*":
            hostname = lease[3]
        if lease[0] != "*":
            expires = datetime.datetime.fromtimestamp(int(lease[0]))

        try:
            manufacturer = oui_dict[mac[:6].upper()]
        except KeyError:
            manufacturer = "N/A"

        lease_success = True

    if lease_success:
        # Filtering for patterns if supplied
        if len(patterns) > 0:
            for pattern in patterns:
                if pattern in mac or pattern in ip or pattern in hostname.lower() or pattern in manufacturer.lower():
                    lease_dict[mac] = [ip, expires, hostname, manufacturer]
                    ip_list.append(ip)
                    break
        else:
            lease_dict[mac] = [ip, expires, hostname, manufacturer]
            ip_list.append(ip)

sum_leases = len(lease_dict)

# If scan option is enabled, scans all interfaces and fills the arp table
if scan:
    arp_search = True
    ping_check = False
    pingable_ips = ping_sweep(ip_list, timeout)

if arp_search:
    try:
        arplist = ext_command("arp", "-an").splitlines()
        arp_success = True
    except OSError:
        arplist = ext_command("ip", "neighbour").splitlines()
        arp_success = False

    for macline in arplist:
        manufacturer = "N/A"
        hostname = "N/A"
        expires = SEVENTIES
        if arp_success:
            ip = macline.split()[1][1:-1]
            mac = macline.split()[3]
            mac = re.sub('[:]', '', mac).lower()
        else:
            ip = macline.split()[0]
            try:
                mac = macline.split()[4]
                mac = re.sub('[:]', '', mac).lower()
            except IndexError:
                continue

        try:
            manufacturer = oui_dict[mac[:6].upper()]
        except KeyError:
            manufacturer = "N/A"

        if mac != "<incomplete>":
            if mac not in lease_dict:

                # Filtering for patterns if supplied
                if len(patterns) > 0:
                    for pattern in patterns:
                        if pattern in mac or pattern in ip or pattern in manufacturer.lower():
                            lease_dict[mac] = [ip, expires, hostname,
                                               manufacturer]
                            ip_list.append(ip)
                            break
                else:
                    lease_dict[mac] = [ip, expires, hostname, manufacturer]
                    ip_list.append(ip)
            elif lease_dict[mac][0] != ip:
                if len(patterns) > 0:
                    for pattern in patterns:
                        if pattern in mac or pattern in ip or pattern in manufacturer.lower():
                            lease_dict[mac] = [ip, expires, hostname,
                                               manufacturer]
                            ip_list.append(ip)
                            break
                else:
                    lease_dict[mac] = [ip, expires, hostname, manufacturer]
                    ip_list.append(ip)

# Checking host availability (if -c option is not enabled)
if ping_check:
    pingable_ips = ping_scan(ip_list, timeout)  # Using only subproccess
elif not scan:
    pingable_ips = ip_list

if sort_by_ip:
    mac_list = sorted(lease_dict.keys(), key=lambda k: lease_dict[k][0])
else:
    mac_list = sorted(lease_dict.keys(), key=lambda k: lease_dict[k][1])

# Check for duplicate IP addresses
ip_list = [item[0] for item in lease_dict.values()]
ip_duplicates = find_duplicates(ip_list)

# Formatting and printing all available info
if mac_list:
    for mac in mac_list:
        info = lease_dict[mac]
        ip = info[0]
        expires = info[1]
        hostname = info[2]
        manufacturer = info[3]

        status = True
        act_color = GREEN
        sum_hosts += 1

        # Preparing lease expiry info, depending on verbosity
        if expires is not None and expires >= today:
            # if verbose:
            if True:
                active = str(expires)
            else:
                active = "ACT"

            if expires == THIRTIES:
                act_color = BLUE
        else:
            if expires == SEVENTIES:
                active = "N/A"
                act_color = UNREG
            else:
                # if verbose:
                if True:
                    active = str(expires)
                else:
                    active = "EXP"
                act_color = RED

        active_display = CSI + NORMAL + "[ " + CSI + act_color + active + RESET + " ]"

        # Checking if host is among pingable hosts
        if ping_check or scan:
            if ip not in pingable_ips:
                status = False
                sum_unavail += 1
            else:
                sum_avail += 1

        if ip in ip_duplicates:
            if status:
                ip = CSI + YELLOW + ip + RESET + (" " * (16 - len(ip)))
            else:
                ip = CSI + YELLOW + ip + CSI + UNREG + (" " * (16 - len(ip)))

        # Adjusting MAC address presentation
        if mac_upper:
            mac = mac.upper()

        if dotted and not hyphenated:
            t = iter(mac)
            mac = ':'.join(a + b for a, b in zip(t, t))

        if hyphenated:
            t = iter(mac)
            mac = '-'.join(a + b for a, b in zip(t, t))

        # Printing info depending on selected options
        if export:
            if ping_check or scan:
                print '%s;%s;%s;%s;%s;%s' % (
                ip, mac, hostname, manufacturer, active, str(int(status)))
            else:
                print '%s;%s;%s;%s;%s' % (ip, mac, hostname, manufacturer, active)
        elif status:
            print ' %-16s %-18s %-25s %-24s %-32s' % (ip, mac, hostname, manufacturer, active_display)
        else:
            print CSI + UNREG + ' %-16s %-18s %-25s %-24s %-32s' % (ip, mac, hostname, manufacturer, active_display) + RESET

# Printing summary
if not export:
    if not ping_check and not scan:
        if arp_search:
            print ""
            print "Hosts: " + str(sum_hosts) + "(" + str(
                sum_leases) + " leases)"
            print ""
        else:
            print ""
            print "Hosts: " + str(sum_hosts)
            print ""
    elif arp_search:
        print ""
        print "Hosts: " + str(sum_hosts) + "(" + str(
            sum_leases) + " leases) - Available: " + str(
            sum_avail) + ", Unavailable: " + str(sum_unavail)
    else:
        print ""
        print "Hosts: " + str(sum_hosts) + " - Available: " + str(
            sum_avail) + ", Unavailable: " + str(sum_unavail)

