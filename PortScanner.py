# Python Port Scanner
# Created By: Abdallah Nour
# Check my GitHub: https://github.com/xAbdalla

from datetime import datetime
import socket
import sys
import re

# Potential logical ports that are the targets of cybercriminals.
critical_ports = {15: 'Netstat', 20: 'FTP', 21: 'FTP', 22: 'SSH',
                  23: 'Telnet', 25: 'SMTP', 50: 'IPSec', 51: 'IPSec',
                  53: 'DNS', 67: 'BOOTP', 69: 'TFTP', 79: 'TACACS+',
                  49: 'TACACS+', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3',
                  111: 'Port Map', 119: 'NNTP', 123: 'NTP', 137: 'NetBIOS',
                  138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP',
                  389: 'LDAP', 443: 'SSL/HTTPS', 554: 'SMB', 500: 'IPSec/ISAKMP',
                  520: 'RIP', 546: 'DHCP', 547: 'DHCP', 636: 'SLDAP',
                  1512: 'WINS', 1701: 'L2TP', 1720: '323', 1723: 'PPTP',
                  1812: 'RADIUS', 1813: 'RADIUS', 3389: 'RDP', 5004: 'RTP',
                  5005: 'RTP', 5060: 'SIP', 5061: 'SIP'}

try:
    f = open("critical_ports", "r")
    for line in f.readlines():
        if not line:
            continue
        ports = line.split()
        if len(ports) > 1 and ports[0].isdigit() and int(ports[0]) in range(0, 65536):
            critical_ports[int(ports[0])] = " ".join(ports[1:])
    f.close()
except:
    pass

well_known_ports = range(0, 1024)
registered_ports = range(1024, 49152)
dynamic_ports = range(49152, 65536)
open_ports = list()

socket_errors = {10013: "Permission denied.",
                 10035: "Resource temporarily unavailable.",
                 10050: "Network is down. check your connection.",
                 10051: "Target is unreachable. check your connection to the target.",
                 10060: "Timeout / Closed (Connection refused passively).",
                 10061: "Closed (Connection refused actively).",
                 10064: "The server is temporarily or permanently unreachable.",
                 10065: "The server is unreachable.",
                 }

try:
    f = open("socket_errors", "r")
    for line in f.readlines():
        if not line:
            continue
        errors = line.split()
        if len(errors) > 1 and errors[0].isdigit():
            socket_errors[int(errors[0])] = " ".join(errors[1:])
    f.close()
except:
    pass

stop_errors = [10050, 10051, 10064, 10065]

try:
    f = open("stop_errors", "r")
    for line in f.readlines():
        if not line:
            continue
        if len(line) > 0 and line.isdigit() and not (int(line) in stop_errors):
            stop_errors.append(int(line))
    f.close()
except:
    pass

def valid_ip(address):
    if not address == "":
        try:
            ip = socket.gethostbyname(address)
            socket.inet_aton(ip)
            return ip
        except socket.gaierror:
            print("Could not resolve the host.")
            return False
        except:
            return False
    else:
        return False


def valid_port(port):
    if port.isdigit() and int(port) in range(1, 65536):
        return int(port)
    elif re.match(r"^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])-" +
                  r"([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", port):
        FIRST_PORT = int(port.split("-")[0])
        LAST_PORT = int(port.split("-")[1])
        if FIRST_PORT > LAST_PORT:
            FIRST_PORT, LAST_PORT = LAST_PORT, FIRST_PORT
        return range(FIRST_PORT, LAST_PORT + 1)
    else:
        return None


def gethost(ip_address):
    try:
        host_info = socket.gethostbyaddr(ip_address)
        return host_info[0]
    except:
        return "Could not resolve hostname."


def checkport(ADDRESS, PORT):
    global open_ports
    try:
        open_ports
    except:
        open_ports = list()
    try:
        socket.setdefaulttimeout(1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        res = s.connect_ex((ADDRESS, PORT))
        if res == 0:
            print(f"Port {PORT} - Open", end="")
            open_ports.append(PORT)
            if PORT in critical_ports:
                print(f" (Critical - {critical_ports[PORT]})", end="")
            # if PORT in well_known_ports:
            #     print(" (Well Known Port).", end="")
            # elif PORT in registered_ports:
            #     print(" (Registered Port).", end="")
            # elif PORT in dynamic_ports:
            #     print(" (Dynamic Port).", end="")
            print()  # Newline
        elif res in socket_errors:
            print(f"Port {PORT} - {socket_errors[res]}")
            if res in stop_errors:
                input("Press ENTER to continue ...")
            pass
        else:
            print(f"Port {PORT} - Closed (Socket Error Code {res})")
            pass
        s.close()
    except Exception as error:
        print(f"Port {PORT} - Exception ({error})")
        input("Press ENTER to continue ...")
        return


def summary(open_ports):
    print("*=*" * 15)
    f = open("logs.txt", "w").close()
    f = open("logs.txt", "a")
    print("Summary of the Scanning: ", end="")
    f.write("Summary of the Scanning: ")
    if len(open_ports):
        if len(open_ports) > 1:
            print(f"There are {len(open_ports)} open ports.\n")
            f.write(f"There are {len(open_ports)} open ports.\n")
        else:
            print(f"There is {len(open_ports)} open port.\n")
            f.write(f"There is {len(open_ports)} open port.\n")
        for port in open_ports:
            print(f"Port {port}: ", end="")
            f.write(f"Port {port}: ")
            if port in well_known_ports:
                print("Well Known Port", end="")
                f.write("Well Known Port")
            elif port in registered_ports:
                print("Registered Port", end="")
                f.write("Registered Port")
            elif port in dynamic_ports:
                print("Dynamic Port", end="")
                f.write("Dynamic Port")
            if port in critical_ports:
                print(f" (Critical) - Service: {critical_ports[port]}", end="")
                f.write(f" (Critical) - Service: {critical_ports[port]}\n")
            print()
    else:
        print("Your ports are closed. sleep well.")
        f.write("Your ports are closed. sleep well.\n")
    print("*=*" * 15)
    f.close()


if len(sys.argv) in [2, 3]:
    if valid_ip(sys.argv[1]):
        ADDRESS = valid_ip(sys.argv[1])
    else:
        print("Invalid IPv4 Address.")
        exit()
    if len(sys.argv) == 3:
        PORT = valid_port(sys.argv[2])
        if PORT is None:
            print("Invalid Port number/range.")
            exit()
elif len(sys.argv) > 3:
    print("Invalid number or arguments.")
    exit()

print("*=*" * 15)
print("Python Port Scanner By: Abdalla NouR ...")
print("*=*" * 15)

try:
    ADDRESS
except NameError:
    ADDRESS = input("Enter the target IPv4/Domain: ")
    if ADDRESS == "":
        ADDRESS = '127.0.0.1'  # Loopback Address
    elif not valid_ip(ADDRESS):
        print("Invalid IPv4 Address.")
        exit()
    ADDRESS = valid_ip(ADDRESS)

try:
    PORT
except NameError:
    in_port = input("Enter the target Port/Ports range: ")
    PORT = valid_port(in_port)
    if in_port == "":
        PORT = range(1, 65536)
    elif PORT is None:
        print("Invalid Port number/range.")
        exit()

HOSTNAME = gethost(ADDRESS)

# print(ADDRESS, HOSTNAME, PORT)
# print(type(ADDRESS), type(HOSTNAME), type(PORT))

###############################################################################################

print(f"\nTarget IPv4: {ADDRESS}\t\t", end="")
print(f"Target Hostname: {HOSTNAME}\t\t", end="")
if isinstance(PORT, int):
    print(f"Target Port: {PORT}\t\t")
    p = f"Target Port: {PORT}"
elif isinstance(PORT, range):
    print(f"Target Ports: {PORT[0]}-{PORT[-1]}\t\t")
    p = f"Target Ports: {PORT[0]}-{PORT[-1]}"
input("Press ENTER to start ...")
print("*=*" * 15)

###############################################################################################
t1 = datetime.now().replace(microsecond=0)
print(f"Scanning {ADDRESS} --- Start Time: {t1}\n")

if isinstance(PORT, int):
    try:
        checkport(ADDRESS, PORT)
    except KeyboardInterrupt:
        print("Stopping the Scan Process ...")
    summary(open_ports)
elif isinstance(PORT, range):
    for port in PORT:
        try:
            checkport(ADDRESS, port)
        except KeyboardInterrupt:
            print("Stopping the Scan Process ...")
            break
    summary(open_ports)

t2 = datetime.now().replace(microsecond=0)
print(f"Finished Scanning {ADDRESS} --- End Time: {t2} --- Time Elapsed: {t2 - t1}\n")
with open('logs.txt', 'r') as f: data = f.read()
with open('logs.txt', 'w') as f: f.write(f"""Target IPv4: {ADDRESS}
Target Hostname: {HOSTNAME}
{p}
Start Time: {t1}
End Time: {t2}
Time Elapsed: {t2 - t1}
\n""" + data)

print("Thank you for using this script.")
print("Check my GitHub: https://github.com/xAbdalla")

