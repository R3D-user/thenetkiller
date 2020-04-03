#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Coded By R3D
#2020/22/მარტი

import sys
import os
import signal
import subprocess
from threading import Thread
from time import sleep
import datetime
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 

# terminal colors
RED = "\033[1;31m"  
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
YELLOW = "\33[1;93m"
NORMAL = "\033[0;0m"
BOLD = "\033[;1m"

#შემოწმების ფუნქციები]
if os.getenv("SUDO_USER"):
    pass
else:
    sys.exit("პროგრამა მოითხოვს ადმინისტრატორის პრივილეგიებს გამოიყენე ბრძანება sudo")

def auto_installer():
    print("[-] მოდულები ვერ მოიძებნა.")
    if sys.version > '3':
        pretext = 'pip3'
        inst = input("გსურს ავტომატურად დაყენდეს ყველა მოდული? (კი/არა): ")
    else:
        pretext = 'pip'
        inst = raw_input("გსურს ავტომატურად დაყენდეს ყველა მოდული? (კი/არა): ")

    if inst in ('კ', 'კი'):
        import subprocess
        print("[*] მიმდინარეობს მოდულების ინსტალაცია, გთხოვთ მოიცადოთ...")
        subprocess.call(pretext+" install netifaces", shell=True)
        subprocess.call("apt-get install python-scapy -y > {}".format(os.devnull), shell=True)
        subprocess.call("apt-get install python-nmap -y > {}".format(os.devnull), shell=True)
        subprocess.call("apt-get install python-nfqueue -y > {}".format(os.devnull), shell=True)
        sys.exit("\n[+] მოდულები დაყენებულია.\n")
    sys.exit(0)

try:
    import netifaces
    from scapy.all import *
    import nfqueue
    import nmap
except ImportError:
    auto_installer()
#შემოწმების ფუნქციები END

from src import *
def get_option():
    '''
    Handling the user's input
    '''
    while True:
        raw_option = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED)).lower()
        if raw_option == "განმარტება":
            return raw_option

        try:
            option = int(raw_option)
        except ValueError:
            print("{R}ERROR: ფუნქცია არასწორია.{N}".format(R=RED, N=NORMAL))
            continue

        if 0 < option <= 12:
            return option
        else:
            print("{R}ERROR: ფუნქცია არასწორია.{N}".format(R=RED, N=NORMAL))
            continue

def handle_option(option):
    '''
    Assgning functions depending on what the user chose
    '''
    if option == 1:
        host_scan(False)
    if option == 2:
        host_scan(True)
    if option == 3:
        arp_kick()
    if option == "განმარტება":
        printings.print_help()

def clear_screen():
    '''
    Simply calling 'clear'''
    subprocess.call("sudo clear", shell=True)

def get_interface():
    clear_screen()

    print("{Y}აირჩიე ქსელის ინტერფეისი:\n{N}".format(Y=YELLOW, N=NORMAL))

    available_interfaces = netifaces.interfaces()

    for x in range(len(available_interfaces)):
        print("   {N}[{R}{num}{N}] {iface}".format(N=NORMAL, R=RED, num=x+1, iface=available_interfaces[x]))

    print("\n")

    while True:
        raw_interface = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED))

        try:
            interface = int(raw_interface)
        except ValueError:
            print("{R}ERROR: გთხოვ აირჩიე ციფრი.{N}".format(R=RED, N=NORMAL))
            continue

        if 0 < interface <= len(available_interfaces):
            return available_interfaces[interface-1]
        else:
            print("{R}ERROR: არასწორი ციფრი.{N}".format(R=RED, N=NORMAL))

def enable_mon_mode(interface):
    # enable monitoring mode to capture and send packets

    try:
        subprocess.call("sudo ip link set {} down".format(interface), shell=True)
        mon = subprocess.Popen(["sudo", "iwconfig", interface, "mode", "monitor"], stderr=subprocess.PIPE)
        for line in mon.stderr:
            if "Error" in line:
                sys.exit("\n{R}არჩეული ინტერფეისი არ არის სწორი.{N}\n".format(R=RED, N=NORMAL))

        subprocess.call("sudo ip link set {} up".format(interface), shell=True)
    except Exception:
        sys.exit("\n{R}ERROR: შეუძლებელია გააქტიურდეს მონიტორინგი არჩეულ ინტერფეისზე.{N}\n".format(R=RED, N=NORMAL))

def enable_ip_forwarding():
    ipfwd = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipfwd.write('1\n')
    ipfwd.close()

def disable_ip_forwarding():
    ipfwd = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipfwd.write('0\n')
    ipfwd.close()

def get_gateway_ip():
    # get the 'default' gateway

    try:
        return netifaces.gateways()['default'][netifaces.AF_INET][0]
    except KeyError:
        print("\n{R}ERROR: IP-ის დადგენა ვერ მოხერხდა.\n{N}".format(R=RED, N=NORMAL))
        return raw_input("გთხოვ მიუთითე IP ხელით: ")

def get_local_ip(interface):
    try:
        local_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        if local_ip == "127.0.0.1" or local_ip == "ff:ff:ff:ff:ff:ff":
            sys.exit("\n{R}ERROR: არასწორი ინტერფეისი.{N}\n".format(R=RED, N=NORMAL))
        return local_ip
    except KeyError:
        print("\n{R}ERROR: შიდა IP-ის დადგენა ვერ მოხერხდა.{N}\n")
        return raw_input("გთხოვ მიუთითე შიდა IP ხელით: ")

def get_mac_by_ip(ipaddr):
    # get the MAC by sending ARP packets to the desired IP

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ipaddr), retry=2, timeout=7)
    for snd, rcv in ans:
        try:
            return rcv[Ether].src
        except KeyError:
            print("\n{R}ERROR: MAC-ის დადგენა ვერ მოხერხდა მიმდინარე IP მისამართითანდ: {N}{ip}\n".format(R=RED, N=NORMAL, ip=ipaddr))
            return raw_input("გთხოვ მიუთითე MAC მისამართი ხელით: ")

def host_scan(advanced_scan=False):
    '''
    This searches for hosts in the network using python-nmap.
    Informations like: IP, MAC, Vendor, OS and open ports can be gathered.
    The function uses 'scan.py' located in the local 'build' folder.
    '''

    interface = get_interface()
    
    hostscan = scan.HostScan(interface)
    ip_range = hostscan.get_range()

    if advanced_scan:
        hostscan.advanced_scan = True

    clear_screen()
    
    print("{N}მითითებული IP შემოწმდება NMAP-ით: {G}{ipr}{N}".format(G=GREEN, N=NORMAL, ipr=ip_range))
    print("დააჭირე {Y}'Enter'{N} დაწყებისთვის ან მიუთითე სასურველი IP.".format(Y=YELLOW, N=NORMAL))
    ipr_change = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED))
    if ipr_change:
        ip_range = ipr_change
    
    clear_screen()

    if advanced_scan:
        # print a different message, since the advanced scan can take up to several minutes
        print("[{Y}*{N}] მიმდინარეობს სკანირება. გთხოვ მოიცადე.".format(Y=YELLOW, N=NORMAL))
    else:
        print("[{Y}*{N}] მიმდინარეობს სკანირება...".format(Y=YELLOW, N=NORMAL))
        
    hostscan.do_scan(ip_range)
    hosts = hostscan.get_hosts()

    clear_screen()

    for mac in hosts:
        # print out gathered informations for each host in the network

        print("<<<-----------------------   {Y}{ip}{N}   ----------------------->>>\n".format(Y=YELLOW, N=NORMAL, ip=hosts[mac]["ip"]))

        if hosts[mac]["gateway"]:
            print("{R}IP:{N}      {Y}{ip} {R}(gateway){N}\n{R}MAC:{N}     {mac}\n{R}სახელი ქსელში:{N}    {name}\n{R}წარმომადგენელი:{N}  {vendor}".format(
                R=RED,
                N=NORMAL,
                Y=YELLOW,
		ip=hosts[mac]['ip'],
            	mac=mac.upper(),
            	vendor=hosts[mac]['vendor'],
            	name=hosts[mac]['name']))
        else:
            print("{R}IP:{N}      {Y}{ip}\n{R}MAC:{N}     {mac}\n{R}სახელი ქსელში:{N}    {name}\n{R}წარმომადგენელი:{N}  {vendor}".format(
                R=RED,
            	N=NORMAL,
	        Y=YELLOW,
            	ip=hosts[mac]['ip'],
            	mac=mac.upper(),
            	vendor=hosts[mac]['vendor'],
            	name=hosts[mac]['name']))

        if advanced_scan:
            if not hosts[mac]["os"]:
                print("{R}ოპერაციული სისტემა:{N} უცნობი ოპერატიული სისტემა\n".format(R=RED, N=NORMAL))
            else:
                '''
                The following dict is created by python-nmap.
                It really is a mess
                '''
                os_list = {}
		
                for item in hosts[mac]["os"]:
                    if not item[0] or not item[1]:
                        continue
                    if item[0] in os_list:
                        if item[1] not in os_list[item[0]]:
                            os_list[item[0]].append(item[1])
                    else:
                        os_list[item[0]] = [item[1]]

                    os_str = "{R}ოპერაციული სისტემა:     {N} "
                    for os in os_list:
                        os_str += "{} ".format(os)
                        for gen in os_list[os]:
                            if gen == os_list[os][-1]:
                                os_str += "{}\n         ".format(gen)
                            else:
                                os_str += "{}/".format(gen)

                    if not os_list:
                        os_str = "{R}OS:{N} უცნობი ოპერაციული სისტემა\n".format(R=RED, N=NORMAL)

                print(os_str.format(R=RED, N=NORMAL))

            if not hosts[mac]["open_ports"]:
                print("{R}Ports:{N} პროტები არ არის ღია".format(R=RED, N=NORMAL))
            else:
                open_ports = hosts[mac]["open_ports"]
                port_str = "{R}პორტები:{N}   ".format(R=RED, N=NORMAL)
                port_len = len(port_str)

                for port in open_ports.keys()[1:]:
                    name = open_ports[port]
                    if not name:
                        name = "უცნობი პორტი"

                    if port == open_ports.keys()[1]:
                        port_str += "{G}open   {Y}{p}{N} ({name})\n".format(G=GREEN, Y=YELLOW, N=NORMAL, p=port, name=name)
                    elif port == open_ports.keys()[-1]:
                        port_str += "         {G}open   {Y}{p}{N} ({name})".format(G=GREEN, Y=YELLOW, N=NORMAL, p=port, name=name)
                    else:
                        port_str += "         {G}open   {Y}{p}{N} ({name})\n".format(G=GREEN, Y=YELLOW, N=NORMAL, p=port, name=name)
		
                if port_len == len(port_str):
                    print("{R}Ports:{N} პროტები არ არის ღია".format(R=RED, N=NORMAL))
                else:
                    print(port_str)

        print("\n")

    print("{R}{num}{N} მოწყობილობა ქსელში.\n".format(R=RED, N=NORMAL, num=len(hosts)))

def wifi_scan():
    '''
    This will perform a basic Access-Point scan.
    Informations like WPS, Encryption, Signal Strength, ESSID, ... will be shown for every available AP.
    The function uses 'scan.py' located in the local 'build' folder.
    '''

    interface = get_interface()
    enable_mon_mode(interface)

    wifiscan = scan.WifiScan(interface)
    wifiscan.do_output = True

    hopT = Thread(target=wifiscan.channelhop, args=[])
    hopT.daemon = True
    hopT.start()

    # This decay is needed to avoid issues concerning the Channel-Hop-Thread
    sleep(0.2)
    
    try:
        wifiscan.do_scan()
    except socket.error:
        print("{R}ERROR: ინტერფეისი გათიშულია.{N}".format(R=RED, N=NORMAL))
        sys.exit(0)

def get_targets_from_hosts(interface):
    '''
    This will scan the network for hosts and print them out.
    It lets you choose the targets for your attack.
    '''

    targets = {}
    available_hosts = {}
    cntr = 1

    hostscan = scan.HostScan(interface)
    ip_range = hostscan.get_range()

    clear_screen()
    
    print("{N}მითითებული IP შემოწმდება NMAP-ით: {G}{ipr}{N}".format(G=GREEN, N=NORMAL, ipr=ip_range))
    print("დააჭირე {Y}'Enter'{N} დაწყებისთვის ან მიუთითე სასურველი IP.".format(Y=YELLOW, N=NORMAL))
    
    ipr_change = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED))
    if ipr_change:
        ip_range = ipr_change
    
    clear_screen()
    
    print("[{Y}*{N}] მიმდინარეობს სკანირება...".format(Y=YELLOW, N=NORMAL))
    
    hostscan.do_scan(ip_range)
    hosts = hostscan.get_hosts()
    
    clear_screen()
    
    if len(hosts) < 1:
        print("\n{R}მოწყობილობა ვერ მოიძებნა :({N}\n".format(R=RED, N=NORMAL))
        sys.exit(0)
    
    print("{Y}მოწყობილობები ქსელში:{N}\n\n".format(Y=YELLOW, N=NORMAL))

    for mac in hosts.keys():
        if hosts[mac]['gateway']:
            del hosts[mac]
            continue
        else:
            available_hosts[len(available_hosts)+1] = mac
            print("   {R}[{N}{ID}{R}] {N}{mac} ({ip}) | {name}".format(
                R=RED,
                N=NORMAL,
                ID=len(available_hosts),
                mac=mac.upper(),
                ip=hosts[mac]['ip'],
                name=hosts[mac]['name']))

    print("\n\nგამოყავით მიზნები {R}','{N} (მძიმით).\nმიუთითეთ სიტყვა {R}'ყველა'{N} რათა აირჩიო ყველა მიზანი.".format(R=RED, N=NORMAL))

    while True:
        targets_in = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED)).lower()
        targets_in = targets_in.replace(" ", "")

        if targets_in == "ყველა":
            for mac in hosts:
                targets[mac] = hosts[mac]["ip"]
            return targets

        if "," in targets_in:
            targets_list = targets_in.split(",")

            if all(x.isdigit() for x in targets_list) and all(0 < int(y) <= len(available_hosts) for y in targets_list):
                for target in targets_list:
                    for num in available_hosts:
                        if int(target) == num:
                            targets[available_hosts[num]] = hosts[available_hosts[num]]["ip"]
                return targets
            else:
                print("{R}ERROR: არასწორი ფუნქცია.{N}".format(R=RED, N=NORMAL))
                continue
        else:
            if targets_in.isdigit() and 0 < int(targets_in) <= len(available_hosts):
                targets[available_hosts[int(targets_in)]] = hosts[available_hosts[int(targets_in)]]["ip"]
                return targets
            else:
                print("{R}ERROR: არასწორი ფუნქცია.{N}".format(R=RED, N=NORMAL))
                continue


def arp_kick():
    interface = get_interface()
    targets = get_targets_from_hosts(interface)
    gateway_ip = get_gateway_ip()
    gateway_mac = get_mac_by_ip(gateway_ip)
    local_ip = get_local_ip(interface)
    
    arpspoof = spoof.ARPSpoof(targets, gateway_ip, gateway_mac, interface)

    for mac in targets:
        print("{G} ->{N}  {mac} ({ip})".format(G=GREEN, N=NORMAL, mac=mac.upper(), ip=targets[mac]))

    disable_ip_forwarding()

    try:
        arpspoof.arp_spoof()
    except:
        print("\n{R}ბრუნდება ყველაფერი თავის ადგილზე. გთხოვ მოიცადო!{N}".format(R=RED, N=NORMAL))
        arpspoof.restore_arp()

def main():
    # Signal handler to catch KeyboardInterrupts
    def signal_handler(signal, frame):
        print("")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    conf.verb = 0 # scapy, QUITE

    clear_screen()
    printings.print_banner()
    printings.print_options()

    option = get_option()
    handle_option(option)

if __name__ == "__main__":
    main()
