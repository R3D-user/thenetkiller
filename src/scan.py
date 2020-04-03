# -*- coding: utf-8 -*-
import nmap
import sys
import netifaces
from time import sleep
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # scapy, psst!
from scapy.all import *
import subprocess
import os
import printings

RED = "\033[1;31m"  
NORMAL = "\033[0;0m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;93m"

conf.verb = 0 # shhh scapy...

class HostScan(object):
    def __init__(self, interface):
        self.interface = interface
        self.hosts = {}
        self.advanced_scan = False
        try:
            self.local_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        except KeyError:
            self.local_ip = raw_input("\n{R}ERROR: შეუძლებელია დადგინდეს შიდა IP.\n{N}გთხოვ მიუთითე ხელით: ".format(R=RED, N=NORMAL))
        try:
            self.gateway_ip = netifaces.gateways()["default"][netifaces.AF_INET][0]
        except KeyError:
            self.gateway_ip = raw_input("\n{R}ERROR: შეუძლებელია დადგინდეს gateway IP.\n{N}გთხოვ მიუთითე ხელით: ".format(R=RED, N=NORMAL))

    def get_range(self):
        try:
            netmask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]["netmask"]
        except KeyError:
            netmask = raw_input("\n{R}ERROR: შეუძლებელია დადგინდეს subnetmask.\n{N}გთხოვ მიუთითე ხელით: ".format(R=RED, N=NORMAL))
        cidr = sum((bin(int(x)).count("1")) for x in str(netmask).split("."))
        ip = ".".join(self.local_ip.split(".")[:-1]) + ".0"
        return "{}/{}".format(ip, cidr)

    def do_scan(self, ip_range):
        nm = nmap.PortScanner()
        if self.advanced_scan:
            result = nm.scan(hosts=ip_range, arguments="-sS -O")
        else:
            result = nm.scan(hosts=ip_range, arguments="-sP")

        for _, item in result["scan"].iteritems():
            if item["status"]["state"] == "up":
                try:
                    ip = item["addresses"]["ipv4"]
                    if ip == self.local_ip:
                        continue
                except KeyError:
                    ip = "უცნობი IP"
                try:
                    mac = item["addresses"]["mac"].lower()
                except KeyError:
                    mac = "უცნობი MAC"
                name = item["hostnames"][0]["name"]
                try:
                    vendor = item["vendor"][mac.upper()]
                except KeyError:
                    vendor = "უცნობი წარმომადგენელი"

                if not ip:
                    ip = "უცნობი IP"
                if not mac:
                    mac = "უცნობი MAC"
                if not name:
                    name = "უცნობი სახელი"
                if not vendor:
                    vendor = "უცნობი წარმომადგენელი"

                gateway = False
                if ip == self.gateway_ip:
                    gateway = True
                

                if self.advanced_scan:
                    try:
                        osmatch = item["osmatch"]
                        os_list = []

                        for os in osmatch:
                            for x in os["osclass"]:
                                try:
                                    os_list.append([x["osfamily"], x["osgen"]])
                                except KeyError:
                                    continue
                    except KeyError:
                        os_list = None
                    try:
                        open_ports = {}
                        for port in item["tcp"]:
                            try:
                                open_ports[port] = item["tcp"][port]["name"]
                            except KeyError:
                                open_ports[port] = None
                                continue
                    except KeyError:
                        open_ports = None


                if mac not in self.hosts:
                    if self.advanced_scan:
                        self.hosts[mac] = {"ip": ip, "name": name, "vendor": vendor, "gateway": gateway, "os": os_list, "open_ports": open_ports}
                    else:
                        self.hosts[mac] = {"ip": ip, "name": name, "vendor": vendor, "gateway": gateway}
                else:
                    continue

    def get_hosts(self):
        return self.hosts
