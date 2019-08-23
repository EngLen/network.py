#!/usr/bin/env python
import scapy.all as scapy
import optparse


def get_arguments():
    pars = optparse.OptionParser()
    pars.add_option("-t", "--target", dest="target", help="Target IP / IP range.")
    options, arguments = pars.parse_args()
    return options

def scan(ip):
    arp_re = scapy.ARP(pdst=ip)
    broad_c = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_re_broad_c = broad_c/arp_re
    anw_ls = scapy.srp(arp_re_broad_c, timeout=1, verbose=False)[0]
    cl_ls = []
    for ip in anw_ls:
        cl_dict = {"ip": ip[1].psrc, "mac": ip[1].hwsrc}
        cl_ls.append(cl_dict)
    return cl_ls

def print_result(re_ls):
    print("IP\t\t\tMAC Address\n-------------------------------------")
    for cl in re_ls:
        print(cl["ip"] + "\t\t" + cl["mac"])


opt = get_arguments()
scan_re = scan(opt.target)
print_result(scan_re)
