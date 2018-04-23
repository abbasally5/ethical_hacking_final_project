#!/usr/bin/env python

import os, subprocess
from multiprocessing import Process

def check_root():

    if os.geteuid() != 0:
        print('need to be root')
        exit(0)

def setup_network():

    out = subprocess.check_output("airmon-ng check kill".split(" "))
    print(out)
    out = subprocess.check_output("/etc/init.d/avahi-daemon stop".split(" "))
    print(out)

    p2 = subprocess.Popen("iwconfig".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p2.communicate()
    result = err + out
    #print(result)
    managed = ""
    #interfaces = [r.split()[0] for r in result.split("\n\n")]
    interfaces = []
    for r in result.split("\n\n"):
        interface = r.split()[0]
        interfaces.append(interface)
        if "Managed" or "Promiscous" in r:
            managed = interface
    #print(interfaces)
    print("Using {} as the interface".format(managed))

    out = subprocess.check_output("ifconfig {} down".format(managed).split(" "))
    print(out)
    out = subprocess.check_output("airmon-ng start {}".format(managed).split(" "))
    print(out)
    #cmd = "ifconfig | grep mon | awk -F ':' '{print $1}' | awk '{print $1}'"
    #out = subprocess.check_output(cmd.split(" "))
    print(out)


def get_bssids():
    pass

def run():
    check_root()
    setup_network()

if __name__ == "__main__": 
    run()
