import os
import subprocess
import interface

def create_hostapd_conf(interface, ssid, channel, pswd):
    file = open("hostapd.conf","w")
    file.write("interface=" + interface) 
    file.write("driver=nl80211") 
    file.write("ssid=" + ssid) 
    file.write("hw_mode=g")
    file.write("channel=" + channel)
    file.write("macaddr_acl=0")
    file.write("auth_algs=1")
    file.write("wpa=2")
    file.write("wpa_key_mgmt=WPA-PSK")
    file.write("rsn_pairwise=CCMP")
    file.write("wpa_passphrase=" + pswd)
    file.write("ignore_broadcast_ssid=0")
    file.close()


def start_access_point(interface, bssid, ssid, channel, pswd):
    # change access point
    down_inteface(interface)
    subprocess.call("macchanger --mac " + bssid + " " + interface, shell=True)
    up_interface(interface)

    #start hostapd
    create_hostapd_conf(interface, ssid, channel, pswd)
    subprocess.call("hostapd hostapd.conf", shell=True)

