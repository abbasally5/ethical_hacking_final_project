import os
import subprocess

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
    subprocess.call("ifconfig " + interface + " down", shell=True)
    subprocess.call("macchanger --mac " + bssid + " " + interface, shell=True)
    subprocess.call("ifconfig " + interface + " up", shell=True)

    #start hostapd
    create_hostapd_conf(interface, ssid, channel, pswd)
    subprocess.call("hostapd hostapd.conf", shell=True)


if __name__ == "__main__":

    start_access_point("wlan0mon", "98:F1:70:09:FE:71", "testnetwork", "6", "poppoppop")
