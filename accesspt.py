import os
import subprocess

def create_hostapd_conf(interface, ssid, channel, pswd):
    file = open("hostapd.conf","w")
    file.write("interface=" + interface + "\n")
    file.write("driver=nl80211" + "\n")
    file.write("ssid=" + ssid + "\n")
    file.write("hw_mode=g" + "\n")
    file.write("channel=" + channel + "\n")
    file.write("macaddr_acl=0" + "\n")
    file.write("auth_algs=1" + "\n")
    file.write("wpa=2" + "\n")
    file.write("wpa_key_mgmt=WPA-PSK" + "\n")
    file.write("rsn_pairwise=CCMP" + "\n")
    file.write("wpa_passphrase=" + pswd + "\n")
    file.write("ignore_broadcast_ssid=0" + "\n")
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
