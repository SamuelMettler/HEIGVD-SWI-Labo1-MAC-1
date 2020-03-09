#python3
import argparse
import numpy as np
from scapy.all import *
from threading import Thread
import pandas
import time
import os
from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump

parser = argparse.ArgumentParser(prog="Evil Twin attack",
                                 usage=" python3 evilTwin.py -i [interface]\n",
                                 allow_abbrev=False)
parser.add_argument("-i", "--Interface", required=True, help="Interface from which you want to send packets, needs to be set to monitor mode ")
parser.add_argument("-s", "--Second", required=True, help="Number of second you will monitor packets")
args = parser.parse_args()

# initialize the networks dataframe that will contain all access points nearby
# for each network we also want to apture the beacon sent

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Number"])
networksBeacon = pandas.DataFrame(columns=["BSSID", "SSID", "Packet"])

# set the index BSSID (MAC address of the AP) for both dataFrame
networks.set_index("BSSID", inplace=True)
networksBeacon.set_index("BSSID", inplace=True)

def callback(packet):
    i = 0
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        networks.loc[bssid] = (ssid, dbm_signal, channel, i)
        
        networksBeacon.loc[bssid] = (ssid, packet)
    
    for index, row in networks.iterrows():
        i+=1
        row['Number'] = i


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


def create_packet(packet):
    #hexdump(packet)
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        print(ssid, dbm_signal, channel)
        

if __name__ == "__main__":
    # interface name, check using iwconfig and pass it with -i argument
    interface = args.Interface    

    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing
    print("Sniff pendant " + str(args.Second) + " secondes, veuiller patienter\n")
    sniff(prn=callback, iface=interface, timeout=int(args.Second))
    print(networks)

    # Display user the list of network
    print("\nSelect target, between 1 and " + str(len(networks)))

    # Get the input of the user 
    userInput = int(input())
    userChoice = 0
    if(isinstance((userInput),int) and 0 < userInput <= len(networks)):
        userChoice = networks.loc[networks["Number"] == userInput].head().index.values[0]
        print(userChoice) 

    # for index, row in networksBeacon.iterrows():
    #     print(index)
    #     print(hexdump(row["Packet"]))



    packet = networksBeacon.loc[userChoice].values[1]
    create_packet(packet)
