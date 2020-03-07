import os
import random
import string
import sys

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.sendrecv import sendp

interface = 'en0'


# print usage and quit
def print_usage():
    print('Usage: ssid-flood.py <ssid-file | ssid-count>')
    print('         ssid-file:  file with a list of SSIDs (one per line)')
    print('         ssid-count: a number of SSIDs to generate')
    sys.exit(1)


if len(sys.argv) != 2:
    print_usage()

ssids = []

# the first argument is a file with a list of ssid
if os.path.isfile(sys.argv[1]):
    with open(sys.argv[1]) as file:
        for ssid in file:
            ssids.append(ssid.strip())

# the first argument is the number of ssid to generate
else:
    try:
        count = int(sys.argv[1])
        for i in range(0, int(sys.argv[1])):
            ssids.append(''.join(random.choices(string.ascii_letters, k=9)))
    except ValueError:
        print_usage()


# inspiration https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/

def random_mac():
    return ':'.join('%02x' % random.randrange(256) for _ in range(5))


# common frame values
dot11 = Dot11(type=0,  # management frame
              subtype=8,  # beacon
              addr1='ff:ff:ff:ff:ff:ff',  # destination MAC address, i.e. broadcast
              addr2=random_mac(),  # MAC address of sender
              addr3=random_mac())  # MAC address of AP
beacon = Dot11Beacon(cap='ESS+privacy')
rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'  # RSN Version 1
    '\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'  # 2 Pairwise Cipher Suites (next two lines)
    '\x00\x0f\xac\x04'  # AES Cipher
    '\x00\x0f\xac\x02'  # TKIP Cipher
    '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
    '\x00\x0f\xac\x02'  # Pre-Shared Key
    '\x00\x00'))  # RSN Capabilities (no extra capabilities)


def broadcast_ssids(ssids):
    """
    Create and send frames for each of the given SSID.

    :param ssids: an array of SSIDs
    """

    # frame.show()
    # print("\nHexdump of frame:")
    # hexdump(frame)

    # create a frame for each SSID
    frames = [create_frame(ssid) for ssid in ssids]

    # send all frames repeatedly
    sendp(frames, iface=interface, inter=0.100, loop=1, monitor=True, verbose=True)


def create_frame(ssid):
    """
    Create the frame for the given SSID.

    :param ssid: the SSID to create the frame for
    :return: the created frame
    """
    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
    return RadioTap() / dot11 / beacon / essid / rsn


print('SSIDs:', ssids)
broadcast_ssids(ssids)
