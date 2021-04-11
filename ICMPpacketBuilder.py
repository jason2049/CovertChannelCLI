import os
from IPGetandSet import getServerAddress

try: #auto install scapy
    from scapy.all import *
except ImportError:
    print("Trying to Install required module: scapy")
    os.system('pip3 install scapy')
    from scapy.all import *


def craft(Message, mode):
    global pkt
    global dest
    dest = getServerAddress()

    if mode == 8:
        hmsg = ord(Message)

    if mode == 1: #send msg
        Message = "!" + Message
        pkt = IP(dst = dest)/ICMP()/Message
        return pkt
    elif mode == 2: #send file data
        Message = "@" + Message
        pkt = IP(dst = dest)/ICMP()/Message
        return pkt
    elif mode == 3: #send file name
        Message = "#" + Message
        pkt = IP(dst = dest)/ICMP()/Message
        return pkt
    elif mode == 4: #end transmission
        Message = "$" + Message
        pkt = IP(dst = dest)/ICMP()/Message
        return pkt
    elif mode == 5: #send md5Hash
        Message = "%" + Message
        pkt = IP(dst = dest)/ICMP()/Message
        return pkt
    elif mode ==6: #test
        Message = "test" + Message
        pkt = IP(dst = dest)/ICMP()/Message
        return pkt
    elif mode == 7: #check ttl shift
        Message = "*" + Message
        pkt = IP(ttl = 128, dst = dest)/ICMP()/Message
        return pkt
    elif mode == 8:
        Message = "&"
        pkt = IP(ttl = hmsg, dst = dest)/ICMP()/Message
        return pkt
    elif mode == 9: #send encrypted msg
        Message = "^" + Message
        pkt = IP(dst = dest)/ICMP()/Message
        return pkt
