import os
from IPGetandSet import getServerAddress

try: #auto install scapy
    from scapy.all import *
except ImportError:
    print("Trying to Install required module: scapy")
    os.system('pip3 install scapy')
    from scapy.all import *

def craft(mess, mode):
    global pkt
    global dest
    mess = str(mess)

    if mode == 9:
        hmsg = ord(mess)

    dest = getServerAddress()
    if mode == 0:
        mess = "0" + mess
        pkt = IP(dst=dest)/UDP(dport=123,sport=50001)/str(mess)
        return pkt
    elif mode == 1:
        mess = "1" + mess
        pkt = IP(dst=dest)/UDP(dport=123,sport=50003)/str(mess)
        return pkt
    elif mode == 2:
        mess = "2" + mess
        pkt = IP(dst=dest)/UDP(dport=123,sport=50002)/str(mess)
        return pkt
    elif mode == 3:
        mess = "3" + mess
        pkt = IP(dst=dest)/UDP(dport=123,sport=50004)/str(mess)
        return pkt
    elif mode == 4:
        mess = "4" + mess
        pkt = IP(dst=dest)/UDP(dport=123,sport=40009)/str(mess)
        return pkt
    elif mode == 5:
        mess = "5" + mess
        pkt = IP(dst=dest)/UDP(dport=123,sport=40008)/str(mess)
        return pkt
    elif mode == 6:
        mess = "6" + mess
        pkt = IP(dst=dest)/UDP(dport=123,sport=40000)/str(mess)
        return pkt
    elif mode == 7:
        mess = "7" + mess
        pkt = IP(dst=dest)/UDP(dport=123,sport=50000)/str(mess)
        return pkt
    elif mode == 8:
        mess = "8" + mess
        pkt = IP(ttl=128, dst=dest)/UDP(dport=123,sport=50005)/str(mess) #check ttl shift
        return pkt
    elif mode == 9:
        pkt = IP(ttl=hmsg, dst=dest)/UDP(dport=123,sport=50006)/str('9')
        return pkt
