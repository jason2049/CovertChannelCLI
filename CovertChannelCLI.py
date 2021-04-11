import os
import time
import threading
import socket
# import signal
# import sys
import base64
from filehash import getFileHash
import DNSpacketBuilder
import ICMPpacketBuilder
import NTPpacketBuilder
import Systemcheck
from IPGetandSet import getServerAddress, setServerAddress, getClientLocalIP, getClientPublicIP
from AES_CBC import AES_Encrypt
from USBkeyReader import getKEY
from zipFile import zipfile
from configurator import getConfig, setConfig

try: #auto install scapy
    from scapy.all import *
except ImportError:
    print("Trying to Install required module: scapy")
    os.system('pip3 install scapy')
    from scapy.all import *

settingFilePath = "SETTING.txt"
setting = getConfig(settingFilePath)
encryptionMode = bool(int(setting["Encryption"]))
if encryptionMode == True:
    plugkey = input("Please plug your USB key to computer and type \"ok\" to continue: ")
    if plugkey == "ok":
        KEY = getKEY()
        if KEY == None:
            print('Error, USB key is not inserted!')
            print('Encryption mode is disable!')
            encryptionMode = False
        elif KEY == "notmatch":
            print('Private key does not match!!!!')
            print('Encryption mode is disable!')
            encryptionMode = False
    else:
        print('Encryption mode is disable!')
        encryptionMode = False

def DNSfeasibilityCheck():
    craft_pkt = DNSpacketBuilder.craft('x', 4)
    send(craft_pkt, verbose=False)
    time.sleep(1.0)
    if DNSchannelCheck[0] == 1:
        print('DNS covert channel feasibility ** success ** ')
        DNSchannelCheck[0] = 0
    else:
        print('DNS covert channel feasibility ** failure ** ')
    time.sleep(0.5)

def ICMPfeasibilityCheck():
    pkt = ICMPpacketBuilder.craft('',6)
    send(pkt, verbose=False)
    time.sleep(1.0)
    if ICMPchannelCheck[0] == 1:
        print('ICMP covert channel feasibility ** success ** ')
        ICMPchannelCheck[0] = 0
    else:
        print('ICMP covert channel feasibility ** failure ** ')
    time.sleep(0.5)

def NTPfeasibilityCheck():
    mess = "test"
    pkt = NTPpacketBuilder.craft(mess, 6)
    send(pkt, verbose=False)
    time.sleep(1.0)
    if NTPchannelCheck[0] == 1:
        print('NTP covert channel feasibility ** success ** ')
        NTPchannelCheck[0] = 0
    else:
        print('NTP covert channel feasibility ** failure ** ')
    time.sleep(0.5)

def DNSmsgsend_request():
    while True:
        message = input('Type a message: ')
        if message == '>exit':
            DNSoption()

        time.sleep(0.5)
        message = message.replace(" ", "-")
        print("On sending: " + message)
        if encryptionMode == True:
            craft_pkt = DNSpacketBuilder.craft(AES_Encrypt(KEY, message), 7)
            send(craft_pkt, verbose=False)
        else:
            craft_pkt = DNSpacketBuilder.craft(message, 5)
            send(craft_pkt, verbose=False)
def DNSfilesend():
    while True:
        filename = input('Type the filename: ')
        if filename == '>exit':
            DNSoption()

        zip = input('Compress file (with AES encryption)? (y or n): ')
        if zip == 'y' or zip == 'Y':
            password = input("Set password for zip file: ")
            print("Compressing file....")
            zipfile(filename, bytes(password, 'utf-8'))
            print("Finish")
            filename = filename + '.zip'

        Ofilename, file_extension = os.path.splitext(filename)
        Ofilename = Ofilename.split('/')[-1]
        try:
            f = open(filename, 'rb')
            fread = f.read()
            f64 = str(base64.b64encode(fread), 'ascii')
            flen = len(f64)
            fhash = getFileHash(filename)
            print('File size: ' + str(flen) + ' bytes')
            print('File hash value: ' + fhash)
        except:
            print('no this file!')
            DNSfilesend()
        #print(f64)
        notcomplete = False
        craft_pkt = DNSpacketBuilder.craft('x', 2, Ofilename, file_extension, flen, fhash) #request the server to receive the file
        send(craft_pkt, verbose=False)
        time.sleep(0.5)

        print('Transferring file...')
        i = 0
        count = 0
        while i < flen:
            craft_pkt = DNSpacketBuilder.craft(f64[i:i+60], 3)
            send(craft_pkt, verbose=False)
            count += 1
            i += 60
        craft_pkt = DNSpacketBuilder.craft('', 6) #end signal
        send(craft_pkt, verbose=False)

        print(str(count) + ' packets are sent.')
        print('Result:')
        time.sleep(5)

        if fileTranferCheck[0] == 0:
            print('    ** Data loss or corruption occur, please try again. **')
            fileTranferCheck[0] = 3
            # print(fileTranferCheck[0])
        elif fileTranferCheck[0] == 1:
            print('    ** File sent successfully **')
            fileTranferCheck[0] = 3
            # print(fileTranferCheck[0])
        else:
            print('    ** Not respond, please try again **')

        time.sleep(0.5)

def DNSoption():
    print('  _____  _   _  _____ ')
    print(' |  __ \| \ | |/ ____|')
    print(' | |  | |  \| | (___  ')
    print(' | |  | | . ` |\___ \ ')
    print(' | |__| | |\  |____) |')
    print(' |_____/|_| \_|_____/ ')
    if encryptionMode == True:
        print('Encryption mode is activate!')
    else:
        print('Encryption mode is disable!')
    print('Option:')
    # print('00. DNS(TTL) covert channel (Text only)')
    print('00. DNS(DNS request) covert channel (Text only)')
    print('01. DNS covert channel (File transfer)')
    print('back. Previous page')

    DNSop = input('Enter number: ')

    # if DNSop == '00':
    #     print('* Using -> DNS(TTL) covert channel (Text only)')
    #     print('* Type \">exit\" to exit')
    #
    #     DNSmsgsend_ttl()
    if DNSop == '00':
        print('* Using -> DNS(DNS request) covert channel (Text only)')
        print('* Type \">exit\" to exit')

        DNSmsgsend_request()
    elif DNSop == '01':
        print('* Using -> DNS covert channel (File transfer)')
        print('* Type \">exit\" to exit')

        DNSfilesend()
    elif DNSop == 'back':
        option()
    else:
        print('No this option!!!')
        DNSoption()
def ICMPmsgsend():
    while True:
        message = input('Type a message: ')
        if message == ">exit":
            ICMPoption()

        if encryptionMode == True:
            # craft_pkt = DNSpacketBuilder.craft(AES_Encrypt(KEY, message), 7)
            # send(craft_pkt, verbose=False)
            pkt = ICMPpacketBuilder.craft(AES_Encrypt(KEY, message), 9)
            send(pkt)
        else:
            pkt = ICMPpacketBuilder.craft(message, 1)
            send(pkt)

def ICMPfilesend():
    while True:
        filename = input('Type the filename: ')
        if filename == ">exit":
            ICMPoption()

        zip = input('Compress file (with AES encryption)? (y or n): ')
        if zip == 'y' or zip == 'Y':
            password = input("Set password for zip file: ")
            print("Compressing file....")
            zipfile(filename, bytes(password, 'utf-8'))
            print("Finish")
            filename = filename + '.zip'
        fname = filename.split('/')[-1]
        if filename == ">exit":
            ICMPoption()

        try:
            hfile = getFileHash(filename)
            pkt = ICMPpacketBuilder.craft(fname,3)
            send(pkt, verbose=False)
            f = open(filename,'rb')
            fread = f.read()
            f64 = base64.b64encode(fread)
            print('File size: ' + str(len(f64)) + ' bytes')
            print('File hash value: ' + hfile)
        except:
            print('no this file!')

            ICMPfilesend()

        print('Transferring file...')
        msg = f64.decode("ascii")
        i = 0
        pkt = ICMPpacketBuilder.craft(msg[i:i+1471],2)
        send(pkt, verbose=False)
        i += 1471
        while i < len(msg):
            pkt = ICMPpacketBuilder.craft(msg[i:i+1471],2)
            send(pkt, verbose=False)
            i += 1471
        pkt = ICMPpacketBuilder.craft("",4)
        send(pkt, verbose=False)
        pkt = ICMPpacketBuilder.craft(hfile,5)
        send(pkt, verbose=False)
        print('Result:')
        time.sleep(5)

        if ICMPfileTranferCheck[0] == 0:
            print('    ** Data loss or corruption occur, please try again. **')
            ICMPfileTranferCheck[0] = 3
            # print(fileTranferCheck[0])
        elif ICMPfileTranferCheck[0] == 1:
            print('    ** File sent successfully **')
            ICMPfileTranferCheck[0] = 3
            # print(fileTranferCheck[0])
        else:
            print('    ** Not respond, please try again **')
        time.sleep(0.5)
def ICMPoption():
    print('  _____ _____ __  __ _____  ')
    print(' |_   _/ ____|  \/  |  __ \ ')
    print('   | || |    | \  / | |__) |')
    print('   | || |    | |\/| |  ___/ ')
    print('  _| || |____| |  | | |     ')
    print(' |_____\_____|_|  |_|_|     ')
    if encryptionMode == True:
        print('Encryption mode is activate!')
    else:
        print('Encryption mode is disable!')
    print('Option:')
    print('00. ICMP covert channel (Text only)')
    print('01. ICMP covert channel (File transfer)')
    print('back. Previous page')

    ICMPop = input('Enter number: ')

    if ICMPop == '00':
        print('* Using -> ICMP covert channel (Text only)')
        print('* Type \">exit\" to exit')

        ICMPmsgsend()
    elif ICMPop == '01':
        print('* Using -> ICMP covert channel (File transfer)')
        print('* Type \">exit\" to exit')

        ICMPfilesend()
    elif ICMPop == 'back':
        option()
    else:
        print('No this option!!!')
        ICMPoption()

def NTPmsgsend():
    while True:
        message = input('Type a message: ')
        if message == '>exit':
            NTPoption()

        print("On sending: " + message)

        #pkt = IP(dst=dest)/UDP(dport=123,sport=50000)/Raw(load=message)
        if len(message) % 2 == 0:
            message = message + ' '

        pkt = NTPpacketBuilder.craft(message, 7)
        send(pkt, verbose=False)
        #pkt.show()
def NTPfilesend():
    while True:
        filename = input('Type the filename:')
        if filename == '>exit':
            NTPoption()

        zip = input('Compress file (with AES encryption)? (y or n): ')
        if zip == 'y' or zip == 'Y':
            password = input("Set password for zip file: ")
            print("Compressing file....")
            zipfile(filename, bytes(password, 'utf-8'))
            print("Finish")
            filename = filename + '.zip'

        Ofilename, file_extension = os.path.splitext(filename)
        Ofilename = Ofilename.split('/')[-1]

        try:
            f = open(filename, 'rb')
            fread = f.read()
            f64 = base64.b64encode(fread)
            fhash = getFileHash(filename)
            print('File size: ' + str(len(f64)) + ' bytes')
            print('File hash value: ' + fhash)
        except:
            print('no this file!')
            NTPfilesend()

        print('Transferring file...')

        fil = str(Ofilename+file_extension)
        pkt1 = NTPpacketBuilder.craft(str(fil), 1)
        send(pkt1, verbose=False)#send file name

        i = 0
        while i < len(f64):
            mess=(f64[i:i+5])

            pkt = NTPpacketBuilder.craft(mess, 0)
            send(pkt, verbose=False)#send file
            i += 5

        pktend = NTPpacketBuilder.craft('e', 2)
        send(pktend, verbose=False)#end send file

        a = 0
        while a < len(fhash):
            f=(fhash[a:a+5])

            pkt = NTPpacketBuilder.craft(f, 3)
            send(pkt, verbose=False)
            a += 5

        pkt2 = NTPpacketBuilder.craft('e', 5)
        send(pkt2, verbose=False)
        print('Result:')
        time.sleep(5)

        if NTPfileTranferCheck[0] == 0:
            print('    ** Data loss or corruption occur, please try again. **')
            NTPfileTranferCheck[0] = 3
            # print(fileTranferCheck[0])
        elif NTPfileTranferCheck[0] == 1:
            print('    ** File sent successfully **')
            NTPfileTranferCheck[0] = 3
            # print(fileTranferCheck[0])
        else:
            print('    ** Not respond, please try again **')
def NTPoption():
    print('  _   _ _______ _____  ')
    print(' | \ | |__   __|  __ \ ')
    print(' |  \| |  | |  | |__) |')
    print(' | . ` |  | |  |  ___/ ')
    print(' | |\  |  | |  | |     ')
    print(' |_| \_|  |_|  |_|     ')
    print('Encryption mode does not support NTP!')
    print('Option:')
    print('00. NTP covert channel (Text only)')
    print('01. NTP covert channel (File transfer)')
    print('back. Previous page')

    NTPop = input('Enter number: ')

    if NTPop == '00':
        print('* Using -> NTP covert channel (Text only)')
        print('* Type \">exit\" to exit')

        NTPmsgsend()
    elif NTPop == '01':
        print('* Using -> NTP covert channel (File transfer)')
        print('* Type \">exit\" to exit')

        NTPfilesend()
    elif NTPop == 'back':
        option()
    else:
        print('No this option!!!')
        NTPoption()

def DNSmsgsend_ttl():
    while True:
        message = input('Type a message: ')
        if message == '>exit':
            IPoption()
        message = message + "\n"

        craft_pkt = DNSpacketBuilder.craft('x', 1) #check ttl shift
        send(craft_pkt, verbose=False)
        time.sleep(0.5)

        for msg in message:
            print("On sending: " + msg)
            craft_pkt = DNSpacketBuilder.craft(msg, 0)
            send(craft_pkt, verbose=False)

def NTPmsgsend_ttl():
    while True:
        message = input('Type a message: ')
        if message == '>exit':
            IPoption()
        message = message + "\n"

        craft_pkt = NTPpacketBuilder.craft('x', 8) #check ttl shift
        send(craft_pkt, verbose=False)
        time.sleep(0.5)

        for msg in message:
            print("On sending: " + msg)
            craft_pkt = NTPpacketBuilder.craft(msg, 9)
            send(craft_pkt, verbose=False)
def ICMPmsgsend_ttl():
    while True:
        message = input('Type a message: ')
        if message == '>exit':
            IPoption()
        message = message + "\n"

        craft_pkt = ICMPpacketBuilder.craft('', 7) #check ttl shift
        send(craft_pkt, verbose=False)
        time.sleep(0.5)

        for msg in message:
            print("On sending: " + msg)
            craft_pkt = ICMPpacketBuilder.craft(msg, 8)
            send(craft_pkt, verbose=False)
def IPoption():
    print('  _____ _____     _________ _______ _    __  ')
    print(' |_   _|  __ \   / /__   __|__   __| |   \ \ ')
    print('   | | | |__) | | |   | |     | |  | |    | |')
    print('   | | |  ___/  | |   | |     | |  | |    | |')
    print('  _| |_| |      | |   | |     | |  | |____| |')
    print(' |_____|_|      | |   |_|     |_|  |______| |')
    print('                 \_\                     /_/ ')
    print('Option:')
    print('00. IP(TTL) DNS covert channel (Text only)')
    print('01. IP(TTL) NTP covert channel (Text only)')
    print('02. IP(TTL) ICMP covert channel (Text only)')
    print('back. Previous page')

    IPop = input('Enter number: ')

    if IPop == '00':
        print('* Using -> IP(TTL) DNS covert channel (Text only)')
        print('* Type \">exit\" to exit')

        DNSmsgsend_ttl()
    elif IPop == '01':
        print('* Using -> IP(TTL) NTP covert channel (Text only)')
        print('* Type \">exit\" to exit')

        NTPmsgsend_ttl()
    elif IPop == '02':
        print('* Using -> IP(TTL) ICMP covert channel (Text only)')
        print('* Type \">exit\" to exit')

        ICMPmsgsend_ttl()
    elif IPop == 'back':
        option()
    else:
        print('No this option!!!')
        IPoption()
def actioninpacket(pkt):
    protocol = pkt['UDP'].sport
    sport = pkt['UDP'].dport

    if protocol == 53:
        # pkt.show()
        if pkt.haslayer(DNSRR):
            try:
                if pkt['DNSRR'].rdata[0].decode("utf-8") == '123.123.123.100':
                    DNSchannelCheck[0] = 1
                elif pkt['DNSRR'].rdata[0].decode("utf-8") == '123.123.123.123':
                    fileTranferCheck[0] = 1
                elif pkt['DNSRR'].rdata[0].decode("utf-8") == '123.123.123.124':
                    fileTranferCheck[0] = 0
            except:
                pass
    elif protocol == 123:
        #pkt.show()
        #print(NTP)
        geetr = str(pkt["Raw"].load)
        geetr = geetr[2]
        #print(geetr)
        if geetr == "0":
            #print ('** Data loss or corruption occur **')
            NTPfileTranferCheck[0] = 0
        elif geetr == "1":
            #print ('** Data not loss or corruption occur **')
            NTPfileTranferCheck[0] = 1
        elif geetr == "t":
            #print ("** It works!! **")
            NTPchannelCheck[0] = 1
        # fileTranferCheck[0] = 3
def actioninICMPpacket(pkt):
    if pkt[ICMP].type == 0 and pkt[Raw].load.decode("ascii") == "same":
        #ICMPchannelCheck = "1"
        ICMPfileTranferCheck[0] = 1
    elif pkt[ICMP].type == 0 and pkt[Raw].load.decode("ascii") == "notsame":
        ICMPfileTranferCheck[0] = 0
    if pkt[ICMP].type == 0 and pkt[Raw].load.decode("ascii") == "ok":
        ICMPchannelCheck[0] = 1
def isIPv4(s):
    try: return str(int(s)) == s and 0 <= int(s) <= 255
    except: return False

def option():
    print('   _____                    _      _____ _                            _ ')
    print('  / ____|                  | |    / ____| |                          | |')
    print(' | |     _____   _____ _ __| |_  | |    | |__   __ _ _ __  _ __   ___| |')
    print(' | |    / _ \ \ / / _ \ \'__| __| | |    | \'_ \ / _` | \'_ \| \'_ \ / _ \ |')
    print(' | |___| (_) \ V /  __/ |  | |_  | |____| | | | (_| | | | | | | |  __/ |')
    print('  \_____\___/ \_/ \___|_|   \__|  \_____|_| |_|\__,_|_| |_|_| |_|\___|_|')
    print('')
    print('Server ip address: ' + getServerAddress())
    print('Client local ip address: ' + getClientLocalIP())
    print('Client public ip address: ' + getClientPublicIP())
    print('Message encryption mode: ' + str(encryptionMode))
    Systemcheck.requirements()
    print('Option:')
    print('00. Set target server IP address')
    print('01. Covert channel feasibility test')
    print('02. DNS covert channel')
    print('03. ICMP covert channel')
    print('04. NTP covert channel')
    print('05. IP(TTL) covert channel')

    op = input('Enter number: ')
    if op == '00':
        ip = input('Enter target server IP address or domain name(Type "C" to cancel): ')
        if ip == "C":
            option()
        try:
            setServerAddress(socket.gethostbyname(ip))
            print('IP address has been set!!!')
            print('Going back to first page...')
            time.sleep(1.0)
        except:
            if ip.count(".") == 3 and all(isIPv4(i) for i in ip.split(".")):
                setServerAddress(str(ip))
                print('IP address has been set!!!')
                print('Going back to first page...')
                time.sleep(1.0)
            else:
                print('Invalid IP address!!! Please input valid IP address!')
                print('Going back to first page...')
                time.sleep(1.0)
        option()
    elif op == '01':
        print('Covert channel feasibility test result:')
        time.sleep(1.0)
        DNSfeasibilityCheck()
        ICMPfeasibilityCheck()
        NTPfeasibilityCheck()
        time.sleep(1.0)
        print('Going back to first page...')
        time.sleep(1.0)
        print()

        option()
    elif op == '02':
        DNSoption()
    elif op == '03':
        ICMPoption()
    elif op == '04':
        NTPoption()
    elif op == '05':
        IPoption()
    else:
        print('No this option!!!')
        option()
ICMPchannelCheck = [0]
DNSchannelCheck = [0]
NTPchannelCheck = [0]

fileTranferCheck = [3]
NTPfileTranferCheck = [3]
ICMPfileTranferCheck = [3]

def job():
    sniff(filter = "ip and udp", prn = actioninpacket)

t = threading.Thread(target = job)
t.start()

def job2():
    sniff(filter = "icmp", prn = actioninICMPpacket)

t2 = threading.Thread(target = job2)
t2.start()

option()
