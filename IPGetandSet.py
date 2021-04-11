import socket
import urllib.request
from configurator import getConfig, setConfig
def getServerAddress():
    try:
        setting = getConfig("SETTING.txt")
        return setting["ServerAddress"].strip()
    except:
        return 'Please set the server address!'
def getClientLocalIP():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return 'Network Card is down'
    except:
        return 'Error'
def getClientPublicIP():
    try:
        external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
        return external_ip
    except urllib.error.URLError:
        return 'NoNetworkConnection'
    except:
        return 'Error'
def setServerAddress(str):
    setting = getConfig("SETTING.txt")
    setting["ServerAddress"] = str
    setConfig("SETTING.txt", setting)
