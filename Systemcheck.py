import os
try:
    import psutil
except ImportError:
    print("Trying to Install required module: psutil")
    os.system('pip3 install psutil')
    import psutil

def requirements():
    cpu = psutil.cpu_count(logical=True)
    ram = psutil.virtual_memory()
    state = 0
    if os.name == 'nt':
        if cpu < 6:
            print("The number of processor does not meet the minimum requirements: >=6")
            state = 1
        if ram.total < 4096*1024*1024:
            print("The memory does not meet the minimum requirements: >=4096MB")
            state += 2
        return state
    elif os.name == 'posix':
        if cpu < 2:
            print("The number of processor does not meet the minimum requirements: >=2")
            state = 1
        if ram.total < 2048*1024*1024:
            print("The memory does not meet the minimum requirements: >=2048MB")
            state += 2
        return state
