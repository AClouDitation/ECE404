#! /usr/bin/env python3

import socket

dst_host = "127.0.0.1"
def scanTarget(rangeStart, rangeEnd):

    open_ports = []

    for testport in range(rangeStart, rangeEnd+1):
        print("testing", testport)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            sock.connect((dst_host, testport))
            open_ports.append(testport)
        except:
            pass

    with open("openports.txt", "w") as fp:
        for port in open_ports:
            fp.write("%d\n"%(port))

def attackTarget(port, numSyn):

    IP_header = IP(src="127.0.0.1", dest=dst_host)
    TCP_header = TCP(flags="s", sport=RandShort(), dport=port)
    packet = IP_header/TCP_header

    try:
        send(packet)
    except Exception as e:
        print(e)


if __name__ == "__main__":
    scanTarget(0,2000)
    attackTarget(631, 5)
