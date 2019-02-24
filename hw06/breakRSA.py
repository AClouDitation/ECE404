#! /usr/bin/env python3 

from PrimeGenerator import *
from BitVector import *
from solve_pRoot import solve_pRoot as sp
import sys

e = 3

def gcd(a, b):
    if b == 0: return a
    return gcd(b, a%b)


def generateN():
    '''
    This function is used to generate two prime numbers p, q while guaranteeing:
    1. p != q
    2. p, q are coprime to e
    3. 2 left most bits of p and q are set
    ret: p, q, n
    '''
    generator = PrimeGenerator(bits = 128)

    p = -1
    q = -1
    while(True):
        p = generator.findPrime()
        q = generator.findPrime()
        while(q == p):
            q = generator.findPrime()
        if gcd((p-1),e) == 1 and gcd((q-1),e) == 1:
            break

    return p,q,p*q


def RSAEncryption(bv, key, n):
    '''
    Encrypt msg with key using modulus n
    '''
    
    bv.pad_from_right(128-len(bv))  # pad to the right if less then 128 bits
    bv.pad_from_left(128)           # pad to the 128 bits to the left make a
                                    # total of 256 bits

    return BitVector(intVal=pow(int(bv), int(key), n),size=256)


def CRT(rs):
    
    '''
    This function is used to find the desired number with Chinese Reminder Theorem
    rs is a list of tuples containing (n, reminder using modulus n)
    '''
    prod = 1
    for r in rs:
        prod *= r[0]

    coeff = [prod // r[0] for r in rs]
   
    sum = 0
    for index, r in enumerate(rs):
        mi = int(BitVector(intVal = coeff[index]).multiplicative_inverse(BitVector(intVal=r[0])))
        sum += (r[1] * mi % r[0]) * coeff[index]
        sum %= prod

    return sum
    

if __name__ == "__main__":

    # generate p, q, n for 3 receivers
    receivers = [generateN() for i in range(3)]

    e_bv = BitVector(intVal = e)
    with open(sys.argv[1], "r") as fp:
        msg = fp.read()

    msg_bv = BitVector(textstring=msg)
    encryptedMsg = [BitVector(size=0) for _ in range(3)]

    # for each receiver, encrypt the message with their respectively public key
    for index, receiver in enumerate(receivers):

        with open("receiver_%d_encryted.txt"%(index), "wb") as fp:
            fp.write(("n:%d\n"%(receiver[2])).encode())
            for i in range(0, len(msg_bv), 128):
                encryptedMsg[index] += RSAEncryption(msg_bv[i:min(len(msg_bv),i+128)], e_bv, receiver[2])
            encryptedMsg[index].write_to_file(fp)

    # crack RSA with CRT
    with open(sys.argv[2], "wb") as fp:
        for i in range(0, len(encryptedMsg[0]), 256):
            rs = [(receivers[j][2], int(encryptedMsg[j][i:i+256])) for j in range(len(receivers))]
            msg_cube = CRT(rs)
            print("block %d cracked"%(i//256))
            sys.stdout.flush()

            # take cube root
            msg = BitVector(intVal = sp(3, msg_cube), size=128)
            msg.write_to_file(fp)