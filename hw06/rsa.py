#! /usr/bin/env python3

from PrimeGenerator import *
from BitVector import *
import os
import sys

e = 65537 # public key

def gcd(a, b):
    if b == 0: return a
    return gcd(b, a%b)


def RSAEncryption(bv, key, n):
    '''
    Encrypt msg with key using modulus n
    '''
    bv.pad_from_right(128-len(bv))  # pad to the right if less then 128 bits
    bv.pad_from_left(128)           # pad to the 128 bits to the left make a
                                    # total of 256 bits

    return BitVector(intVal=pow(int(bv), int(key), n),size=256)

    
def RSADecryption(bv, key, n):
    '''
    Decrypt msg with key using modulus n
    '''
    bv = BitVector(intVal = pow(int(bv), int(key), n),size=256)
    return bv[-128:] # take the right most 128 bits


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
    with open("p.txt", "w") as fp:
        print(p, end='', file=fp)

    with open("q.txt", "w") as fp:
        print(q, end='', file=fp)

    print("p and q generated")


def get_pq_from_file():
    '''
    This function is used to read p and q form file
    ret: p, q
    '''
    with open("p.txt", "r") as fp:
        p = int(fp.read())

    with open("q.txt", "r") as fp:
        q = int(fp.read())

    return p, q


def main():
    if len(sys.argv) != 4:
        print("""Usage: ./rsa.py <flag> <input file> <output file>
        flags:
            -e: encryption
            -d: decryption""")
        sys.exit(1)

    if sys.argv[1] == "-e":
        # encryption mode
        if not os.path.exists("p.txt") or not os.path.exists("q.txt"):
            generateN()

        e_Bv = BitVector(intVal = e)
        p, q = get_pq_from_file()
        n = p * q

        with open(sys.argv[2], "r") as fp:
            msg = fp.read()

        msg_bv = BitVector(textstring=msg)

        with open(sys.argv[3], "w") as fp:
            for i in range(0, len(msg_bv), 128):
                encryptedMsg = RSAEncryption(msg_bv[i:min(len(msg_bv),i+128)], e_Bv, n)
                fp.write(encryptedMsg.get_bitvector_in_hex())
            

    elif sys.argv[1] == "-d":
        # decryption mode
        if not os.path.exists("p.txt") or not os.path.exists("q.txt"):
            print("no p and q found, encrypt first")
            sys.exit(1)

        e_Bv = BitVector(intVal = e)
        p, q = get_pq_from_file()
        n = p * q

        d_Bv = e_Bv.multiplicative_inverse(BitVector(intVal = (p-1)*(q-1)))
        with open(sys.argv[2], "r") as fp:
            msg = fp.read()

        msg_bv = BitVector(hexstring=msg)

        with open(sys.argv[3], "wb") as fp:
            for i in range(0, len(msg_bv), 256):
                decryptedMsg = RSADecryption(msg_bv[i:i+256], d_Bv, n)
                if i + 256 < len(msg_bv):
                    decryptedMsg.write_to_file(fp)
                else:
                    for k in range(0, 128, 8):
                        if int(decryptedMsg[k:k+8]) != 0:
                            decryptedMsg[k:k+8].write_to_file(fp)

    else:
        print("""Usage: ./rsa.py <flag> <input file> <output file>
        flags:
            -e: encryption
            -d: decryption""")
        sys.exit(1)


if __name__ == "__main__":
    main()
