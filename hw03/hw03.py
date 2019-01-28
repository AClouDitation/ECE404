#! /usr/bin/env python3

def _isPrime(n):

    for i in range(2, int(n**(1/2))):
        if n % i == 0:
            return False
    return True

if __name__ == "__main__":

    n = int(input("Please Enter a number:"))
    if _isPrime(n):
        print("field")
    else:
        print("ring")

