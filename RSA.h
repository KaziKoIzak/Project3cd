#ifndef _RSA_H
#define _RSA_H

#include "FME.h"

unsigned int basicallyRSA(unsigned int p, unsigned int q)
{
    unsigned int totient_n = (p - 1) * (q - 1);

    unsigned int e = find_smallest_relative_prime(totient_n);

    return e;
}

int DRSA(unsigned int p, unsigned int q, unsigned int e)
{
    unsigned int totient_n = (p - 1) * (q - 1);

    int d = modInverse(e, totient_n);

    return d;
}

unsigned int PrimeN(unsigned int p, unsigned int q)
{
    return p * q;
}

unsigned int RSAEncrypt(unsigned int message, unsigned int e, unsigned int n)
{
    return FME(message, e, n);
}

unsigned int RSADecrypt(unsigned int message, unsigned int d, unsigned int n)
{
    return FME(message, d, n);
}

#endif