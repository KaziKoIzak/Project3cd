#ifndef _FME_H
#define _FME_H

#include <stdio.h>

unsigned int gcd(unsigned int a, unsigned int b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

unsigned int find_smallest_relative_prime(unsigned int num) {
    unsigned int relative_prime = 2;
    while (gcd(num, relative_prime) != 1) {
        relative_prime++;
    }
    
    return relative_prime;
}
 
// Function for extended Euclidean Algorithm
int gcdExtended(int a, int b, int* x, int* y)
{
 
    // Base Case
    if (a == 0) {
        *x = 0, *y = 1;
        return b;
    }
 
    // To store results of recursive call
    int x1, y1;
    int gcd = gcdExtended(b % a, a, &x1, &y1);
 
    // Update x and y using results of recursive
    // call
    *x = y1 - (b / a) * x1;
    *y = x1;
 
    return gcd;
}

// Function to find modulo inverse of a
int modInverse(int A, int M)
{
    int x, y;
    int g = gcdExtended(A, M, &x, &y);
    if (g != 1)
        printf("\n");
    else {
 
        // m is added to handle negative x
        int res = (x % M + M) % M;
        return res;
    }

    return 0;
}

unsigned int fastModExpo(unsigned int base, unsigned int exponent, unsigned int modulus)
{
    unsigned int result = 1;
    base = base % modulus;

    while (exponent > 0)
    {
        if (exponent % 2 == 1)
        {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1;
        base = (base * base) % modulus;
    }

    return result;
}

unsigned int FME(unsigned int base, unsigned int exponent, unsigned int modulus)
{
    unsigned int result = fastModExpo(base, exponent, modulus);

    return result;
}

#endif