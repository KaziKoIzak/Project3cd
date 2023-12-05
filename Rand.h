#ifndef _RAND_H
#define _RAND_H

#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>

bool is_prime(unsigned int n)
{
    if (n <= 1)
        return false;
    if (n <= 3)
        return true;
    if (n % 2 == 0 || n % 3 == 0)
        return false;

    for (unsigned int i = 5; i * i <= n; i += 6)
    {
        if (n % i == 0 || n % (i + 2) == 0)
            return false;
    }

    return true;
}

unsigned int generate_random_prime()
{
    unsigned int candidate;
    do
    {
        candidate = rand() % (300 - 1) + 2; // Generate a random number between 2 and UINT_MAX
    } while (!is_prime(candidate));
    return candidate;
}

unsigned int randomPrime()
{
    srand(clock());

    unsigned int random_prime = generate_random_prime();

    return random_prime;
}

unsigned int mod_pow(unsigned int base, unsigned int exponent, unsigned int modulus) {
    unsigned int result = 1;
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }
    return result;
}

bool is_primitive_root(unsigned int g, unsigned int p) {
    unsigned int phi = p - 1;
    for (unsigned int i = 2; i <= phi; i++) {
        if (mod_pow(g, i, p) == 1) {
            return false;
        }
    }
    return true;
}

unsigned int find_primitive_root(unsigned int p) {
    for (unsigned int g = 2; g < p; g++) {
        if (is_primitive_root(g, p)) {
            return g;
        }
    }
    return 0;
}

unsigned int primitiveRoot(unsigned int p) {
    unsigned int primitive_root = find_primitive_root(p);

    if (primitive_root != 0) {
        printf("A primitive root modulo %u is %u\n", p, primitive_root);
    } else {
        printf("No primitive root found modulo %u\n", p);
    }

    return primitive_root;
}


#endif