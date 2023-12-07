#ifndef _CERT_H
#define _CERT_H
#include "SDES.h"
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

// A structure to hold the certificate fields
typedef struct {
    char version[4];
    char serialNumber[20];
    char signatureAlgorithm[50];
    char issuer[256];
    char validityNotBefore[20];
    char validityNotAfter[20];
    char subject[256];
    char subjectPublicKeyInfo[512];
    char trustLevel[4];
} Certificate;

// A function to read the certificate from a file
void readCertificate(const char *filename, Certificate *cert);
int verifyCert(Certificate* cert, char* currentDate, unsigned char currentHash, int CRLsize);
void writeCertificate(const char *filename, const Certificate* cert);

void writeCertificate(const char *filename, const Certificate* cert) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        printf("Error opening file");
        return;
    }

    fprintf(file, "Version: %s\n", cert->version);
    fprintf(file, "Serial Number: %s\n", cert->serialNumber);
    fprintf(file, "Signature Algorithm: %s\n", cert->signatureAlgorithm);
    fprintf(file, "Issuer: %s\n", cert->issuer);
    fprintf(file, "Validity Not Before: %s\n", cert->validityNotBefore);
    fprintf(file, "Validity Not After: %s\n", cert->validityNotAfter);
    fprintf(file, "Subject: %s\n", cert->subject);
    fprintf(file, "Subject Public Key Info: %s\n", cert->subjectPublicKeyInfo);
    fprintf(file, "Trust Level: %s\n", cert->trustLevel);

    fclose(file);
}

void Certifier(Certificate* readCert, int CRLsize) {
    //Manually change the "current date" to check if certificate is within its valid timeframe
    char currentDate[] = "20231205092956";// YYYY MM DD HH MM SS

    // Read the certificate from the file
    readCertificate("certificate.txt", readCert);

    // Hash the certificate
    bool flag = false;
    char c, ch;
    long long hashKey = 1234;
    // keys(hashKey);

    FILE* hashFileCert = fopen("certificate.txt", "r");
    
    do {
        c = fgetc(hashFileCert);
        if (feof(hashFileCert)) {
            break;
        }

        if(!flag) {
            ch = hash(c);
            flag = true;
        } else {
            ch = hash(c);
        }
    } while(1);

    fclose(hashFileCert);

    unsigned char uch = ch;
    int certIsValid = verifyCert(readCert, currentDate, uch, CRLsize);
    printf("verification function returned %d", certIsValid);

    if (certIsValid == 1) {
        printf("Cert is valid and hashes to: %c\n", uch);
    }

    // Hash the CRL
    flag = false;
    // keys(hashKey);


    FILE* crlFileCert = fopen("CRL.txt", "r");

    do {
        c = fgetc(crlFileCert);
        if (feof(crlFileCert)) {
            break;
        }

        if(!flag) {
            ch = hash(c);
            flag = true;
        } else {
            ch = hash(c);
        }
    } while(1);

    fclose(hashFileCert);

    uch = ch;

    FILE* crlHash = fopen("crlHash.txt", "r");
    unsigned char crlHashChar = fgetc(crlHash);

    if (uch == crlHashChar) {
        printf("CRL is valid and hashes to:  %c\n", uch);
    } else {
        printf("CRL is not valid - hashes do not match");
    }

    fclose(crlHash);
    
    return;
}

// A function to read the certificate from a file
void readCertificate(const char *filename, Certificate *cert) {
    char line[100];
    char *issuerValue;

    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Error opening file.\n");
    }
    fscanf(file, "Version: %s\n", cert->version);
    fscanf(file, "Serial Number: %s\n", cert->serialNumber);
    fscanf(file, "Signature Algorithm: %s\n", cert->signatureAlgorithm);
    fgets(line, sizeof(line), file);
    issuerValue = strstr(line, "Issuer: ");
    issuerValue += strlen("Issuer: ");
    int destIndex = 0;    
    for (int i = 0; i < strlen(issuerValue); i++) {
        if (issuerValue[i] != '\n') {
            cert->issuer[destIndex] = issuerValue[i];
            destIndex++;
        }
    }
    fscanf(file, "Validity Not Before: %s\n", cert->validityNotBefore);
    fscanf(file, "Validity Not After: %s\n", cert->validityNotAfter);
    fgets(line, sizeof(line), file);
    issuerValue = "";
    issuerValue = strstr(line, "Subject: ");
    issuerValue += strlen("Subject: ");
    destIndex = 0;    
    for (int i = 0; i < strlen(issuerValue); i++) {
        if (issuerValue[i] != '\n') {
            cert->subject[destIndex] = issuerValue[i];
            destIndex++;
        }
    }
    fscanf(file, "Subject Public Key Info: %s\n", cert->subjectPublicKeyInfo);
    fscanf(file, "Trust Level: %s\n", cert->trustLevel);

    fclose(file);
}

int verifyCert(Certificate* cert, char* currentDate, unsigned char currentHash, int CRLsize) {
    //returns true if cert is valid, false otherwise
    int valid = 1;

    //Check if current date is before "valid not before" date
    if (strcmp(cert->validityNotBefore, currentDate) > 0) {
        printf("Cert is not valid. Current date is before certificate validity start.\n");
        valid = 0;
    }

    //Check if current date is after "valid not after" date
    if (strcmp(cert->validityNotAfter, currentDate) < 0) {
        printf("Cert is not valid. Current date is after certificate validity end.\n");
        valid = 0;
    }

    //Check if certificate hashes to the same value
    FILE* hashFile = fopen("certHash.txt", "r");
    if (!hashFile) {
        printf("Error opening certificate hash\n");
    }
    char storedHash = fgetc(hashFile);
    fclose(hashFile);

    if (storedHash != currentHash) {
        printf("Cert hashes to: %c\n", currentHash);
        printf("Cert is not valid. Cert has been modified - hashes do not match.\n");
        valid = 0;
    }

    //Check if certificate is in CRL list
    char revoked;
    FILE* revokationList = fopen("CRL.txt", "r");

    printf("%d", CRLsize);
    for (int i = 0; i < CRLsize; i++) {
        //printf("revoked: %c\n", revoked);
        if(storedHash == revoked) {
            printf("Cert is not valid. Cert appears on Certificate Revocation List.\n");
            printf("valid = %d", valid);
            valid = 0;
        }
    }

    /*
    while ((revoked = fgetc(revokationList)) != '\0') {
        printf("revoked: %c\n", revoked);
        if(storedHash == revoked) {
            printf("Cert is not valid. Cert appears on Certificate Revocation List.\n");
            printf("valid = %d", valid);
            valid = 0;
        }
    } */

    return valid;
}

#endif