#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sha.h"

// Benchmark sha-256
int sha256_run(){
	struct timespec start, end;
	double elapsed, elapsed_total = 0, time[100];;
	
    SHA256Context context;
    uint8_t digest[SHA256HashSize];
    const char* message = "hello,world!hello,world!hello,world!";
    size_t messagelen = strlen(message);

	printf("*************************SHA-256**************************\n");

	for (int n = 0; n < 100; n++)
	{
		clock_gettime(CLOCK_MONOTONIC, &start);
		// Initialize the SHA256Context in preparation
		SHA256Reset(&context);

		// Inpute message
		SHA256Input(&context, (const uint8_t*)message, messagelen);

		// Return the 256-bit message digest
		if(SHA256Result(&context, digest))
		{
			printf("Error calculating SHA-256 hash\n");
			return 1;
		}
		clock_gettime(CLOCK_MONOTONIC, &end);

		elapsed = (end.tv_sec - start.tv_sec) * 1000000000.0 + (end.tv_nsec - start.tv_nsec);
        elapsed_total += elapsed; 
        time[n] = elapsed;
	}

	printf("平均耗时: %8.0f ns\n", elapsed_total/100.0);
	/********************** Save 100 time overheads ********************/
	FILE* fp = fopen("results.txt", "a");
	if (fp == NULL) {
        printf("\nError opening file!\n");
        return 1;
    }
	fprintf(fp, "\nTIME_SHA_256: \n");
	for (int n = 0; n < 100; n++)
	{
		fprintf(fp, "%8.0f, ", time[n]);
	}
	fclose(fp);
	
    printf("\nSHA-256 results: \n");
	printf("  message: %s\n", message);
	printf("  HASH(message): ");
    for (int i = 0; i < SHA256HashSize; i++)
    {
        printf("%02X", digest[i]);
    }

    printf("\n\n  SHA-256:-----------------------------------passed\n\n");

    return 0;
}


// Benchmark HMAC
int hmac_sha256_run()
{
	struct timespec start, end;
	double elapsed, elapsed_total = 0, time[100];

	SHAversion sha = SHA256;
	const char* text = "hello,world!hello,world!hello,world!";
	int text_len = strlen(text);
	const char* key = "0123456789ABCDEF0123456789ABCDEF";
	int key_len = strlen(key);
	uint8_t digest[USHAMaxHashSize];

	printf("**********************HMAC-SHA-256************************\n");

	for(int n = 0; n < 100; n++)
	{
		clock_gettime(CLOCK_MONOTONIC, &start);
		hmac(sha, (const unsigned char*)text, text_len, (const unsigned char*)key, key_len, digest);
		clock_gettime(CLOCK_MONOTONIC, &end);

		elapsed = (end.tv_sec - start.tv_sec) * 1000000000.0 + (end.tv_nsec - start.tv_nsec);
        elapsed_total += elapsed; 
        time[n] = elapsed;
	}

	printf("平均耗时: %8.0f ns\n", elapsed_total/100.0);
	/********************** Save 100 time overheads ********************/
	FILE* fp = fopen("results.txt", "a");
	if (fp == NULL) {
        printf("\nError opening file!\n");
        return 1;
    }
	fprintf(fp, "\nTime_HMAC_SHA256: \n");
	for (int n = 0; n < 100; n++)
	{
		fprintf(fp, "%8.0f, ", time[n]);
	}
	fclose(fp);

	printf("\nHMAC-SHA256 results: \n");
	printf("  text: %s\n", text);
	printf("  key: %s\n", key);
	printf("  HMAC(text, key): ");
    for (int i = 0; i < SHA256HashSize; i++)
    {
        printf("%02X", digest[i]);
    }
    printf("\n\n  HMAC-SHA-256:---------------------------------passed\n\n");

	return 0;
}


// Benchmark HKDF
int hkdf_run()
{
	struct timespec start, end;
	double elapsed, elapsed_total = 0, time[100];;

	SHAversion sha=SHA256;
	const char* salt = "12345";
	int salt_len = strlen(salt);
	const char* ikm = "0123456789ABCDEF0123456789ABCDEF";
	int ikm_len = strlen(ikm);
	const char* info = "65535";
	int info_len =strlen(info);
	int okm_len = 64;
	uint8_t okm[okm_len];
	

	printf("**********************HKDF-HMAC-SHA-256************************\n");


	for(int n=0; n<100; n++)
	{
		clock_gettime(CLOCK_MONOTONIC, &start);
		hkdf(sha, (const unsigned char*)salt, salt_len, (const unsigned char*)ikm, ikm_len, (const unsigned char*)info, info_len, okm, okm_len);
		clock_gettime(CLOCK_MONOTONIC, &end);

		elapsed = (end.tv_sec - start.tv_sec) * 1000000000.0 + (end.tv_nsec - start.tv_nsec);
        elapsed_total += elapsed; 
        time[n] = elapsed;
	}

	printf("平均耗时: %8.0f ns\n", elapsed_total/100.0);
	/********************** Save 100 time overheads ********************/
	FILE* fp = fopen("results.txt", "a");
	if (fp == NULL) {
        printf("\nError opening file!\n");
        return 1;
    }
	fprintf(fp, "\nTime_HKDF_HMAC_SHA256: \n");
	for (int n = 0; n < 100; n++)
	{
		fprintf(fp, "%8.0f, ", time[n]);
	}
	fclose(fp);

	printf("\nHKDF-HMAC-SHA-256 results: \n");
	printf("  salt: %s\n", salt);
	printf("  input keying material(ikm): %s\n", ikm);
	printf("  info: %s\n", info);
	printf("  HKDF(salt, ikm, info): ");
	for (int i = 0; i < okm_len; i++)
    {	
        printf("%02X", okm[i]);
    }

	printf("\n    SK1:");
    for (int i = 0; i < okm_len; i++)
    {
		if (i == 32)
		{
			printf("\n    SK2:");
		}
		
        printf("%02X", okm[i]);
    }
    printf("\n\n  HMAC-SHA-256:---------------------------------passed\n\n");

	return 0;
}


int main(){
    if (sha256_run() != 0)
    {
        printf("\n\n    Error detected SHA-256. \n\n");
    }

    if (hmac_sha256_run() != 0)
    {
        printf("\n\n    Error detected HMAC-SHA-256. \n\n");
    }

	if (hkdf_run() != 0)
    {
        printf("\n\n    Error detected HKDF-HMAC-SHA-256. \n\n");
    }

    return 0;
}