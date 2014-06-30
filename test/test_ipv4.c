/*
*    libFNR - A reference implementation library for FNR encryption mode.
*
*    FNR represents "Flexible Naor and Reingold" mode

*    FNR is a small domain block cipher to encrypt small domain
*    objects ( < 128 bits ) like IPv4, MAC, Credit Card numbers etc.

*    FNR is designed by Sashank Dara (sadara@cisco.com), Scott Fluhrer (sfluhrer@cisco.com)
*
*    test_ipv4.c is written by Kaushal Bhandankar (kbhandan@cisco.com)
*
*    Copyright (C) 2014 , Cisco Systems Inc.
*
*    This library is free software; you can redistribute it and/or
*    modify it under the terms of the GNU Lesser General Public
*    License as published by the Free Software Foundation; either
*    version 2.1 of the License, or (at your option) any later version.
*
*    This library is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*    Lesser General Public License for more details.
*
*    You should have received a copy of the GNU Lesser General Public
*    License along with this library; if not, write to the Free Software
*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*
**/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include "fnr.h"
#include <openssl/aes.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

void generate_master_key(char* passwd, char*  key) {
  unsigned char salt[16];
  if(!(RAND_bytes(salt, sizeof(salt)))) {
    printf("ERROR: call to RAND_bytes() failed\n");
    exit(1);
  }
  PKCS5_PBKDF2_HMAC_SHA1(passwd, strlen(passwd), (unsigned char*)salt, strlen(salt), 1000, 16, key);
}

/*convert the raw IP from a.b.c.d format to unsigned int format.*/
unsigned int ipv4_rank(char * ip_str){
    unsigned int a,b,c,d;
    sscanf(ip_str, "%d.%d.%d.%d", &a, &b, &c, &d);
    return (a << 24) + (b << 16) + (c << 8) + d; 
}

/*convert the raw IP from unsigned int format to a.b.c.d format.*/
char * ipv4_derank(unsigned int ip){
    unsigned int a,b,c,d;
    char * ip_str = (char *)calloc(16, 1);
    a = ip >> 24;
    b = (ip << 8) >> 24;
    c = (ip << 16) >> 24;
    d = (ip << 24) >> 24;

    sprintf(ip_str, "%d.%d.%d.%d", a, b, c, d);
    return ip_str;
}

int main(int argc, char * argv[]) {
    static unsigned char orig_key[16] = {0};
    char *passwd = NULL , *tweak_str = NULL , *filename = NULL, ip_str[16] = {0};
    int c, ret ;
    FILE * f;
    unsigned int *p_raw_addr = NULL, raw_addr, encrypted_addr;
    unsigned int num_ip_addresses = 0, loop_count = 0;
    char *no_ip_str;
#ifdef DEBUG
    char *ip_address_str = NULL;
#endif

    if (argc != 7) {
        fprintf(stderr, "usage: ipv4test -p passwd -t tweak -f raw-trace-file\n");
        exit(-1);
    }

     while ((c = getopt (argc, argv, "p:t:f:")) != -1){
         switch (c)
           {
           case 'p':
             passwd = optarg;
             break;
           case 't':
             tweak_str = optarg;
             break;
           case 'f':
             filename = optarg; /* Could be used when inputs are read from file */
             break;
           case '?':
             if (optopt == 'c')
               fprintf (stderr, "Option -%c requires an argument.\n", optopt);
             else if (isprint (optopt))
               fprintf (stderr, "Unknown option `-%c'.\n", optopt);
             else
               fprintf (stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
             return 1;
           default:
             abort ();
           }
     }

#ifdef DEBUG
    printf ("%s, %s, %s\n", passwd, tweak_str, filename);
    printf("-----------------------------------------------------------\n");
#endif
    if ((f = fopen(filename,"r")) == NULL) {
        fprintf(stderr,"Cannot open file %s\n", argv[1]);
        exit(-2);
    }

    /* Init */
    FNR_init();

    /* Initialize the keys and tweaks */
    generate_master_key(passwd,orig_key);
    fnr_expanded_key *key = FNR_expand_key(orig_key, 128, 32);
    if (!key) {
        fprintf( stderr, "Error expanding key\n" );
        return 0;
    }

    fnr_expanded_tweak tweak;
    FNR_expand_tweak(&tweak, key, (void*)tweak_str, strlen(tweak_str));

    fgets(no_ip_str, 10, f);
    num_ip_addresses = atoi(no_ip_str);
    p_raw_addr = (unsigned int *)malloc(sizeof(int)* num_ip_addresses);
    if(NULL == p_raw_addr){
        fprintf(stderr,"Cannot allocate memory for %d IP addresses\n", num_ip_addresses);
        exit(-3);
    }

    while(fgets(ip_str, 16 , f) != NULL) {
        p_raw_addr[loop_count] = ipv4_rank(ip_str);
        FNR_burn(ip_str, 16);
        ++loop_count;
    }

    loop_count = 0;
         
    clock_t start, end;
    double cpu_time_used;

    //Performance test start
    start = clock();
    while(loop_count < num_ip_addresses){

        encrypted_addr = raw_addr = p_raw_addr[loop_count];

#ifdef DEBUG
        ip_address_str = ipv4_derank(raw_addr);
        printf("Input\t\t%s\n", ip_address_str);
        free(ip_address_str);
#endif

        FNR_encrypt(key, &tweak, &raw_addr, &encrypted_addr);

#ifdef DEBUG
        ip_address_str = ipv4_derank(encrypted_addr);
        printf("Ciphertext\t%s\n", ip_address_str);
        free(ip_address_str);
#endif

        FNR_decrypt(key, &tweak, &encrypted_addr, &raw_addr);

#ifdef DEBUG
        ip_address_str = ipv4_derank(raw_addr);
        printf("Plaintext\t%s\n", ip_address_str);
        free(ip_address_str);
        printf("-----------------------------------------------------------\n");

        if(raw_addr != p_raw_addr[loop_count]){
            printf("ERROR: decrypt output does not match the user input\n");
            exit(-4);
        }
#endif

        ++loop_count;
    }

    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    //Performance test end 

    //printf("CPU time used %f\n", cpu_time_used);
    printf("%d , %f\n",num_ip_addresses, cpu_time_used);
    free(p_raw_addr);
    FNR_release_key(key);
    FNR_shut();
    return 0;
}
