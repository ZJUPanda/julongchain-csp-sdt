#include<stdio.h>
#include<malloc.h>
#include "SM3.h"
#include "SM2.h"

void print_0x(U8 *ch, int len){
    for(int i = 0; i < len; i++){
        if(i%4 == 0){
            printf(" 0x");
        }
        printf("%02x", ch[i]);
        if((i+1)%32==0){
            printf("\n");
        }
    }
    printf("\n");
}

int main(void){

/*  // sm3 hash test   
    U8 *msg = "abc";
    U32 msg_len = 4;
    U32 hash_len = 32;
    U8 *hash = (U8 *)malloc(sizeof(U8) * hash_len);
    int success = SM3_Hash(msg , msg_len, hash, hash_len);
    if(!success){
        printf("success\n");
        for(int i=0; i<hash_len; i++){
            printf("%x",hash[i]);
        }
        printf("\n");
    }
 */

    // 1. test for signing
    U32 msg_len = 46;
    U8 _M[46] = {
        0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 
        0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
        0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
        0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, // ZA
        0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
        0x64, 0x69, 0x67, 0x65, 0x73, 0x74              // message
    };
    U32 hash_len = 32;
    U8 *hash = (U8 *)malloc(sizeof(U8) * hash_len);
    int hash_success = SM3_Hash(_M , msg_len, hash, hash_len);
    
    U8 random[32] = {
        0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A,
        0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D, 0xCC,
        0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE,
        0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21
    };
    U32 random_len = 32;

    U8 sk[32] = {
        0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1,
        0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3, 0x9F, 0x95,
        0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A,
        0x42, 0xFB, 0x81, 0xEF, 0x4D, 0xF7, 0xC5, 0xB8
    };
    U32 sk_len = 32;

    U32 sign_len = 64;
    U8 *sign = (U8 *)malloc(sizeof(U8) * sign_len);
    int sign_success = 1;
    while(sign_success){
        sign_success = EccSign(hash, hash_len, random, random_len,
                                sk, sk_len, sign, &sign_len);
    }
    printf("sign result(r,s):\n");
    print_0x(sign, sign_len);

    // 2. test for sign verifying
    U8 pk[64] = {
        0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1,
        0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
        0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07,
        0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
        0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5,
        0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
        0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A,
        0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13
    };
    U32 pk_len = 64;
    int verify = EccVerify(hash, hash_len, pk, pk_len, sign, sign_len);
    if(!verify){
        printf("verify result: success!\n\n");
    }

    // 3. test for encryption
    U8 *plain_in = "encryption standard";
    U32 plain_len = 19;  

    U32 cipher_len = plain_len + 96;
    U8 * cipher = (U8 *)malloc(sizeof(U8) * cipher_len);
    int encrypt = EccEncrypt(plain_in, plain_len, random, random_len, pk, pk_len, cipher, &cipher_len);
    printf("plain_in:\n");
    print_0x(plain_in, plain_len);
    if(!encrypt){
        printf("\nencrypt result(Cipher):\n");
        print_0x(cipher, cipher_len);
    }


    // 4. test for decryption

    U8 plain_out[plain_len];
    int decrypt = EccDecrypt(cipher, cipher_len, sk, sk_len, plain_out, &plain_len);
    if(!decrypt){
        printf("\ndecrypt result(plain_out):\n");
        print_0x(plain_out, plain_len);
    }

    free(hash);
    free(sign);
    free(cipher);
    return 0;
}