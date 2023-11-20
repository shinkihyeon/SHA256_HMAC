#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define MAC_SIZE 32

//SHA-256 연산에 필요한 매크로들
#define ROTR(input,n) (((input)>>(n)) | ((input)<<(32-(n))))
#define CH(x,y,z) (((x) & (y)) ^ ((~x) & (z)))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define sigma0(x) ((ROTR((x), 2)) ^ (ROTR((x), 13)) ^ (ROTR((x), 22)))
#define sigma1(x) ((ROTR((x), 6)) ^ (ROTR((x), 11)) ^ (ROTR((x), 25)))
#define df0(x) ((ROTR((x), 7)) ^ (ROTR((x), 18)) ^ ((x) >> 3))
#define df1(x) ((ROTR((x), 17)) ^ (ROTR((x), 19)) ^ ((x) >> 10))

//SHA_256
void cut_st(uint8_t* input, uint32_t* output);
void SHA256_padding(uint8_t* input, uint32_t pt_len, uint32_t MSG_LEN);
void SHA256(uint8_t* MSG, uint64_t MSG_len, uint8_t* output);
void WordToByte(uint32_t* input, uint8_t* output);

//HMAC
void HMAC(uint8_t* text, uint32_t text_len, uint8_t* h_key, int keylen, uint8_t* output);
