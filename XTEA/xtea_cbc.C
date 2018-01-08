//
// Created by Ashwin S on 10/25/17.
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

void hexdump_to_string(const void *data, int size, char *str) {
    const unsigned char *byte = (unsigned char *)data;
    while (size > 0) {
        size--;
        sprintf(str, "%.2x ", *byte);
        byte++;
        str+=2;
    }
}

void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]);

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]);

uint32_t* encryptWithCBC(unsigned int num_rounds, uint32_t* v, unsigned int v_len, uint32_t const
key[4], uint32_t iv[2]);

uint32_t* decryptWithCBC(unsigned int num_rounds, uint32_t* v, unsigned int v_len, uint32_t const
key[4], uint32_t iv[2]);

void padMessage(char *msg, unsigned int msg_len, uint32_t** padded_msg, unsigned int *padded_msg_len);

void unpadMessage(char **msg, unsigned int *msg_len, uint32_t* padded_msg, unsigned int padded_msg_len);

void bitXOR(uint32_t msgblock[2],uint32_t iv[2]);

int lenpad =0;
int main(int argc, char **argv)
{
    FILE *msg_fp;
    FILE *key_fp;
    FILE *encrypted_msg_fp;
    FILE *decrypted_msg_fp;

    int num_rounds;
    msg_fp = fopen("message.txt", "r");
    key_fp = fopen("key.txt", "r");
    encrypted_msg_fp = fopen("encrypted_msg.bin", "wb");
    decrypted_msg_fp = fopen("decrypted_msg.txt", "w");
    if (argc == 2) {
        num_rounds = (unsigned int)atoi(argv[1]);
    } else {
        printf("Program needs 1 input - number of rounds\n");
        return 0;
    }

    // read key from key file
    if (key_fp == NULL)
    {
        printf("Cannot open key file \n");
        exit(0);
    }
    char key[1024];
    while ( fgets(key, 1024, key_fp) != NULL )
    {
        if(key[strlen(key)-1]=='\n')
            key[strlen(key)-1] = '\0';
    }

    // read msg from msg file
    if (msg_fp == NULL)
    {
        printf("Cannot open message file \n");
        exit(0);
    }
    char msg[1024];
    int i=0;
    char c;
    while ((c = fgetc(msg_fp)) != EOF)
    {
        msg[i++] = (char) c;
    }
    msg[i] = '\0';
    if(msg[i-1] == '\n')
    {
        msg[i-1] = '\0';
    }

    // convert key as string to uint32_t
    uint32_t num[4];
    memcpy(num,key,16);

    //pad message
    uint32_t* padmsg;
    unsigned int padmsglen;
    uint32_t iv[2];
    iv[0] = 1111;
    iv[1] = 1111;
    int len = strlen(msg);
    padMessage(msg,strlen(msg),&padmsg,&padmsglen);

    // encryptWithCBC and write encrypted message using ‘hexdump_to_string’ to ‘encrypted_msg.bin’
    uint32_t* encryptedmsg = encryptWithCBC(num_rounds,padmsg,padmsglen,num,iv);
    char * str = (char*)malloc(8*padmsglen);
    hexdump_to_string(encryptedmsg, 4*padmsglen, str);
    fwrite(str, 1, strlen(str), encrypted_msg_fp);

    // decryptWithCBC
    uint32_t *decryptedtext = decryptWithCBC(num_rounds, encryptedmsg, padmsglen, num, iv);

    // unpad message and write decrypted message to ‘decrypted_msg.txt’
    char* finalmsg;
    unsigned int finalmsglen;
    unpadMessage(&finalmsg, &finalmsglen, decryptedtext, len);
    fwrite(finalmsg, sizeof(char), finalmsglen, decrypted_msg_fp);

    fclose(msg_fp);
    fclose(key_fp);
    fclose(encrypted_msg_fp);
    fclose(decrypted_msg_fp);

    return 0;
}

void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4])
{
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4])
{
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

uint32_t* encryptWithCBC(unsigned int num_rounds, uint32_t* v,
                         unsigned int v_len, uint32_t const key[4], uint32_t iv[2])
{
    uint32_t msgblocks[2];
    for(int i=0;i<1;i++)
    {
        msgblocks[0] = *(v+i);
        msgblocks[1] = *(v+i+1);
        bitXOR(msgblocks,iv);
        encipher(num_rounds, msgblocks, key);
        *(v+i) = msgblocks[0];
        *(v+i+1) = msgblocks[1];
    }

    uint32_t block[2];
    block[0] = *(v+0);
    block[1] = *(v+1);
    uint32_t cipherblocks[2];
    for(int j=2;j<v_len;j++)
    {
        cipherblocks[0] = block[0];
        cipherblocks[1] = block[1];
        block[0] = *(v+j);
        block[1] = *(v+j+1);
        bitXOR(block,cipherblocks);
        encipher(num_rounds, block, key);
        *(v+j) = block[0];
        *(v+j+1) = block[1];
        j=j+1;
    }
    return v;
}

uint32_t* decryptWithCBC(unsigned int num_rounds, uint32_t* v,
                         unsigned int v_len, uint32_t const key[4], uint32_t iv[2])
{
    uint32_t cipherblock[2];
    uint32_t ciphertext[2];
    for(int k=0;k<1;k++)
    {
        cipherblock[0] = *(v+k);
        cipherblock[1] = *(v+k+1);
        ciphertext[0] = *(v+k);
        ciphertext[1] = *(v+k+1);
        decipher(num_rounds, cipherblock, key);
        bitXOR(cipherblock,iv);
        *(v+k) = cipherblock[0];
        *(v+k+1) = cipherblock[1];
    }

    uint32_t block[2];
    block[0] = ciphertext[0];
    block[1] = ciphertext[1];
    uint32_t cipher[2];
    uint32_t beforedecipher[2];
    for(int j=2;j<v_len;j++)
    {
        cipher[0] = block[0];
        cipher[1] = block[1];
        block[0] = *(v+j);
        block[1] = *(v+j+1);
        beforedecipher[0] = block[0];
        beforedecipher[1] = block[1];
        decipher(num_rounds, beforedecipher, key);
        bitXOR(beforedecipher,cipher);
        *(v+j) = beforedecipher[0];
        *(v+j+1) = beforedecipher[1];
        j=j+1;
    }
    return v;
}

void padMessage(char *msg, unsigned int msg_len, uint32_t** padded_msg,
                unsigned int *padded_msg_len)
{
    if(msg_len%8==0)
    {
        for(int m=0;m<8;m++)
        {
            if(m==7)
                msg[msg_len++]= '8';
            else
                msg[msg_len++]= '0';
        }
    }
    else
    {
        int temp = 0;
        while(msg_len%8!=0)
        {
            temp++;
            msg[msg_len++]= '0';
        }
        msg[msg_len-1]=temp+'0';;
    }
    unsigned int length = (unsigned int )strlen(msg);
    *padded_msg_len = length/4;
    int j=0;
    int k=0;
    lenpad = strlen(msg)/8;
    *padded_msg = (uint32_t *)malloc((*padded_msg_len)*4);
    memcpy(*padded_msg, msg, strlen(msg));
}

void unpadMessage(char **msg, unsigned int *msg_len, uint32_t* padded_msg,
                  unsigned int padded_msg_len)
{
    *msg_len = padded_msg_len;
    *msg = (char *)malloc((*msg_len)*1);
    memcpy(*msg, padded_msg, *msg_len);
}

void bitXOR(uint32_t msgblock[2],uint32_t iv[2])
{
    uint32_t a1 = msgblock[0] & iv[0];
    uint32_t a2 = msgblock[1] & iv[1];
    uint32_t b1 = (~msgblock[0]) & (~iv[0]);
    uint32_t b2 = (~msgblock[1]) & (~iv[1]);
    uint32_t final1 = (~a1) & (~b1);
    uint32_t final2 = (~a2) & (~b2);
    msgblock[0] = final1;
    msgblock[1] = final2;
}



