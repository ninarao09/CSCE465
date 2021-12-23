#include <openssl/conf.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>


void getHash(char* hash, char* msg,  unsigned char md_value[EVP_MAX_MD_SIZE]){
    
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;

    OpenSSL_add_all_digests();

    md = EVP_get_digestbyname(hash);
    if (md == NULL) {
        printf("Unknown message digest %s\n", hash);
        exit(1);
    }

     mdctx = EVP_MD_CTX_create();
     EVP_DigestInit_ex(mdctx, md, NULL);
     EVP_DigestUpdate(mdctx, msg, strlen(msg));
     EVP_DigestFinal_ex(mdctx, md_value, &md_len);
     EVP_MD_CTX_cleanup(mdctx);
}


int isDgstEqual(unsigned char dgst1[EVP_MAX_MD_SIZE], unsigned char dgst2[EVP_MAX_MD_SIZE]){
    for(int i=0; i<3; ++i){
        if(dgst1[i] != dgst2[i]){
            return 0;
        }
    }
    return 1;
}

int isMsgEqual(char* msg1, char* msg2){
    for(int i=0; i<sizeof(msg1); ++i){
        if(msg1[i] != msg2[i]){
            return 0;
        }
    }
    return 1;
}

/*Referenced from stack overflow*/
char* getRandomMsg(char msg[20]){
    char * str = "abcdefghijklmnopqrstuvwxyz";
    for(int i=0; i<19; ++i){
        msg[i] = str[rand()%26];
    }
    
    msg[19] = '\0';
    return msg;
}


int main(int argc, char **argv){

    char* hash = "md5";
    srand((int)time(0));

    //*********************************Case 1***************************************;
    /* Both messages are random */

    int totalTries = 0;
    int flag = 1;

    char msg1[20], msg2[20];

    unsigned char dgst1[EVP_MAX_MD_SIZE], dgst2[EVP_MAX_MD_SIZE];

    getHash(hash, getRandomMsg(msg1), dgst1);
    getHash(hash, getRandomMsg(msg2), dgst2);

    while(flag==1){

        getHash(hash, getRandomMsg(msg1), dgst1);
        getHash(hash, getRandomMsg(msg2), dgst2);

        totalTries++;

        if(isDgstEqual(dgst1, dgst2)==1 && isMsgEqual(msg1, msg2)==0){
            flag = 0;
        }

    }

    printf("Same Hash was found! It took %d tries \n", totalTries);

    //*********************************Case 2***************************************
    /* One message is random, and one hash is known*/

    int totalTriesPart2 = 0;
    int flagPart2 = 1;

    char msg3[4], msg4[4];

    unsigned char dgst3[EVP_MAX_MD_SIZE], dgst4[EVP_MAX_MD_SIZE];

    getHash(hash, getRandomMsg(msg3), dgst3);
    getHash(hash, getRandomMsg(msg4), dgst4);

    while(flagPart2==1){

        getHash(hash, getRandomMsg(msg4), dgst4);
        totalTriesPart2++;

        if((isDgstEqual(dgst3, dgst4)==1) && isMsgEqual(msg3, msg4)==0 ){
            flagPart2 = 0;
            printf("M3: %s, M4: %s \n", msg3, msg4);
        }
    }

    printf("Message with same hash was found! It took %d tries \n", totalTriesPart2);

    exit(0);

}