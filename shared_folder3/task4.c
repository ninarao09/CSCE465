#include <openssl/conf.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>


/*******************Reference from stackoverflow***************************/
int hex_to_int(char c){
    if(c >= 97){
        c = c- 32;
    }
    int first = c/16-3;
    int second = c%16;
    int result = first*10 + second;
    if(result>9){
        result--;
    }
    return result;

}

int hex_to_ascii(char c, char d){
    int high = hex_to_int(c)*16;
    int low = hex_to_int(d);
    return high+low;
}
/*************************************************************************/

int find_key(unsigned char cipher[1024], unsigned char outbuf[1024]){
    for(int j=0; j<32; ++j){
        if(cipher[j]!=outbuf[j]){
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv){

    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    unsigned char cipher[1024];
    unsigned char key[16];

    int outlen, buff_out_len;
    
    //iv of all 0's 
    unsigned char iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; 


    char plaintext[] = "This is a top secret.";
    char ciphertext[] = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";

    //initializing cipher context
    EVP_CIPHER_CTX ctx; 
    EVP_CIPHER_CTX_init(&ctx); 

    int i = 0, index=0;    
    char buf = 0;
    //running thorugh the cipher to convert it to ascii characters
    for(i=1; i<strlen(ciphertext); i+=2){
        cipher[index] = hex_to_ascii(ciphertext[i-1], ciphertext[i]);
        index++;
    }

    //open the words file
    FILE *words = fopen("../../media/sf_shared_folder3/words.txt", "r");

    while(fgets(key, sizeof(key), words) != NULL){
        int len=0;

        // if key < 16 append spaces to the end 0x20 = ' '
        if(strlen(key) < 16){
            len = strlen(key)-1;
            while(len<16){
                key[len] = 0x20;  //appending the spaces to the end of the key
                ++len;
            }
        }

        //initualizes encryption to -aes-128-cbc as well as key and iv
        EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL);

        //makes sure iv and key are correct length
        OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
        OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

        EVP_EncryptInit_ex(&ctx, 0, 0, key, iv);

        // updates the output buffer
        EVP_EncryptUpdate(&ctx, outbuf, &outlen, plaintext, strlen(plaintext));

        //finalizes the output buffer
        EVP_EncryptFinal_ex(&ctx, outbuf + outlen, &buff_out_len);

        outlen += buff_out_len;
        // clean it up
        EVP_CIPHER_CTX_cleanup(&ctx);
         
        //The check_key function compares the ciphertexts, and it each matches, then it will 
        // return 1 else it will return 0;
        if(find_key(cipher, outbuf) == 1){
            printf("\nThe encryption key was found to be: %s \n", key);
            break;
        } 
        
    }
    
    //If key was not found, let me know
    if(find_key(cipher, outbuf) == 0){
        printf("\n The encryption key was not found \n");
        
    }

    return 0;

}