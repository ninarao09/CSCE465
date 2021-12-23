#include <openssl/conf.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>


char* convertHexToBinary(char h){
    char* binary = "";

    if(h =='0'){
        binary = "0000";
    }else if ((h =='1')){
        binary = "0001";
    }else if ((h =='2')){
        binary = "0010";
    }else if ((h =='3')){
        binary = "0011";
    }else if ((h =='4')){
        binary = "0100";
    }else if ((h =='5')){
        binary = "0101";
    }else if ((h =='6')){
        binary = "0110";
    }else if ((h =='7')){
        binary = "0111";
    }else if ((h =='8')){
        binary = "1000";
    }else if ((h =='9')){
        binary = "1001";
    }else if ((h =='a')){
        binary = "1010";
    }else if ((h =='b')){
        binary = "1011";
    }else if ((h =='c')){
        binary = "1100";
    }else if ((h =='d')){
        binary = "1101";
    }else if ((h =='e')){
        binary = "1110";
    }else if ((h =='f')){
        binary = "1111";
    }  
    return binary;
}

int findSimilarBits(char h1[], char h2[], int size){
    char* b1; 
    char* b2;
    int count = 0;

    for(int i=0; i<size; ++i){
        b1 = convertHexToBinary(h1[i]);
        b2 = convertHexToBinary(h2[i]);
        for(int j=0; j<4; ++j){
             if(b1[j] == b2[j]){
                 count++;
             }
        }        
    }

    return count;
}



int main(int argc, char **argv){

    char h1[] = "5100195a424ff69391c077a7b3d6c4d3";
    char h2[] = "a621e0f6ce07412d79cf7b436ce719d9";

    char h3[] = "1caf185782ac2e54e1323685bafadc3b3872e176a2d3a6f0fa9b00b019ab2d54";
    char h4[] = "528c9dd0cc597cd174a89b5baf35593a91d58f7a33e2842e07b1c586d80bba3e";

    printf("Number of similar bits for md5 : %i\n", findSimilarBits(h1, h2, sizeof(h1)-1));
    printf("Number of similar bits for sha256 : %i\n", findSimilarBits(h3, h4, sizeof(h3)-1));

    return 0;

}