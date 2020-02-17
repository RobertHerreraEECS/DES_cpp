#include "encrypt.h"
#include "desEncrypt.h"
#include "BitPermutationFunctions.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void encryptUsingRandomKey(){
	char key[9] = "aabbccdd"; // entered 64 bit key
	char message[9] = "messages";// IP per 64 bits of original message

	printf("message to encrypt: %s\n", message);

	desEncryptionPer64(message,key);
	printf("encrypted message: %s\n",message);

    desDecryptionPer64(message,key);
    printf("decrypted message: %s\n",message);
}// end


void desEncryptionPer64(char* message,char* key){

	 char pk[8]; // 56 bit permutation
	 char ip[8]; // destination 64 bit (permuted message)
	 char R[4],L[4]; // 32 bit left and right blocks
	 char c[4],d[4]; // c0 d0
	 char cShifts[17][4];//c schedule
	 char dShifts[17][4];// d scheulde
	 char keyCD[16][8];// concatanted schedule
	 char keyPC2[16][8];// sub keys
	 char subR[17][4]; //R transformation (round function)
	 char subL[17][4]; //L transformation (round function)
	 char roundOutput[8];
	 char finalOutput[8];//final Ouput
	 
	 initialKeyPermutation(key,pk);// initial key permutation
	 initialPermutation(message,ip);// intial permutation

	 splitCharByte(ip,L,R);//L,R
	 splitCharByte(pk,c,d);//c0,d0

	 keyBlock(c,d,cShifts,dShifts); //key schedule
	 concatSubBlocks(cShifts,dShifts,keyCD); 
	 PC2Permutation(keyCD,keyPC2); // generate subKeys from key schedule
	 
	 int i;
	 for(i = 0;i < 17; i++) { // 16 iteration round function | 0th index initializes
	 	Round(L,R,keyPC2,subR,subL,i);
	 }

	 flipSplitBytes(roundOutput,subR[16],subL[16]); // swap R and L
	 finalPermutation(roundOutput,finalOutput);// final permutation
	 memcpy(message,finalOutput,8);
}

void desDecryptionPer64(char* message,char* key){
	 char pk[8]; // 56 bit permutation
	 char ip[8]; // destination 64 bit (permuted message)
	 char R[4],L[4]; // 32 bit left and right blocks
	 char c[4],d[4]; // c0 d0
	 char cShifts[17][4];//c schedule
	 char dShifts[17][4];// d scheulde
	 char keyCD[16][8];// concatanted schedule
	 char keyPC2[16][8];// sub keys

	 char keyReversal[16][8]; // sub key reveral  ****  

	 char subR[17][4]; //R transformation (round function)
	 char subL[17][4]; //L transformation (round function)
	 char roundOutput[8];
	 char finalOutput[8];//final Ouput
	 
	 initialKeyPermutation(key,pk);// initial key permutation
	 initialPermutation(message,ip);// intial permutation

	 splitCharByte(ip,L,R);//L,R
	 splitCharByte(pk,c,d);//c0,d0

	 keyBlock(c,d,cShifts,dShifts); //key schedule
	 concatSubBlocks(cShifts,dShifts,keyCD); 
	 PC2Permutation(keyCD,keyPC2); // generate subKeys from key schedule
	 reverseSubKeys(keyPC2,keyReversal);

	 int i;
	 for(i = 0;i < 17; i++) { // 16 iteration round function | 0th index initializes
	 	Round(L,R,keyReversal,subR,subL,i);
	 }

	 flipSplitBytes(roundOutput,subR[16],subL[16]); // swap R and L
	 finalPermutation(roundOutput,finalOutput);// final permutation
	 memcpy(message,finalOutput,8);
}

void printCharBinary(char* message) {
 int i,j;

  for (j = 0; j < 8; j++) {
 	for( i = 7; i >= 0; i--) {
	 	printf("%d",(message[j] >> i) & 0x01);
 	}
	printf("\n");
 }
 printf("\n");
 
}

void printCharHex(char* message) {
 int i;
 	for( i = 0; i < 8; i++) {
	 	printf("%02x ",message[i] & 0xff);
 	}
	printf("\n");
}

void printIntBinary(int message) {
 int i,j;

 	for( i = 7; i >= 0; i--) {
	 	printf("%d",(message >> i) & 0x01);
 	}
	printf("\n");
}

