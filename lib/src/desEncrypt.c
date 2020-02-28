#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>


#ifdef __cplusplus
extern "C"
{
#endif
	#include "desEncrypt.h"
	#include "encrypt.h"
	#include "BitPermutationFunctions.h"
	#include "permTables.h"
#ifdef __cplusplus
}
#endif

#define MAX_SIZE sizeof(uint64_t) * 8
#define NUM_SUB_KEYS 16
#define NUM_BLOCKS 16

//NOTE: Under construction. Currently refactoring code to be more linear in fashion
// and less memcpy heavy and get rid of unecessary 2d arrays.


void encryptUsingRandomKey(){
	char key[9] = "aabbccdd"; // entered 64 bit key
	char message[9] = "messages";// IP per 64 bits of original message

	printf("message to encrypt: %s\n", message);

	desEncryptionPer64(message,key);
	//printf("encrypted message: %s\n",message);

 //    desDecryptionPer64(message,key);
 //    printf("decrypted message: %s\n",message);
}// end


void desEncryptionPer64(char* message,char* key){
    // num sub keys = 16
	int i,j;
	uint64_t key_plus = 0x0;
	uint64_t _ip = 0x0;
	uint64_t K[NUM_SUB_KEYS] = {0};
	uint32_t _c[NUM_SUB_KEYS+1] = {0};
	uint32_t _d[NUM_SUB_KEYS+1] = {0};
	uint64_t _cd[NUM_SUB_KEYS] = {0};
	int shiftSchedule[NUM_SUB_KEYS] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

    uint64_t _message = 0x0123456789ABCDEF;
	uint64_t keys = 0x133457799BBCDFF1;
	printf("0x%llx\n",keys);

    // load key in big endian and perform PC-1
	for (i = 0; i < sizeof(uint64_t) * 7; i++) {
	key_plus |= (uint64_t) (
		        ((keys >> (uint64_t) (MAX_SIZE - PC1[i]) ) & 0x1) 
		        << (MAX_SIZE - 1 - i));
	}

    // seperate permutation into c and d blocks
	_c[0] = (key_plus>>36);
	_d[0] = (key_plus>>8);

    for (i = 1; i < NUM_SUB_KEYS + 1; i++) {

        uint32_t temp = _d[i-1];
        for (j = 1; j <= shiftSchedule[i-1]; j++) {
            _d[i] = (temp << 1) | (1 & (temp >> 27));
            temp = _d[i];
        }

        temp = _c[i-1];
        for (j = 1; j <= shiftSchedule[i-1]; j++) {
            _c[i] = (temp << 1) | (1 & (temp >> 27));
            temp = _c[i];
        }

        _c[i] = (_c[i] << 4) >> 4;
        _d[i] = (_d[i] << 4) >> 4;
    } 

    // concatenate blocks
    for (i = 0; i < NUM_SUB_KEYS; i++) {
	    _cd[i] |= _c[i+1];
	    _cd[i] = (_cd[i] << 28);
	    _cd[i] |= _d[i+1];
	}

    // generate subkeys
	for (i = 0; i < NUM_SUB_KEYS; i++) {
        for (j = 0; j < (sizeof(uint64_t) * 6); j++)
	    K[i] |= (_cd[i] >> ((sizeof(uint64_t) * 7) - PC2[j]) & 0x1) 
             << ((sizeof(uint64_t) * 6) - i - 1);
	}

    // == encode message ==

    // load message in big endian and perform IP
	for (i = 0; i < sizeof(uint64_t) * 8; i++) {
	_ip |= (uint64_t) (
		        ((_message >> (uint64_t) (MAX_SIZE - IP[i]) ) & 0x1) 
		        << (MAX_SIZE - 1 - i));
	}


    uint32_t r[NUM_BLOCKS + 1];
    uint32_t l[NUM_BLOCKS + 1];

    // split permutated message
    r[0] |= _ip;
    l[0] = _ip >> 32;

    printf("r0\n");
    for (i = 31; i > -1; i--)
	printf("%d", (r[0] >> i) & 0x01);
    printf("\n");

    //for (i = 1; i <= NUM_BLOCKS; i++) {
    //	l[i] = r[i-1];
    //	r[i] = l[i-1] ^ f(r[i-1],K[i]);
    //}

    printf("Expand r0\n");

    uint64_t _e = 0x0;
    // expand block
	//for (i = 0; i < NUM_SUB_KEYS; i++) {
    for (j = 0; j < 48; j++)
    _e |= (r[0] >> (E[j]) & 0x1) << (j);
	//}

    for (i = 63; i > -1; i--)
	printf("%d", (_e >> i) & 0x01);
    printf("\n");


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


