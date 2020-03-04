
#ifdef __cplusplus
extern "C"
{
#endif
	#include "desEncrypt.h"
#ifdef __cplusplus
}
#endif

#define MAX_SIZE sizeof(uint64_t) * 8
#define INT_SIZE64 sizeof(uint64_t) * 8
#define INT_SIZE56 sizeof(uint64_t) * 7
#define INT_SIZE48 sizeof(uint64_t) * 6
#define INT_SIZE32 sizeof(uint64_t) * 4
#define NUM_BLOCKS 16
#define NUM_SUB_KEYS 16

uint64_t* desEncryptECB(uint64_t *message, int len, uint64_t key){
	printf("[*] Encrypting Message Using: DES ECB Mode.\n");
	int i;
	uint64_t *a = malloc(sizeof(uint64_t) * len);
	for (i = 0; i < len; i++) {
		a[i] = encrypt(message[i],key);
	}
	return a;
}// end

uint64_t* desDecryptECB(uint64_t *ciphertext, int len,  uint64_t key){
	printf("[*] Decrypting Message Using: DES ECB Mode.\n");
	int i;
	uint64_t *a = malloc(sizeof(uint64_t) * len);
	for (i = 0; i < len; i++) {
		a[i] = decrypt(ciphertext[i],key);
	}
	return a;
}// end

uint64_t encrypt(const uint64_t message,const uint64_t key) {
   return DES(message,key,false);
}

uint64_t decrypt(const uint64_t message,const uint64_t key) {
    return DES(message,key,true);
}

uint64_t DES(const uint64_t message,const uint64_t key, const bool decrypt) {
    int i,j,k;
	uint64_t _ip = 0;
	uint64_t K[NUM_SUB_KEYS] = {0};

	generateSubKeys(key,K);

    // encode message
	for (i = 0; i < INT_SIZE64; i++) {
	_ip |= (uint64_t) (
		        ((message >> (uint64_t) (MAX_SIZE - IP[i]) ) & 0x1) 
		        << (MAX_SIZE - 1 - i));
	}

    // split permutated message
    uint32_t r[NUM_BLOCKS + 1];
    uint32_t l[NUM_BLOCKS + 1];
    r[0] |= _ip;
    l[0] = _ip >> ((INT_SIZE64) / 2);

    // rounds
    if (!decrypt) {
        for (i = 1; i <= NUM_BLOCKS; i++) {
    		l[i] = r[i-1];
    		r[i] = l[i-1] ^ sBoxPermutation(r[i-1],K[i-1]);
    	}
    } else {
    	for (i = 1; i <= NUM_BLOCKS; i++) {
    		l[i] = r[i-1];
    		r[i] = l[i-1] ^ sBoxPermutation(r[i-1],K[NUM_SUB_KEYS - i]);
    	}
    }

    uint64_t concatBlocks = 0;
    concatBlocks |= r[16];
    concatBlocks = concatBlocks << ((INT_SIZE64) / 2);
    concatBlocks |= l[16];

    // inverse permutation
    uint64_t finalPermutation = 0;
    for (j = 0; j < INT_SIZE64; j++)
    finalPermutation |= ((concatBlocks >>  ((uint64_t) INT_SIZE64 - FP[j])) & 0x1) 
                        << (uint64_t)(INT_SIZE64 - 1 - j);
	return finalPermutation;
}

void generateSubKeys(const uint64_t key, uint64_t *subKeys) {
    
    int i,j;
	uint64_t key_plus = 0;
	uint32_t _c[NUM_SUB_KEYS+1] = {0};
	uint32_t _d[NUM_SUB_KEYS+1] = {0};
	uint64_t _cd[NUM_SUB_KEYS] = {0};

	int shiftSchedule[NUM_SUB_KEYS] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

	// load key in big endian and perform PC-1
	for (i = 0; i < INT_SIZE56; i++) {
		key_plus |= (uint64_t) (
		    ((key >> (uint64_t) (MAX_SIZE - PC1[i]) ) & 0x1) 
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

        // clear high bits
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
        for (j = 0; j < (INT_SIZE48); j++)
	    subKeys[i] |= (_cd[i] >> ((INT_SIZE56) - PC2[j]) & 0x1) 
             << ((INT_SIZE48) - j - 1);
	}
}

uint32_t sBoxPermutation (const uint32_t block, uint64_t key) {

	int j;
	uint32_t pOut = 0;
	uint64_t _e = 0;

    // expand right block (E)
    for (j = 0; j < INT_SIZE48; j++)
    _e |= (((uint64_t) (block >>  ((INT_SIZE32) - E[j])) & 0x1) 
    	    << ((INT_SIZE48) - j - 1));

    // sBox Lookup table
    int count = INT_SIZE48;
    int sBoxCount = 1;
    uint32_t sLookup = 0;
    while (count != 0) {

        count -= 6;

        // extract 6 bits at a time from output of e ^ K
        uint8_t sCmpn = (((_e ^ key) >> (count)) << 2) >> 2;
	    uint8_t row = 0;
	    uint8_t column = 0;
	    row = (((sCmpn >> 5) & 1) << 1) | (sCmpn & 1);
	    column = (sCmpn >> 1) & 0xf;

	    int index = ((NUM_BLOCKS*(row))+(column));
        switch(sBoxCount) {
        	case 1:
                sLookup |= S1[index];
                sLookup = sLookup << 4;
                break;
            case 2:
            	sLookup |= S2[index];
                sLookup = sLookup << 4;
            	break;
            case 3:
            	sLookup |= S3[index];
                sLookup = sLookup << 4;
            	break;
            case 4:
            	sLookup |= S4[index];
                sLookup = sLookup << 4;
            	break;
            case 5:
            	sLookup |= S5[index];
                sLookup = sLookup << 4;
            	break;
            case 6:
            	sLookup |= S6[index];
                sLookup = sLookup << 4;
            	break;
            case 7:
                sLookup |= S7[index];
                sLookup = sLookup << 4;
                break;
            case 8:
                sLookup |= S8[index];
                break;
        	default:
        	    break;
        }
        sBoxCount++;
    }

    // sBox Permutation
	for (j = 0; j < INT_SIZE32; j++)
    pOut |= ((sLookup >>  (uint32_t) ((INT_SIZE32) - P[j])) & 0x1) 
          << (uint32_t)((INT_SIZE32) - 1 -j);
	return pOut;
}
