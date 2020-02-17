#ifndef BITPERMUTATIONFUNCTIONS_H
#define BITPERMUTATIONFUNCTIONS_H

 #ifdef __cplusplus
 extern "C"
 {
 #endif

	void initialPermutation(char* key,char*pk);
	void splitCharByte(char* input,char* side1,char* side2);
	void initialKeyPermutation(char* key,char*pk);
	void keyBlock(char* cn,char* dn, char (*cs)[4],char (*ds)[4]);
	void leftShift(char* message);
	void concatSubBlocks(char (*cs)[4],char (*ds)[4], char (*subKey)[8]);

	void PC2Permutation(char(*key)[8], char(*pk)[8]);
	void reverseSubKeys(char(*key)[8], char(*reverse)[8]);// DECRYPTION

	void Round(char* L0,char* R0, char (*subKey)[8],char (*R)[4],char (*L)[4], int index);

	void sBoxLookup(char* sOutput, char* b);
	void StraightPermutation(char* message, char* pk);
	void shiftPBoxOutput(char* message);

	void finalPermutation(char* message,char* ip);
	void flipSplitBytes(char* output,char* R,char* L);


	void mapFunction(char* fOutput,char* R,char *subKey);
	void eSelection(char* message);


	int  findDesiredByte(int goalByte);
	int  findDesiredByte7Bit(int goalByte);
	int  findDestinationBit(int goalBit);
	int findDestinationBit7Bit(int goalBit);
	int findDesiredByte6Bit(int goalByte);
	int findDestinationBit6Bit(int goalBit);
	int findDestinationBit4Bit(int goalBit);
	int findDesiredByte4Bit(int goalByte);



 #ifdef __cplusplus
 }
 #endif

#endif
