/***********************************************************/
/**********Author: osama hegazi*****************************/
/**********Date:24/1/2021***********************************/
/***********version:1***************************************/
/***********************************************************/

#ifndef AES_CONFIG_H
#define AES_CONFIG_H

/*
key lenght options:

128bit--->10cycles
192bits-->12cycles
256bits-->14cycles
*/
#define AES_BLOCK_SIZE       16   // block size of message to be incrypt
#define AES_TEN_BLOCK_SIZE   160  // size of 10 blocks
/*
rounds number options:

10cycles--->128bit
12cycles-->192bits
14cycles-->256bits
*/
#define AES_ROUNDS          10   // number of rounds performed
/*
roundkey size options:

10cycles--->176bit
12cycles-->208bits
14cycles-->240bits

*/
#define AES_ROUND_KEY_SIZE  176  // every byte of the block has 10 round and extra round as Init "(1 + 10 ) * 16 = 176"





#endif
