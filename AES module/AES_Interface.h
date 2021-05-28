/***********************************************************/
/**********Author: osama hegazi*****************************/
/**********Date:24/1/2021***********************************/
/***********version:1***************************************/
/***********************************************************/
#ifndef AES_INTERFACE_H
#define AES_INTERFACE_H  

/**************************************************************************************************************************************************************************************************************************************************************
                                              *******Common Macros******
***********************************************************************************************************************************************************************************************************************************************************/																			
#define  ONE       1
#define  ZERO      0
#define  ONE_WORD  4


enum ARRAY_INDEX
{
	
BYTE0, 
BYTE1,
BYTE2,
BYTE3,
BYTE4,
BYTE5,
BYTE6,
BYTE7,
BYTE8,
BYTE9,
BYTE10,
BYTE11,
BYTE12,
BYTE13,
BYTE14,
BYTE15
	
};

/***********************************************************************************/
                      /***FUNCTIONS PROTOTYPES***/
/************************************************************************************

*Name       :   Aes_VoidGetRoundkeys

*Description: * Function to Get Rounds keys (key schedule) (176 bytes)              
							
*Pre-Cond   :	None				
							
*pos-Cond   : None

*Input      : Block(16 bytes) represent the key

*Output     : void

*Return     : void

****************************************************************************************/
void AES_VoidKeyExpansion(const u8 *Copy_u8userkey, u8 *Copy_roundkeys) ;
/************************************************************************************

*Name       :   Aes_VoidEncrypt_16Bytes

*Description: * Function to encrypt one block(16 bytes) using key Rounds               
							
*Pre-Cond   :	Roundkeys is get				
							
*pos-Cond   : None

*Input      : Block(16 bytes) of plain text and 176 bytes of roundskeys

*Output     : one block(16bytes) of cipher text

*Return     : void

****************************************************************************************/
void AES_VoidEncrypt_16Bytes(const u8 *Copy_u8roundkeys, const u8 *Copy_u8plaintext, u8 *Copy_u8ciphertext) ;
/************************************************************************************

*Name       :   Aes_VoidDecrypt_16Bytes

*Description: * Function to decrypt one block(16 bytes) using key Rounds               
							
*Pre-Cond   :	Roundkeys is get 				
							
*pos-Cond   : None

*Input      : Block(16 bytes) of cipher text and 176 bytes of roundskeys

*Output     : one block(16bytes) of plain text

*Return     : void

****************************************************************************************/
void AES_VoidDecrypt_16Bytes(const u8 *Copy_u8roundkeys, const u8 *Copy_u8ciphertext, u8 *Copy_u8plaintext) ;
/************************************************************************************

*Name       :   AES_U8GetMul2

*Description: * Function to mul 2 of input
              
							
*Pre-Cond   :	None				
							
*pos-Cond   : None

*Input      : num

*Output     : void

*Return     : mul by 2 of input number

****************************************************************************************/
static u8 AES_U8GetMul2(u8 Copy_u8number ) ; 
/************************************************************************************

*Name       :   AES_voidMixColoums

*Description: * Function to perform mix Coloums of the array to incrupt
              * MixColumns 
              * [02 03 01 01]   [s0  s4  s8  s12]
              * [01 02 03 01] . [s1  s5  s9  s13]
              * [01 01 02 03]   [s2  s6  s10 s14]
              * [03 01 01 02]   [s3  s7  s11 s15]            
							
*Pre-Cond   :	sub bytes step is performed				
							
*pos-Cond   : None

*Input      : cipher text and temp array after sumbytes step

*Output     : void

*Return     : void

****************************************************************************************/
static void AES_voidMixColoums( u8 *Copy_u8ciphertext, u8 *Copy_u8tmptext);
/************************************************************************************

*Name       :   AES_voidInvMixColoums

*Description: * Function to perform inv mix Coloums of the array to decrypt              
              * Inverse MixColumns
              * [0e 0b 0d 09]   [s0  s4  s8  s12]
              * [09 0e 0b 0d] . [s1  s5  s9  s13]
              * [0d 09 0e 0b]   [s2  s6  s10 s14]
              * [0b 0d 09 0e]   [s3  s7  s11 s15]
      
*Pre-Cond   :	sub bytes step is performed				
							
*pos-Cond   : None

*Input      : plain text and temp array after sum bytes step

*Output     : void

*Return     : void 

****************************************************************************************/
static void AES_voidInvMixColoums( u8 *Copy_u8plaintext, u8 *Copy_u8tmptext);
/************************************************************************************

*Name       :   AES_voidShiftRows

*Description: * Function to perform shif rows of the array to incrypt              
              * Shift Rows
              *  Row0: s0  s4  s8  s12   <<< 0 byte
              *  Row1: s1  s5  s9  s13   <<< 1 byte
              *  Row2: s2  s6  s10 s14   <<< 2 bytes
              *  Row3: s3  s7  s11 s15   <<< 3 bytes
      
*Pre-Cond   :	None				
							
*pos-Cond   : None

*Input      : state array to shift rows

*Output     : void

*Return     : void 

****************************************************************************************/
static void AES_voidShiftRows(u8 *Copy_u8state) ;
/************************************************************************************

*Name       :   AES_voidInvShiftRows

*Description: * Function to perform inv shif rows of the array to decrupt              
              * inv Shift Rows
              *  Row0: s0  s4  s8  s12   >>> 0 byte
              *  Row1: s1  s5  s9  s13   >>> 1 byte
              *  Row2: s2  s6  s10 s14   >>> 2 bytes
              *  Row3: s3  s7  s11 s15   >>> 3 bytes
      
*Pre-Cond   :	None				
							
*pos-Cond   : None

*Input      : state array to inv shift rows

*Output     : void

*Return     : void 

****************************************************************************************/
static void AES_voidInvShiftRows(u8 *Copy_u8state);



#endif
