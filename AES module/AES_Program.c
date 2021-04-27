/***********************************************************/
/**********Author: osama hegazi*****************************/
/**********Date:27/4/2021***********************************/
/***********version:1***************************************/
/***********************************************************/
#include "STD_TYPES.h"
#include "BIT_MATH.h"
#include "AES_Private.h"
#include "AES_Interface.h"
#include "AES_Config.h"

/*************************************************************************************/
                             /*****Functions Definitions********/
/*************************************************************************************/
static u8 AES_U8GetMul2(u8 Copy_u8number ) 
{
	
    return (Copy_u8number & RoundConstats[BYTE7] ) ? ((Copy_u8number << ONE) ^ RoundConstats[BYTE8] ) : (Copy_u8number << ONE);
 }
/*****************************************************************END OF FUNCTION**************************************************************************************************************************************************************************************************************************/																                                  
static void AES_voidMixColoums( u8 *Copy_u8ciphertext, u8 *Copy_u8tmptext)
{
	
u8 Local_u8elementCounter ;//element counter
u8 Local_u8tmp1 ;	
	
	for (Local_u8elementCounter = ZERO; Local_u8elementCounter < AES_BLOCK_SIZE; Local_u8elementCounter+=4) 
				{
            Local_u8tmp1 = Copy_u8tmptext[Local_u8elementCounter]  //tmp1 = XOR operation in 4 words of the array
              					 ^ Copy_u8tmptext[Local_u8elementCounter+BYTE1] 
					               ^ Copy_u8tmptext[Local_u8elementCounter+BYTE2] 
					               ^ Copy_u8tmptext[Local_u8elementCounter+BYTE3];
					
            Copy_u8ciphertext[Local_u8elementCounter]   = AES_U8GetMul2(Copy_u8tmptext[Local_u8elementCounter] 
                                               					^ Copy_u8tmptext[Local_u8elementCounter+BYTE1]) 
					                                              ^ Copy_u8tmptext[Local_u8elementCounter]  
                                              					^ Local_u8tmp1;
            Copy_u8ciphertext[Local_u8elementCounter+BYTE1] = AES_U8GetMul2(Copy_u8tmptext[Local_u8elementCounter+BYTE1] 
					                                              ^ Copy_u8tmptext[Local_u8elementCounter+BYTE2])
                                              					^ Copy_u8tmptext[Local_u8elementCounter+BYTE1] 
					                                              ^ Local_u8tmp1;
            Copy_u8ciphertext[Local_u8elementCounter+BYTE2] = AES_U8GetMul2(Copy_u8tmptext[Local_u8elementCounter+BYTE2]
                                              					^ Copy_u8tmptext[Local_u8elementCounter+BYTE3]) 
					                                              ^ Copy_u8tmptext[Local_u8elementCounter+BYTE2] 
					                                              ^ Local_u8tmp1;
            Copy_u8ciphertext[Local_u8elementCounter+BYTE3] = AES_U8GetMul2(Copy_u8tmptext[Local_u8elementCounter+BYTE3]
                                              					^ Copy_u8tmptext[Local_u8elementCounter]  )
                                              					^ Copy_u8tmptext[Local_u8elementCounter+BYTE3] 
					                                              ^ Local_u8tmp1;
        }
	
 }
/*****************************************************************END OF FUNCTION**************************************************************************************************************************************************************************************************************************/																                                  
static void AES_voidInvMixColoums( u8 *Copy_u8plaintext, u8 *Copy_u8tmptext)
{

	
	
u8  Local_u8elementCounter ; //element counter in the array
u8	Local_u8tmp1 ;
u8	Local_u8tmp2 ;
u8  Local_u8tmp3 ;		
	
 for (Local_u8elementCounter = ZERO; Local_u8elementCounter < AES_BLOCK_SIZE; Local_u8elementCounter+=4) 
				{
            Local_u8tmp1 = Copy_u8tmptext[Local_u8elementCounter]  //tmp1 = XOR operation in 4 words of the array
					               ^ Copy_u8tmptext[Local_u8elementCounter+BYTE1] 
					               ^ Copy_u8tmptext[Local_u8elementCounter+BYTE2] 
					               ^ Copy_u8tmptext[Local_u8elementCounter+BYTE3];
					
            Copy_u8plaintext[Local_u8elementCounter]   = Local_u8tmp1 ^ Copy_u8tmptext[Local_u8elementCounter]
                                              				 ^ AES_U8GetMul2(Copy_u8tmptext[Local_u8elementCounter] 
                                              				 ^ Copy_u8tmptext[Local_u8elementCounter+BYTE1]);
					
            Copy_u8plaintext[Local_u8elementCounter+BYTE1] = Local_u8tmp1 ^ Copy_u8tmptext[Local_u8elementCounter+BYTE1]
                                             					 ^ AES_U8GetMul2(Copy_u8tmptext[Local_u8elementCounter+BYTE1] 
					                                             ^ Copy_u8tmptext[Local_u8elementCounter+BYTE2]);
					
            Copy_u8plaintext[Local_u8elementCounter+BYTE2] = Local_u8tmp1 ^ Copy_u8tmptext[Local_u8elementCounter+BYTE2] 
					                                             ^ AES_U8GetMul2(Copy_u8tmptext[Local_u8elementCounter+BYTE2] 
					                                             ^ Copy_u8tmptext[Local_u8elementCounter+BYTE3]);
					
            Copy_u8plaintext[Local_u8elementCounter+BYTE3] = Local_u8tmp1 ^ Copy_u8tmptext[Local_u8elementCounter+BYTE3] 
					                                             ^ AES_U8GetMul2(Copy_u8tmptext[Local_u8elementCounter+BYTE3]  
					                                             ^ Copy_u8tmptext[Local_u8elementCounter]);
					
            Local_u8tmp2 = AES_U8GetMul2(AES_U8GetMul2(Copy_u8tmptext[Local_u8elementCounter]
              					 ^ Copy_u8tmptext[Local_u8elementCounter+BYTE2]));
					
            Local_u8tmp3 = AES_U8GetMul2(AES_U8GetMul2(Copy_u8tmptext[Local_u8elementCounter+BYTE1] 
						             ^ Copy_u8tmptext[Local_u8elementCounter+BYTE3]));
					
            Local_u8tmp1 = AES_U8GetMul2(Local_u8tmp2 ^ Local_u8tmp3);
					
            Copy_u8plaintext[Local_u8elementCounter]   ^= Local_u8tmp1 ^ Local_u8tmp2;
            Copy_u8plaintext[Local_u8elementCounter+BYTE1] ^= Local_u8tmp1 ^ Local_u8tmp3;
            Copy_u8plaintext[Local_u8elementCounter+BYTE2] ^= Local_u8tmp1 ^ Local_u8tmp2;
            Copy_u8plaintext[Local_u8elementCounter+BYTE3] ^= Local_u8tmp1 ^ Local_u8tmp3;
        }
 } 
/*****************************************************************END OF FUNCTION**************************************************************************************************************************************************************************************************************************/																                                   
static void AES_voidShiftRows(u8 *Copy_u8state)	
{
/*
    * row 0 is not shifted
	* row 1 is shifted by 1
	* row 2 is shifted by 2
	* row 3 is shifted by 3
*/	
    u8 Local_u8temp;
    // row1
    Local_u8temp       = *(Copy_u8state+BYTE1);
    *(Copy_u8state+BYTE1)  = *(Copy_u8state+BYTE5);
    *(Copy_u8state+BYTE5)  = *(Copy_u8state+BYTE9);
    *(Copy_u8state+BYTE9)  = *(Copy_u8state+BYTE13);
    *(Copy_u8state+BYTE13) = Local_u8temp;
    // row2
    Local_u8temp       = *(Copy_u8state+BYTE2);
    *(Copy_u8state+BYTE2)  = *(Copy_u8state+BYTE10);
    *(Copy_u8state+BYTE10) = Local_u8temp;
    Local_u8temp       = *(Copy_u8state+BYTE6);
    *(Copy_u8state+BYTE6)  = *(Copy_u8state+BYTE14);
    *(Copy_u8state+BYTE14) = Local_u8temp;
    // row3
    Local_u8temp       = *(Copy_u8state+BYTE15);
    *(Copy_u8state+BYTE15) = *(Copy_u8state+BYTE11);
    *(Copy_u8state+BYTE11) = *(Copy_u8state+BYTE7);
    *(Copy_u8state+BYTE7)  = *(Copy_u8state+BYTE3);
    *(Copy_u8state+BYTE3)  = Local_u8temp;
}
/*****************************************************************END OF FUNCTION**************************************************************************************************************************************************************************************************************************/																                                  	
static void AES_voidInvShiftRows(u8 *Copy_u8state)
{
	
		
    u8 Local_u8temp;
    // row1
    Local_u8temp        = *(Copy_u8state+BYTE13);
    *(Copy_u8state+BYTE13) = *(Copy_u8state+BYTE9);
    *(Copy_u8state+BYTE9)  = *(Copy_u8state+BYTE5);
    *(Copy_u8state+BYTE5)  = *(Copy_u8state+BYTE1);
    *(Copy_u8state+BYTE1)  = Local_u8temp;
    // row2
    Local_u8temp        = *(Copy_u8state+BYTE14);
    *(Copy_u8state+BYTE14) = *(Copy_u8state+BYTE6);
    *(Copy_u8state+BYTE6)  = Local_u8temp;
    Local_u8temp        = *(Copy_u8state+BYTE10);
    *(Copy_u8state+BYTE10) = *(Copy_u8state+BYTE2);
    *(Copy_u8state+BYTE2)  = Local_u8temp;
    // row3
    Local_u8temp        = *(Copy_u8state+BYTE3);
    *(Copy_u8state+BYTE3)  = *(Copy_u8state+BYTE7);
    *(Copy_u8state+BYTE7)  = *(Copy_u8state+BYTE11);
    *(Copy_u8state+BYTE11) = *(Copy_u8state+BYTE15);
    *(Copy_u8state+BYTE15) = Local_u8temp;
}
/*****************************************************************END OF FUNCTION**************************************************************************************************************************************************************************************************************************/																                                  
void AES_VoidKeyExpansion(const u8 *Copy_u8Initkey, u8 *Copy_u8roundkeys) //each round has its unique key 
{	
	
    u8  Local_u8temptext[ONE_WORD]; //The key expansion routine creates round keys word by word
                             // word is an array of four bytes 
    u8 *Local_u8last4bytesptr;  // pointer to the last 4 bytes of one round
    u8 *Local_u8lastroundptr;  //pionter to the last round
    u8  Local_u8roundCounter; //counter of the rounds
    u8  Local_u8elementCounter; //counter of the rounds

	
    for (Local_u8elementCounter = ZERO; Local_u8elementCounter < AES_BLOCK_SIZE; ++Local_u8elementCounter) {  //save first round of keys
			
        *Copy_u8roundkeys++ = *Copy_u8Initkey++;
    }

    Local_u8last4bytesptr = Copy_u8roundkeys - ONE_WORD;//piont to last round
		
    for (Local_u8roundCounter = ZERO; Local_u8roundCounter < AES_ROUNDS; ++Local_u8roundCounter) //set other 10 rounds of keys
		{
			
        // k0-k3 for next round
        Local_u8temptext[BYTE3] = SBOX[*Local_u8last4bytesptr++];
        Local_u8temptext[BYTE0] = SBOX[*Local_u8last4bytesptr++];
        Local_u8temptext[BYTE1] = SBOX[*Local_u8last4bytesptr++];
        Local_u8temptext[BYTE2] = SBOX[*Local_u8last4bytesptr++];
        Local_u8temptext[BYTE0] ^= RoundConstats[Local_u8roundCounter]; //XOR operation to add round key
        Local_u8lastroundptr = Copy_u8roundkeys-AES_BLOCK_SIZE;//piont to last round
        *Copy_u8roundkeys++ = Local_u8temptext[BYTE0] ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = Local_u8temptext[BYTE1] ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = Local_u8temptext[BYTE2] ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = Local_u8temptext[BYTE3] ^ *Local_u8lastroundptr++;
        // k4-k7 for next round        
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
        // k8-k11 for next round
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
        // k12-k15 for next round
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
        *Copy_u8roundkeys++ = *Local_u8last4bytesptr++ ^ *Local_u8lastroundptr++;
    }
}
/*****************************************************************END OF FUNCTION**************************************************************************************************************************************************************************************************************************/																                                  
void AES_VoidEncrypt_16Bytes(const u8 *Copy_u8roundkeys, const u8 *Copy_u8plaintext, u8 *Copy_u8ciphertext) 
{
    u8 Local_u8tmptext[16] ;
    u8 Local_u8elementcounter;
    u8 Local_u8roundcounter	 ;

    // first round we add Roundkeys
    for ( Local_u8elementcounter = ZERO; Local_u8elementcounter < AES_BLOCK_SIZE; ++Local_u8elementcounter )
	  {
			
        *(Copy_u8ciphertext+Local_u8elementcounter) = *(Copy_u8plaintext+Local_u8elementcounter)
                                               			^ *(Copy_u8roundkeys++); // XOR operation to add roundkey to each element
    }

    // 9 rounds
    for (Local_u8roundcounter = ONE; Local_u8roundcounter< AES_ROUNDS; ++Local_u8roundcounter)
		{

        // SubBytes step
      for (Local_u8elementcounter = ZERO; Local_u8elementcounter < AES_BLOCK_SIZE; ++Local_u8elementcounter)
			  {
            *(Local_u8tmptext+Local_u8elementcounter) = SBOX[*(Copy_u8ciphertext+Local_u8elementcounter)];//replace each byte of cipher with  depend on the keyround
        }
		     //shift rows step	
       AES_voidShiftRows(Local_u8tmptext);
				
	     	//mix coloums step		
	    	AES_voidMixColoums( Copy_u8ciphertext , Local_u8tmptext );
        
        // AddRoundKey step
        for ( Local_u8elementcounter= ZERO; Local_u8elementcounter < AES_BLOCK_SIZE; ++Local_u8elementcounter )
				{
            *(Copy_u8ciphertext+Local_u8elementcounter) ^= *(Copy_u8roundkeys++);
        }
    }    
		
         // final round this one not contain mix coloums
		
	    	// SubBytes step
        for (Local_u8elementcounter = ZERO; Local_u8elementcounter < AES_BLOCK_SIZE; ++Local_u8elementcounter) 
	    	{
           *(Copy_u8ciphertext+Local_u8elementcounter) = SBOX[*(Copy_u8ciphertext+Local_u8elementcounter)]; //replace each byte of cipher with  depend on the keyround
        }
		
	      //shift rows step	
        AES_voidShiftRows(Copy_u8ciphertext);
		
		    //add Round key
        for ( Local_u8elementcounter = ZERO; Local_u8elementcounter < AES_BLOCK_SIZE; ++Local_u8elementcounter )
		    {
           *(Copy_u8ciphertext+Local_u8elementcounter) ^= *(Copy_u8roundkeys++); // XOR operation to add roundkey to each element
        }

}
/*****************************************************************END OF FUNCTION**************************************************************************************************************************************************************************************************************************/																                                  
void AES_VoidDecrypt_16Bytes(const u8 *Copy_u8roundkeys, const u8 *Copy_u8ciphertext, u8 *Copy_u8plaintext) 
{

    u8 Local_u8tmptext[AES_BLOCK_SIZE] ;
    u8 Local_u8elementcounter;
    u8 Local_u8roundcounter	 ;

    Copy_u8roundkeys += AES_TEN_BLOCK_SIZE;

    // first round
    for ( Local_u8elementcounter = ZERO; Local_u8elementcounter < AES_BLOCK_SIZE; ++Local_u8elementcounter )
  	{
        *(Copy_u8plaintext+Local_u8elementcounter) = *(Copy_u8ciphertext+Local_u8elementcounter)  
			                                             ^ *(Copy_u8roundkeys+Local_u8elementcounter);
    }
    Copy_u8roundkeys -= AES_BLOCK_SIZE;
		
    AES_voidInvShiftRows(Copy_u8plaintext);
		
    for (Local_u8elementcounter = ZERO; Local_u8elementcounter < AES_BLOCK_SIZE; ++Local_u8elementcounter)
		{
			
        *(Copy_u8plaintext+Local_u8elementcounter) = INV_SBOX[*(Copy_u8plaintext+Local_u8elementcounter)];
    }

    for (Local_u8roundcounter = ONE; Local_u8roundcounter < AES_ROUNDS; ++Local_u8roundcounter)
		{
        
        // Inverse AddRoundKey
        for ( Local_u8elementcounter= ZERO; Local_u8elementcounter < AES_BLOCK_SIZE; ++Local_u8elementcounter)
			{
				
            *(Local_u8tmptext+Local_u8elementcounter) = *(Copy_u8plaintext+Local_u8elementcounter) 
				                                              ^ *(Copy_u8roundkeys+Local_u8elementcounter);
        }

         // inv Mix couloms
       AES_voidInvMixColoums( Copy_u8plaintext , Local_u8tmptext );
        
        // Inverse ShiftRows
        AES_voidInvShiftRows(Copy_u8plaintext);
        
        // Inverse SubBytes
        for (Local_u8elementcounter = ZERO; Local_u8elementcounter < AES_BLOCK_SIZE; ++Local_u8elementcounter)
				{
            *(Copy_u8plaintext+Local_u8elementcounter) = INV_SBOX[*(Copy_u8plaintext+Local_u8elementcounter)];
        }

        Copy_u8roundkeys -= AES_BLOCK_SIZE;

    }

    // last AddRoundKey
    for ( Local_u8elementcounter = ZERO; Local_u8elementcounter < AES_BLOCK_SIZE; ++Local_u8elementcounter ) 
		{
        *(Copy_u8plaintext+Local_u8elementcounter) ^= *(Copy_u8roundkeys+Local_u8elementcounter);
    }

}
/*****************************************************************END OF FUNCTION**************************************************************************************************************************************************************************************************************************/																                                  
void AES_VoidDecrypt_64Byte ( const u8 *Copy_u8roundkeys , const u8 *Copy_u8CipherText_64Byte , const u8 *Copy_u8PlainText_64Byte)
{

	u8 *Local_u8CipherTextPtr = Copy_u8CipherText_64Byte ;
	u8 *Local_u8PlainTextPtr  = Copy_u8PlainText_64Byte  ;

	 for (u8 Round_Counter = 0; Round_Counter < FOUR_ROUNDS ; Round_Counter++) // fetch 16 byte == one record and fill message1 array
    {
	 
 	          AES_VoidDecrypt_16Bytes ( Copy_u8roundkeys  , Local_u8CipherTextPtr  , Local_u8PlainTextPtr) ; //get 16 byte of plain text
	          Local_u8CipherTextPtr += FOUR_WORDS ;
	          Local_u8PlainTextPtr  += FOUR_WORDS ;	
    }
 }
/*****************************************************************END OF FUNCTION**************************************************************************************************************************************************************************************************************************/																                                  
void AES_VoidEncrypt_64Byte ( const u8 *Copy_u8roundkeys , const u8 *Copy_u8PlainText_64Byte , const u8 *Copy_u8CipherText_64Byte)
{

	u8 *Local_u8PlainTextPtr   = Copy_u8PlainText_64Byte ;
	u8 *Local_u8CipherTextPtr  = Copy_u8CipherText_64Byte  ;

	 for (u8 Round_Counter = 0; Round_Counter < FOUR_ROUNDS ; Round_Counter++) // fetch 16 byte == one record and fill message1 array
    {
	 
 	          AES_VoidEncrypt_16Bytes ( Copy_u8roundkeys  , Local_u8PlainTextPtr  , Local_u8CipherTextPtr) ; //get 16 byte of plain text
	          Local_u8CipherTextPtr += FOUR_WORDS ;
	          Local_u8PlainTextPtr  += FOUR_WORDS ;
	
   }
}
/*****************************************************************END OF FUNCTION**************************************************************************************************************************************************************************************************************************/																                                  

/*
void AES_VoidDecrypt_64Bytes (u8 *CipherText)
{

u32  Local_u32SizeAddress = Image->EncImage_SizeAddress ;
	
u32  Local_u32Size = *((volatile uint32*)Local_u32SizeAddress)  ;	

u32  Local_u32FirstAddress = Image->EncImage_FirstAddress ;
	
for ( u16 Record_Counter = 0 ;  Record_Counter < Local_u32Size ; Record_Counter ++  )
{	

	     for (u8 Data_Counter = 0; Data_Counter < 16; Data_Counter++) // fetch 16 byte == one record and fill message1 array
{
	
         	  CipherText[Data_Counter] = *((volatile uint8*)Local_u32FirstAddress) ; //Load the Data

		        Local_u32FirstAddress += 1 ; //step address by 1	
}
	
	
}

}*/


/*****************************************************************END OF FUNCTION**************************************************************************************************************************************************************************************************************************/																                                  