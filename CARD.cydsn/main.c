/* ========================================
 *
 * Copyright YOUR COMPANY, THE YEAR
 * All Rights Reserved
 * UNPUBLISHED, LICENSED SOFTWARE.
 *
 * CONFIDENTIAL AND PROPRIETARY INFORMATION
 * WHICH IS THE PROPERTY OF your company.
 *
 * ========================================
*/
#include "project.h"
#include "usbserialprotocol.h"

#include <stdlib.h>
#include "bearssl_rsa.h"



//static uint8_t privkey[] = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789123456";

const uint8 eeprom_ref[EEPROM_PHYSICAL_SIZE] __ALIGNED(CY_FLASH_SIZEOF_ROW) = {0u};

#define SIGNATURE_SIZE 25                                                                                   
#define KEY_SIZE 256
#define SALT_SIZE 256
#define ENCRYPTION_NUMBER_SIZE 64;



static const unsigned char RSA_N[] = {
	0xBF, 0xB4, 0xA6, 0x2E, 0x87, 0x3F, 0x9C, 0x8D,
	0xA0, 0xC4, 0x2E, 0x7B, 0x59, 0x36, 0x0F, 0xB0,
	0xFF, 0xE1, 0x25, 0x49, 0xE5, 0xE6, 0x36, 0xB0,
	0x48, 0xC2, 0x08, 0x6B, 0x77, 0xA7, 0xC0, 0x51,
	0x66, 0x35, 0x06, 0xA9, 0x59, 0xDF, 0x17, 0x7F,
	0x15, 0xF6, 0xB4, 0xE5, 0x44, 0xEE, 0x72, 0x3C,
	0x53, 0x11, 0x52, 0xC9, 0xC9, 0x61, 0x4F, 0x92,
	0x33, 0x64, 0x70, 0x43, 0x07, 0xF1, 0x3F, 0x7F,
	0x15, 0xAC, 0xF0, 0xC1, 0x54, 0x7D, 0x55, 0xC0,
	0x29, 0xDC, 0x9E, 0xCC, 0xE4, 0x1D, 0x11, 0x72,
	0x45, 0xF4, 0xD2, 0x70, 0xFC, 0x34, 0xB2, 0x1F,
	0xF3, 0xAD, 0x6A, 0xF0, 0xE5, 0x56, 0x11, 0xF8,
	0x0C, 0x3A, 0x8B, 0x04, 0x46, 0x7C, 0x77, 0xD9,
	0x41, 0x1F, 0x40, 0xBE, 0x93, 0x80, 0x9D, 0x23,
	0x75, 0x80, 0x12, 0x26, 0x5A, 0x72, 0x1C, 0xDD,
	0x47, 0xB3, 0x2A, 0x33, 0xD8, 0x19, 0x61, 0xE3
};
static const unsigned char RSA_E[] = {
	0x01, 0x00, 0x01
};
/* unused
static const unsigned char RSA_D[] = {
	0xAE, 0x56, 0x0B, 0x56, 0x7E, 0xDA, 0x83, 0x75,
	0x6C, 0xC1, 0x5C, 0x00, 0x02, 0x96, 0x1E, 0x58,
	0xF9, 0xA9, 0xF7, 0x2E, 0x27, 0xEB, 0x5E, 0xCA,
	0x9B, 0xB0, 0x10, 0xD6, 0x22, 0x7F, 0xA4, 0x6E,
	0xA2, 0x03, 0x10, 0xE6, 0xCB, 0x7B, 0x0D, 0x34,
	0x1E, 0x76, 0x37, 0xF5, 0xD3, 0xE5, 0x00, 0x70,
	0x09, 0x9E, 0xD4, 0x69, 0xFB, 0x40, 0x0A, 0x8B,
	0xCB, 0x3E, 0xC8, 0xB4, 0xBC, 0xB1, 0x50, 0xEA,
	0x9D, 0xD9, 0x89, 0x8A, 0x98, 0x40, 0x79, 0xD1,
	0x07, 0x66, 0xA7, 0x90, 0x63, 0x82, 0xB1, 0xE0,
	0x24, 0xD0, 0x89, 0x6A, 0xEC, 0xC5, 0xF3, 0x21,
	0x7D, 0xB8, 0xA5, 0x45, 0x3A, 0x3B, 0x34, 0x42,
	0xC2, 0x82, 0x3C, 0x8D, 0xFA, 0x5D, 0xA0, 0xA8,
	0x24, 0xC8, 0x40, 0x22, 0x19, 0xCB, 0xB5, 0x85,
	0x67, 0x69, 0x60, 0xE4, 0xD0, 0x7E, 0xA3, 0x3B,
	0xF7, 0x70, 0x50, 0xC9, 0x5C, 0x97, 0x29, 0x49
};
*/
static const unsigned char RSA_P[] = {
	0xF2, 0xE7, 0x6F, 0x66, 0x2E, 0xC4, 0x03, 0xD4,
	0x89, 0x24, 0xCC, 0xE1, 0xCD, 0x3F, 0x01, 0x82,
	0xC1, 0xFB, 0xAF, 0x44, 0xFA, 0xCC, 0x0E, 0xAA,
	0x9D, 0x74, 0xA9, 0x65, 0xEF, 0xED, 0x4C, 0x87,
	0xF0, 0xB3, 0xC6, 0xEA, 0x61, 0x85, 0xDE, 0x4E,
	0x66, 0xB2, 0x5A, 0x9F, 0x7A, 0x41, 0xC5, 0x66,
	0x57, 0xDF, 0x88, 0xF0, 0xB5, 0xF2, 0xC7, 0x7E,
	0xE6, 0x55, 0x21, 0x96, 0x83, 0xD8, 0xAB, 0x57
};
static const unsigned char RSA_Q[] = {
	0xCA, 0x0A, 0x92, 0xBF, 0x58, 0xB0, 0x2E, 0xF6,
	0x66, 0x50, 0xB1, 0x48, 0x29, 0x42, 0x86, 0x6C,
	0x98, 0x06, 0x7E, 0xB8, 0xB5, 0x4F, 0xFB, 0xC4,
	0xF3, 0xC3, 0x36, 0x91, 0x07, 0xB6, 0xDB, 0xE9,
	0x56, 0x3C, 0x51, 0x7D, 0xB5, 0xEC, 0x0A, 0xA9,
	0x7C, 0x66, 0xF9, 0xD8, 0x25, 0xDE, 0xD2, 0x94,
	0x5A, 0x58, 0xF1, 0x93, 0xE4, 0xF0, 0x5F, 0x27,
	0xBD, 0x83, 0xC7, 0xCA, 0x48, 0x6A, 0xB2, 0x55
};
static const unsigned char RSA_DP[] = {
	0xAF, 0x97, 0xBE, 0x60, 0x0F, 0xCE, 0x83, 0x36,
	0x51, 0x2D, 0xD9, 0x2E, 0x22, 0x41, 0x39, 0xC6,
	0x5C, 0x94, 0xA4, 0xCF, 0x28, 0xBD, 0xFA, 0x9C,
	0x3B, 0xD6, 0xE9, 0xDE, 0x56, 0xE3, 0x24, 0x3F,
	0xE1, 0x31, 0x14, 0xCA, 0xBA, 0x55, 0x1B, 0xAF,
	0x71, 0x6D, 0xDD, 0x35, 0x0C, 0x1C, 0x1F, 0xA7,
	0x2C, 0x3E, 0xDB, 0xAF, 0xA6, 0xD8, 0x2A, 0x7F,
	0x01, 0xE2, 0xE8, 0xB4, 0xF5, 0xFA, 0xDB, 0x61
};
static const unsigned char RSA_DQ[] = {
	0x29, 0xC0, 0x4B, 0x98, 0xFD, 0x13, 0xD3, 0x70,
	0x99, 0xAE, 0x1D, 0x24, 0x83, 0x5A, 0x3A, 0xFB,
	0x1F, 0xE3, 0x5F, 0xB6, 0x7D, 0xC9, 0x5C, 0x86,
	0xD3, 0xB4, 0xC8, 0x86, 0xE9, 0xE8, 0x30, 0xC3,
	0xA4, 0x4D, 0x6C, 0xAD, 0xA4, 0xB5, 0x75, 0x72,
	0x96, 0xC1, 0x94, 0xE9, 0xC4, 0xD1, 0xAA, 0x04,
	0x7C, 0x33, 0x1B, 0x20, 0xEB, 0xD3, 0x7C, 0x66,
	0x72, 0xF4, 0x53, 0x8A, 0x0A, 0xB2, 0xF9, 0xCD
};
static const unsigned char RSA_IQ[] = {
	0xE8, 0xEB, 0x04, 0x79, 0xA5, 0xC1, 0x79, 0xDE,
	0xD5, 0x49, 0xA1, 0x0B, 0x48, 0xB9, 0x0E, 0x55,
	0x74, 0x2C, 0x54, 0xEE, 0xA8, 0xB0, 0x01, 0xC2,
	0xD2, 0x3C, 0x3E, 0x47, 0x3A, 0x7C, 0xC8, 0x3D,
	0x2E, 0x33, 0x54, 0x4D, 0x40, 0x29, 0x41, 0x74,
	0xBA, 0xE1, 0x93, 0x09, 0xEC, 0xE0, 0x1B, 0x4D,
	0x1F, 0x2A, 0xCA, 0x4A, 0x0B, 0x5F, 0xE6, 0xBE,
	0x59, 0x0A, 0xC4, 0xC9, 0xD9, 0x82, 0xAC, 0xE1
};

static const br_rsa_public_key RSA_PK = {
	(void *)RSA_N, sizeof RSA_N,
	(void *)RSA_E, sizeof RSA_E
};

static const br_rsa_private_key RSA_SK = {
	1024,
	(void *)RSA_P, sizeof RSA_P,
	(void *)RSA_Q, sizeof RSA_Q,
	(void *)RSA_DP, sizeof RSA_DP,
	(void *)RSA_DQ, sizeof RSA_DQ,
	(void *)RSA_IQ, sizeof RSA_IQ
};



uint8_t result[1024*1024];

const uint8_t row[CY_FLASH_SIZEOF_ROW] CY_ALIGN(CY_FLASH_SIZEOF_ROW) = {0};
static size_t;
static uint8_t* readUART();
static void writeUART(uint8_t* buffer);
static void writeMemory(int row, uint8_t* buffer);
static uint8_t* readMemory(int row,  int size);
int checkArrays(uint8_t* array1, uint8_t* array2, int size);
uint8_t* readData(uint8_t* buffer);
uint8_t* readSignature(uint8_t* buffer);
uint8_t* readSalt(uint8_t* buffer);
uint8_t* rsaDecrypt(uint8_t ct[], int size);
static int check_equals(const char *banner, const void *v1, const void *v2, size_t len);
uint8_t* test_RSA_core(const char *name, br_rsa_public fpub, br_rsa_private fpriv, uint8_t* msg);
int hex_to_int(char c);
int hex_to_ascii(char c, char d);

int main(void)
{
    CyGlobalIntEnable; /* Enable global interrupts. */

    //uint8_t* privKey = readMemory(0, KEY_SIZE);
    //uint8_t* bankSig = readMemory(2, SIGNATURE_SIZE);
    //int* cardNum = (int*)readMemory(4, KEY_SIZE);
   
   
    
    //int return_val;
    uint8_t db[KEY_SIZE];
    uint8_t* cardnum;
    uint8_t* banksig;
    uint8_t* testbanksig;
    uint8_t* privkey;
    uint8_t* data;
    uint8_t* everything;
    uint8_t* salt;
    const char test[] = "hello world";
    
    
    UART_Start();
    EEPROM_Init((uint32)eeprom_ref);
    
    //start process, recieve and write card num to mem
    writeUART((uint8_t*) "Start card prod, give me card number\n");
    cardnum = readUART(); //ask laslo about it dangerous since we give them things to write?
    writeUART((uint8_t*)"num recieved\n");
    EEPROM_Write(0, cardnum, KEY_SIZE); //write num to memory
    EEPROM_Read(0, db, KEY_SIZE); //look to make sure its good
    
    //recieve and write bank sig to mem
    writeUART((uint8_t*) "Give me the Bank signature");
    //RSA sign #TODO
    banksig = readUART();
    writeUART((uint8_t*)"signature recieved\n");
    EEPROM_Write(KEY_SIZE, banksig, KEY_SIZE); //write num to memory
    EEPROM_Read(KEY_SIZE, db, KEY_SIZE); //look to make sure its good
    writeUART(db);
    
    //Write private key to memory
    //TODO composing RSA keys from components given from python code
    privkey = (uint8_t*)&RSA_SK; //does this work lol
    EEPROM_Write(KEY_SIZE*2, privkey , KEY_SIZE);
    writeUART((uint8_t*)"WRITE SUCCESSFUL\n");
    EEPROM_Read(KEY_SIZE*2, db, KEY_SIZE); //look to make sure its good
    writeUART(db);
    
    writeUART((uint8_t*)"Card Christening finished, dump all memory to double check\n");
    EEPROM_Read(0, db, KEY_SIZE*4);
    writeUART(db);
    
    //MAIN Rsa Protocol
    //recieve data
    writeUART((uint8_t*) "Send over onion protected message\n");
    everything = readUART();
    writeUART((uint8_t*) "Onion recieved ... Starting decrypt\n");
    data = readData(everything);
    
    EEPROM_Read(KEY_SIZE*2, privkey, KEY_SIZE); //load key from mem
    everything = test_RSA_core(&test[0], &br_rsa_i31_public, &br_rsa_i31_private, everything); //still needs to be modified assume works
    writeUART((uint8_t*) "Decryption done ... starting decomp\n");
    
    writeUART((uint8_t*) "data extracted\n");
    testbanksig = readSignature(everything);
    writeUART((uint8_t*) "sig extracted\n");
    if(*banksig != *testbanksig)
    {
        writeUART((uint8_t*) "Wrong signature ... terminating application");
        return -1;
    }
    salt = readSalt(everything);
    writeUART((uint8_t*) "salt extracted\n");
    writeUART((uint8_t*) "Decomp done\n");
    
    writeUART((uint8_t*) "Starting to send data ...\n");
    writeUART(data);
    writeUART((uint8_t*) "Starting to send decrypted salt ...\n");
    writeUART(salt);
    writeUART((uint8_t*) "Starting to send signature ...\n");
    //TODO implment RSA signature
    
    
    
    
    
    
    
    
    /*
    if(checkArrays(readMemory(0, KEY_SIZE), testKey, KEY_SIZE))
      {
        writeUART((uint8_t*)"Successful read/write of key");
      }
    else
    {
        writeUART((uint8_t*)"Unsuccessful read/write of key");
    }
    writeUART((uint8_t*)"Waiting for 3*256 byte input");

    uint8_t* read = readUART();
    writeUART((uint8_t*)"Writing first value");
    writeUART(readData(read));
    writeUART((uint8_t*)"Writing first value");
    writeUART(readSignature(read));
    writeUART((uint8_t*)"Writing first value");
    writeUART(readSalt(read));
    */
    
    for(;;)
    {
        //UART_PutString("Test String\n");
        
        /* Place your application code here. */
        //UART_PutString("Test String \n");
        //TODO Card checking ATM identity
        //code for sending hash
        /*
        writeUART((uint8_t*)"___Sending card number___");
        writeUART((uint8_t*)cardNum);
        writeUART((uint8_t*)"___Sent card number___");
        
        //Read checknum, decrypt and return with salt to ATM
        uint8_t* checkNumE = readUART();
        writeUART((uint8_t*)"___Received checkNum___");
        uint8_t* checkNumD = readData(rsaDecrypt(checkNumE, sizeof(checkNumE, sizeof(checkNumE))));
        uint8_t* candBankSig = readSignature(rsaDecrypt(checkNumE, sizeof(checkNumE)));
        uint8_t* salt = readSalt(rsaDecrypt(checkNumE, sizeof(checkNumE)));
        if(checkArrays(candBankSig, bankSig, SIGNATURE_SIZE))
        {
            writeUART(checkNumD);
            writeUART(salt);
            writeUART((uint8_t*)"___Correct signature sent checknum___");
        }
        else
        {
            writeUART((uint8_t*)"___Incorrect signature did not send checknum___");
        }
 
        
        //Read onion, decrypt, and send back inner layer with salt back to ATM
        uint8_t* onionE = readUART();
        writeUART((uint8_t*)"___Received onion___");
        uint8_t* onionD = readData(rsaDecrypt(onionE, sizeof(onionE)));
        candBankSig = readSignature(rsaDecrypt(onionE, sizeof(onionE)));
        //salt = readSalt(rsaDecrypt(onionE, privKey));
        if(checkArrays(candBankSig, bankSig, SIGNATURE_SIZE))
        {
            writeUART(onionD);
            //writeUART(salt);
            writeUART((uint8_t*)"___Correct signature sent onion___");
        }
        else
        {
            writeUART((uint8_t*)"___Incorrect signature did not send onion___");
        }
        */
        
    }
}

  

static uint8_t* readUART(){
  uint8_t* result = malloc(KEY_SIZE*sizeof(uint8_t));
  for(int i = 0; i < KEY_SIZE;){
    uint8_t rxData = (uint8_t)UART_GetChar();
    if(rxData)
    {
        result[i] = rxData;
    }
  }
  return result;
}

static void writeUART(uint8_t* buffer)
{
  for(int i = 0; i < KEY_SIZE; i++)
  {
    UART_PutChar((char)buffer[i]);
  }
}

//TEST TOMORROW
static void writeMemory(int row, uint8_t* buffer){
  uint8_t* firstHalf = malloc(CY_FLASH_SIZEOF_ROW*sizeof(uint8_t));
  uint8_t* secondHalf = malloc(CY_FLASH_SIZEOF_ROW*sizeof(uint8_t));
  for(uint32 i = 0; i < CY_FLASH_SIZEOF_ROW; i++){
    firstHalf[i] = buffer[i];
    secondHalf[i] = buffer[i+CY_FLASH_SIZEOF_ROW];
  }
  CySysFlashWriteRow((uint32_t)row, firstHalf);
  CySysFlashWriteRow((uint32_t)(row+1), secondHalf);
}

//NOT TESTED YET
static uint8_t* readMemory(int row, int size){
  uint8_t* result = malloc(CY_FLASH_SIZEOF_ROW * sizeof(uint8_t));
  for(int i = 0; i < size; i++){
    result[i] = (uint8_t)(CY_FLASH_BASE + (CY_FLASH_SIZEOF_ROW * row) + (i*sizeof(uint8_t)));
  }
  return result;
}

//Checks arrays against each other: for testing keys
int checkArrays(uint8_t* array1, uint8_t* array2, int size){
  for(int i = 0; i < size; i++){
    if(array1[i] != array2[i]){
      return 0;
    }
  }
  return 1;
}

uint8_t* readData(uint8_t* buffer)
{
  uint8_t* result = malloc(KEY_SIZE*sizeof(uint8_t));
  for(int i = 0; i < KEY_SIZE; i++){
    result[i] = buffer[i];
  }
  return result;
}

uint8_t* readSignature(uint8_t* buffer){
  uint8_t* result = malloc(SIGNATURE_SIZE*sizeof(uint8_t));
  for(int i = KEY_SIZE; i < KEY_SIZE + SIGNATURE_SIZE; i++){
    result[i - KEY_SIZE] = buffer[i];
  }
  return result;
}

//Reads the third 256 byte segment of data: salt
uint8_t* readSalt(uint8_t* buffer){
  uint8_t* result = malloc(SALT_SIZE*sizeof(uint8_t));
  for(int i = KEY_SIZE + SIGNATURE_SIZE; i < KEY_SIZE + SIGNATURE_SIZE + SALT_SIZE; i++){
    result[i - KEY_SIZE - SIGNATURE_SIZE] = buffer[i];
  }
  return result;
}

static int check_equals(const char *banner, const void *v1, const void *v2, size_t len)
{
	size_t u;
	const unsigned char *b;

	if (memcmp(v1, v2, len) == 0) {
		return 1;
	}
	//fprintf(stderr, "\n%s failed\n", banner);
	//fprintf(stderr, "v1: ");
	for (u = 0, b = v1; u < len; u ++) {
		//fprintf(stderr, "%02X", b[u]);
	}
	//fprintf(stderr, "\nv2: ");
	for (u = 0, b = v2; u < len; u ++) {
		//fprintf(stderr, "%02X", b[u]);
	}
	//fprintf(stderr, "\n");
	//exit(EXIT_FAILURE);
    return 0;
}

static size_t
hextobin(unsigned char *dst, const char *src)
{
	size_t num;
	unsigned acc;
	int z;

	num = 0;
	z = 0;
	acc = 0;
	while (*src != 0) {
		int c = *src ++;
		if (c >= '0' && c <= '9') {
			c -= '0';
		} else if (c >= 'A' && c <= 'F') {
			c -= ('A' - 10);
		} else if (c >= 'a' && c <= 'f') {
			c -= ('a' - 10);
		} else {
			continue;
		}
		if (z) {
			*dst ++ = (acc << 4) + c;
			num ++;
		} else {
			acc = c;
		}
		z = !z;
	}
	return num;
}






uint8_t* test_RSA_core(const char *name, br_rsa_public fpub, br_rsa_private fpriv, uint8_t* msg)
{
	uint8_t t1[128], t2[128], t3[128];
    /*
    unsigned char t1[5], t2[5], t3[5];
    unsigned char *t2in;
    t2in = t1;
    *t2 = *t2in;
    */

	//printf("Test %s: ", name);
	//fflush(stdout);

	/*
	 * A KAT test (computed with OpenSSL).
	 */
	hextobin(t1, "45A3DC6A106BCD3BD0E48FB579643AA3FF801E5903E80AA9B43A695A8E7F454E93FA208B69995FF7A6D5617C2FEB8E546375A664977A48931842AAE796B5A0D64393DCA35F3490FC157F5BD83B9D58C2F7926E6AE648A2BD96CAB8FCCD3D35BB11424AD47D973FF6D69CA774841AEC45DFAE99CCF79893E7047FDE6CB00AA76D");
	hextobin(t2, "0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003021300906052B0E03021A05000414A94A8FE5CCB19BA61C4C0873D391E987982FBBD3");
	
    memcpy(t3, t1, sizeof t1);
    //t3 stores output of function
    //encrypt
	if (!fpub(t3, sizeof t3, &RSA_PK)) {
		//fprintf(stderr, "RSA public operation failed\n");
        writeUART((uint8_t*)"RSA PUB OP FAILED\n");
		exit(EXIT_FAILURE);
	}
    //decrpyt
    
	check_equals("KAT RSA pub", t2, t3, sizeof t2);
	if (!fpriv(t3, &RSA_SK)) {
		//fprintf(stderr, "RSA private operation failed\n");
        writeUART((uint8_t*)"RSA PRIV OP FAILED\n");
		exit(EXIT_FAILURE);
	}
	check_equals("KAT RSA priv", t1, t3, sizeof t1);
    writeUART(t3);
    //UART_PutString((uint8_t*)"SUCESS BOIZ");

	//printf("done.\n");
	//fflush(stdout);
    uint8_t *bin= t3;
    uint8_t *a = bin;
    int num = 0;
    do {
        int b = *a=='1'?1:0;
        num = (num<<1)|b;
        a++;
    } while (*a);
    writeUART((uint8_t*) num);
    //printf("%X\n", num);
    
    return msg;
    
}
int hex_to_ascii(char c, char d){
        int high = hex_to_int(c) * 16;
        int low = hex_to_int(d);
        return high+low;
}
int hex_to_int(char c){
        int first = c / 16 - 3;
        int second = c % 16;
        int result = first*10 + second;
        if(result > 9) result--;
        return result;
}


