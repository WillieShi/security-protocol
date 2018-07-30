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


#include <stdlib.h>
#include "bearssl_rsa.h"
#include "bearssl_hash.h"
#include "usbserialprotocol.h"



//static uint8_t privkey[] = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789123456";

//const uint8 eeprom_ref[EEPROM_PHYSICAL_SIZE] __ALIGNED(CY_FLASH_SIZEOF_ROW) = {0u};

#define SIGNATURE_SIZE 256
#define KEY_SIZE 256
#define SALT_SIZE 256
#define ENCRYPTION_NUMBER_SIZE 64;
#define DOFF 36;

//Ben's crappy variable
#define PIN_LEN 8
#define UUID_LEN 36
#define PINCHG_SUC "SUCCESS"
#define PROV_MSG "P"
#define RECV_OK "K"
#define PIN_OK "OK"
#define PIN_BAD "BAD"
#define CHANGE_PIN '3'

#define PIN ((uint8*)(CY_FLASH_BASE + 0x6400))
#define UUID ((uint8*)(CY_FLASH_BASE + 0x6480))
#define PROVISIONED ((uint8*)(CY_FLASH_BASE + 0x6500))
#define write_pin(p) CySysFlashWriteRow(200, p);
#define write_uuid(u) CySysFlashWriteRow(201, u);


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

static const unsigned char SHA1_OID[] = {
	0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A
};


uint8_t result[1024*1024];

const uint8_t row[CY_FLASH_SIZEOF_ROW] CY_ALIGN(CY_FLASH_SIZEOF_ROW) = {0};
static uint8_t* readUART(uint8_t size);
static void writeUART(uint8_t* buffer, uint8_t size);
int checkArrays(uint8_t* array1, uint8_t* array2, int size);
uint8_t* readData(uint8_t* buffer);
uint8_t* readSignature(uint8_t* buffer);
uint8_t* readSalt(uint8_t* buffer);
static int check_equals(const void *v1, const void *v2, size_t len);
void mark_provisioned();
void provision();
void init();
unsigned char* RSA_decrypt512(br_rsa_private fpriv, char* msg, uint8_t size);
unsigned char* RSA_decrypt256(br_rsa_private fpriv, char* msg, uint8_t size);
int RSAver( br_rsa_pkcs1_vrfy fvrfy, unsigned char buf[256], unsigned char *pt, int sizept);
struct verificationPacket{uint8_t encryptedRandNum[256];uint8_t signature[256];};
struct onionPacket{uint8_t outerLayer[512];uint8_t signature[256];};
int computeVerify(struct verificationPacket pack);
int computeOnion(struct onionPacket pack, uint8_t* privkey);
struct verificationPacket readVerify();
struct onionPacket readOnion();
void getValidBytes(uint8_t* buffer, int n);
int main(void)
{
    CyGlobalIntEnable; /* Enable global interrupts. */

    uint8_t* db;
    uint8_t dump[KEY_SIZE*4];
    uint8_t readrow[CY_FLASH_SIZEOF_ROW];
    uint8_t cardnum[CY_FLASH_SIZEOF_ROW];
    uint8_t* verif;
    uint8_t* banksig;
    uint8_t* testbanksig;
    uint8_t* testbanksigver;
    uint8_t* privkey;
    uint8_t* data;
    uint8_t* everything;
    uint8_t* salt;
    uint8_t* pt;

    UART_Start();
    //init()
    //start process, recieve and write card num to mem
   
    for(int i = 0; i < 128; i++)
    {
        cardnum[i] = 'a';
    }
    CySysFlashWriteRow(150, cardnum); //write num to memory
    db = (uint8_t*) (CY_FLASH_BASE + 150*128); //look to make sure its good
    memcpy(readrow, db, CY_FLASH_SIZEOF_ROW);
    //UART_PutString("Testing ... Testing ...\n\r"); IT WORKS BABYYYYYYYYYYYy
    //writeUART(readrow, (uint8_t) CY_FLASH_SIZEOF_ROW);

    //recieve and write bank sig to mem
    UART_PutString("Give me the Bank signature\n\r");
    //RSA sign #TODO !MIGHT JUST BE THE PUBLIC KEY COME BACK TO THIS
    banksig = readUART((uint8_t) KEY_SIZE);
    UART_PutString("signature recieved\n\r");
    CySysFlashWriteRow(151, banksig);
    CySysFlashWriteRow(152, banksig+128);
    
    //debug 
    /*
    db = (uint8_t*) (CY_FLASH_BASE + 151*128);
    writeUART(db,(uint8_t) KEY_SIZE);
    memcpy(readrow, db, CY_FLASH_SIZEOF_ROW);
    writeUART(readrow, (uint8_t) CY_FLASH_SIZEOF_ROW);
    db = (uint8_t*) (CY_FLASH_BASE + 152*128);
    writeUART(db,(uint8_t) KEY_SIZE);
    memcpy(readrow, db, CY_FLASH_SIZEOF_ROW);
    writeUART(readrow, (uint8_t) CY_FLASH_SIZEOF_ROW);
    */

    //Write private key to memory
    //TODO composing RSA keys from components given from python code
    privkey = (uint8_t*)&RSA_SK; //does this work lol
    // EEPROM_Write(KEY_SIZE*2, privkey , KEY_SIZE);
    int row = 153;
    //key size 1636
    for(int i = 0; i < 13; i++)
    {
        CySysFlashWriteRow(row+i, privkey + (i*128));
        //debug
        /*
        db = (uint8_t*) (CY_FLASH_BASE + row+i*128);
        writeUART(db,(uint8_t) KEY_SIZE);
        memcpy(readrow, db, CY_FLASH_SIZEOF_ROW);
        writeUART(readrow, (uint8_t) CY_FLASH_SIZEOF_ROW);
        */
    }    
     
    UART_PutString("WRITE SUCCESSFUL\n\r");
    
    UART_PutString("Card Provisioning finished, dump all memory to double check\n\r");
    //writeUART(dump, (uint8_t) KEY_SIZE*4); //REMEMBER TO GET RID OF THIS SO THEY CAN'T EXPLOIT THIS

		for(;;){
            char* command[3];
			getValidBytes((uint8_t*) command, 3);
            if(strcmp((char*)command, "cir") == 0){
                pushMessage(cardnum, 32);
            }else if(strcmp((char*)command, "cvw") == 0){
                computeVerify(readVerify());
            }else if(strcmp((char*)command, "own") == 0){
                computeOnion(readOnion(), privkey);
            }
		}




    //MAIN Rsa Protocol
    //Recieve Transaction code
		/*
    UART_PutString("Give me the verification code\n\r");
    verif = readUART((uint8_t)KEY_SIZE);
    UART_PutString("Give me signature\n\r");
    testbanksigver = readUART((uint8_t)SIGNATURE_SIZE);
    UART_PutString("Decrypting and verifying...\n\r");
    verif = RSA_decrypt256(&br_rsa_i31_private, (char*) verif,(uint8_t) KEY_SIZE );
    //NEED TO DEBUG RSA VER
    if(RSAver(&br_rsa_i31_pkcs1_vrfy, testbanksigver,verif, KEY_SIZE) == -1)
    {
        UART_PutString("Signature wrong, terminating program\n\r");
        return -1;
    }
    UART_PutString("Signature verified...\n\r");
    UART_PutString("Sending be ready\n\r");
    writeUART(verif, sizeof(verif));
		*/

    //recieve data
		/*
    UART_PutString("Send over onion protected message\n\r");
    everything = readUART((uint8_t)KEY_SIZE*4);
    UART_PutString("Onion recieved ... Starting decrypt\n\r");

    EEPROM_Read(KEY_SIZE*2, privkey, KEY_SIZE); //load key from mem
    //should get 256 bytes
    everything = (uint8_t*) RSA_decrypt512(&br_rsa_i31_private, (char*) everything, (uint8_t) KEY_SIZE*2); //still needs to be modified assume works
    UART_PutString("Decryption done ... starting decomp\n\r");

    data = readData(everything);
    UART_PutString("data extracted\n\r");

    testbanksig = readSignature(everything);
    UART_PutString("sig extracted\n\r");

    salt = readSalt(everything);
    UART_PutString("salt extracted\n\r");

    UART_PutString("Decomp done\n\r");

    //Verify signature
    pt = malloc(KEY_SIZE*3*sizeof(uint8_t));
    memcpy(pt, everything, KEY_SIZE*3);
    if(RSAver(&br_rsa_i31_pkcs1_vrfy, testbanksig, pt , KEY_SIZE*3) == -1)
    {
        UART_PutString("Signature wrong, terminating program\n\r");
        return -1;
    }
    UART_PutString("Signature verified...\n\r");


    UART_PutString("Starting to send data ...\n\r");
    writeUART(data, sizeof(data));
    UART_PutString("Starting to send decrypted salt ...\n\r");
    writeUART(salt,sizeof(salt));
    UART_PutString("Starting to send signature ...\n\r");
		*/
}

void getValidBytes(uint8_t* buffer, int size)
{
    for(int i = 0; i < size; i++){
      while(UART_GetRxBufferSize() < 1); // wait for byte
      buffer[i] = UART_GetByte();
    }
}



struct verificationPacket readVerify()
{
  struct verificationPacket result;
  uint8_t encryptedRandNum[256]; 
  getValidBytes(encryptedRandNum, 256);
  memcpy(result.encryptedRandNum , encryptedRandNum, 256);
  uint8_t signature[256]; 
  getValidBytes(signature, 256);
  memcpy(result.signature , signature, 256);
  return result;
}

struct onionPacket readOnion()
{
  struct onionPacket result;
  uint8_t outerLayer[256]; 
  getValidBytes(outerLayer, 256);
  memcpy(result.outerLayer , outerLayer, 256);
  uint8_t signature[256]; 
  getValidBytes(signature, 256);
  memcpy(result.signature , signature, 256);
  return result;
}

int computeOnion(struct onionPacket pack, uint8_t* privkey){
	privkey = (uint8_t*) (CY_FLASH_BASE + 153*128);
   
	//should get 256 bytes
	uint8_t* innerLayer = (uint8_t*) RSA_decrypt512(&br_rsa_i31_private, (char*) pack.outerLayer, (uint8_t) KEY_SIZE*2); //still needs to be modified assume works
	//UART_PutString("Decryption done ... starting decomp\n\r");

	uint8_t* testbanksig = pack.signature;
	//UART_PutString("sig extracted\n\r");

	//Verify signature
	uint8_t* pt = malloc(KEY_SIZE*3*sizeof(uint8_t));
	memcpy(pt, innerLayer, KEY_SIZE*3);
	if(RSAver(&br_rsa_i31_pkcs1_vrfy, testbanksig, pt , KEY_SIZE*3) == -1)
	{
			//UART_PutString("Signature wrong, terminating program\n\r");
			return -1;
	}
	//UART_PutString("Signature verified...\n\r");


	//UART_PutString("Starting to send data ...\n\r");
	pushMessage(innerLayer, sizeof(innerLayer));
	//UART_PutString("Starting to send signature ...\n\r");
    return 1;
}


int computeVerify(struct verificationPacket pack){
	//UART_PutString("Give me the verification code\n\r");
	uint8_t* verif = pack.encryptedRandNum;
	//UART_PutString("Give me signature\n\r");
	uint8_t* testbanksigver = pack.signature;
	//UART_PutString("Decrypting and verifying...\n\r");
	verif = RSA_decrypt256(&br_rsa_i31_private, (char*) verif,(uint8_t) KEY_SIZE );
	//NEED TO DEBUG RSA VER
	if(RSAver(&br_rsa_i31_pkcs1_vrfy, testbanksigver,verif, KEY_SIZE) == -1)
	{
			//UART_PutString("Signature wrong, terminating program\n\r");
			return -1;
	}
	//UART_PutString("Signature verified...\n\r");
	//UART_PutString("Sending be ready\n\r");
	pushMessage(verif, sizeof(verif));
	return 0;
}

static uint8_t* readUART(uint8_t size)
{
    //uint8_t* result = malloc(size*sizeof(uint8_t));
    uint8_t* result;
    for(int i = 0; i < size; i++)
    {
        uint8_t rxData = (uint8_t)getValidByte();
        if(rxData)
        {
            result[i] = rxData;
            UART_PutChar(result[i]);
        }
    }

    return result;
}

static void writeUART(uint8_t* buffer, uint8_t size)
{
    for(int i = 0; i < size; i++)
    {
        UART_PutChar((char)buffer[i]);
    }
    UART_PutString("\n\r");
}

//TEST TOMORROW
/*
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
*/

//NOT TESTED YET
/*
static uint8_t* readMemory(int row, int size)
{
    uint8_t* result = malloc(CY_FLASH_SIZEOF_ROW * sizeof(uint8_t));
    for(int i = 0; i < size; i++)
    {
        result[i] = (uint8_t)(CY_FLASH_BASE + (CY_FLASH_SIZEOF_ROW * row) + (i*sizeof(uint8_t)));
    }
    return result;
}
*/

//Checks arrays against each other: for testing keys
int checkArrays(uint8_t* array1, uint8_t* array2, int size)
{
  for(int i = 0; i < size; i++)
    {
        if(array1[i] != array2[i])
        {
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

uint8_t* readSalt(uint8_t* buffer)
{
    uint8_t* result = malloc(SIGNATURE_SIZE*sizeof(uint8_t));
    int x = 0;
    //512 to 768
    for(int i = KEY_SIZE*2; i < KEY_SIZE*2 + SALT_SIZE; i++)
    {
        result[x] = buffer[i];
        x++;
    }
    return result;
}

//Reads the third 256 byte segment of data: salt
uint8_t* readSignature(uint8_t* buffer)
{
    uint8_t* result = malloc(SALT_SIZE*sizeof(uint8_t));
    int x = 0;
    //768 to 1024
    for(int i = KEY_SIZE*2 + SALT_SIZE; i < KEY_SIZE*2 + SIGNATURE_SIZE + SALT_SIZE; i++)
    {
        result[x] = buffer[i];
        x++;
    }
    return result;
}

static int check_equals(const void *v1, const void *v2, size_t len)
{

	if (memcmp(v1, v2, len) == 0) {
		return 1;
	}
	//fprintf(stderr, "\n");
	//exit(EXIT_FAILURE);
    return -1;
}

unsigned char* RSA_decrypt512(br_rsa_private fpriv, char* msg, uint8_t size)
{
    unsigned char tmp[256];
    unsigned char tmp2[256];
    unsigned char* ret = malloc(size*sizeof(unsigned char));

    memcpy(tmp, msg, size/2);
    memcpy(tmp2, msg+256, size/2);

    //decrypt first
    if (!fpriv(tmp, &RSA_SK))
    {
		//fprintf(stderr, "RSA private operation failed\n");
        UART_PutString("RSA PRIV OP FAILED\n\r");
		exit(EXIT_FAILURE);
	}

    //decrypted second
    if (!fpriv(tmp2, &RSA_SK))
    {
		//fprintf(stderr, "RSA private operation failed\n");
        UART_PutString("RSA PRIV OP FAILED\n\r");
		exit(EXIT_FAILURE);
	}

    memcpy(ret, tmp, KEY_SIZE);
    memcpy(ret+128, tmp2, KEY_SIZE);


    return ret;

}

unsigned char* RSA_decrypt256(br_rsa_private fpriv, char* msg, uint8_t size)
{
    //unsigned char tmp[256];
    unsigned char* tmp = malloc(size*sizeof(unsigned char));
    memcpy(tmp, msg, size);

    //decrypt first
    if (!fpriv(tmp, &RSA_SK))
    {
		//fprintf(stderr, "RSA private operation failed\n");
        UART_PutString("RSA PRIV OP FAILED\n\r");
		exit(EXIT_FAILURE);
	}

    return tmp;

}
//returns 1 if verified, returns 0 if not
int RSAver( br_rsa_pkcs1_vrfy fvrfy, unsigned char buf[256], unsigned char *pt, int sizept)
{
    unsigned char t1[256];
	unsigned char hv[256], tmp[256];
	br_sha1_context hc;

    memcpy(t1, buf, SIGNATURE_SIZE);
    br_sha1_init(&hc);
	br_sha1_update(&hc, pt, sizept);
	br_sha1_out(&hc, hv);
	if (!fvrfy(t1, sizeof t1, SHA1_OID, sizeof tmp, &RSA_PK, tmp)) {
		//fprintf(stderr, "Signature verification failed\n");
		return 0;
	}
	int i = check_equals( hv, tmp, sizeof tmp);
    if(i == -1)
    {
        return 0;
    }
    return 1;


}

void mark_provisioned()
{
    uint8 row[128];
    *row = 1;
    CySysFlashWriteRow(202, row);
}

// provisions card (should only ever be called once)
void provision()
{
    uint8 message[128];

    // synchronize with bank
    syncConnection(SYNC_PROV);

    pushMessage((uint8*)PROV_MSG, (uint8)strlen(PROV_MSG));

    // set PIN
    pullMessage(message);
    write_pin(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));

    // set account number
    pullMessage(message);
    write_uuid(message);
    pushMessage((uint8*)RECV_OK, strlen(RECV_OK));
}

void init()
{
    /* Declare vairables here */
    uint8 message[128];

    //while(1) UART_UartPutString("HELLO WORLD!\r\n");
    // Provision card if on first boot
    if (*PROVISIONED == 0x00) {
        provision();
        mark_provisioned();
    }

    // Go into infinite loop
    while (1) {
        /* Place your application code here. */

        // syncronize communication with bank
        syncConnection(SYNC_NORM);

        // receive pin number from ATM
        pullMessage(message);

        if (strncmp((char*)message, (char*)PIN, PIN_LEN)) {
            pushMessage((uint8*)PIN_BAD, strlen(PIN_BAD));
        } else {
            pushMessage((uint8*)PIN_OK, strlen(PIN_OK));

            // get command
            pullMessage(message);
            pushMessage((uint8*)RECV_OK, strlen(RECV_OK));

            // change PIN or broadcast UUID
            if(message[0] == CHANGE_PIN)
            {
                pullMessage(message);
                write_pin(message);
                pushMessage((uint8*)PINCHG_SUC, strlen(PINCHG_SUC));
            } else {
                pushMessage(UUID, UUID_LEN);
            }
        }
    }
}
