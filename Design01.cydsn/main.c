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


//priv key components
#define RSAN ((uint8*)(CY_FLASH_BASE + 200)
#define RSAE ((uint8*)(CY_FLASH_BASE + 204)
#define RSAQ ((uint8*)(CY_FLASH_BASE + 205)
#define RSAP ((uint8*)(CY_FLASH_BASE + 207)
#define RSADP ((uint8*)(CY_FLASH_BASE + 209)
#define RSAQP ((uint8*)(CY_FLASH_BASE + 212)
#define RSAIQ ((uint8*)(CY_FLASH_BASE + 214)
//compnents will be stored from 200-208
//16*8*2 = 256
//row 200-201
//define them same method as ben janice's variables
//512 200-203
static const unsigned char RSA_N[] = {

    0xa1,0x80,0x40,0xf2,0x10,0x98,0xfb,0xf2,0xc0,0xd6,0x3f,0xf8,0x80,0xb3,0x17,0x97,0x24,0x4e,0x4f,0x9a,0xf3,0xb0,0xca,0x65,0x79,0xe8,0x57,0x4a,0x58,0x8c,0x09,0x9a,0x38,0xc2,0x7f,0xc5,0x58,0x8d,0xb3,0x7d,0xb0,0x12,0x10,0x4f,0xc5,0x8d,0x04,0x16,0x5c,0x85,0x07,0x5a,0x66,0xf2,0x3e,0x21,0x7e,0xb9,0x98,0xa8,0xcb,0x91,0x49,0x37,0xf7,0xe6,0xc0,0xe2,0xae,0x82,0x77,0x1b,0x87,0x78,0x90,0x27,0x9d,0xb2,0xd1,0xdf,0x38,0x89,0x7e,0x6a,0x7c,0xf5,0xe5,0xe0,0x22,0x85,0xba,0x0b,0xb0,0x36,0x4c,0x6a,0xb3,0x96,0x88,0x48,0xb7,0x86,0xc4,0x9b,0x1f,0xf4,0x7d,0x00,0xe4,0x54,0x4e,0xd6,0x2c,0x70,0x41,0x3a,0x1e,0x4a,0x00,0x66,0x40,0xa6,0x4e,0x05,0x91,0x00,0xba,0xa0,0x0f,0xd8,0xbc,0x1e,0x1b,0xca,0x5c,0x07,0xfc,0x4b,0xe6,0x7c,0x6f,0xe1,0xf2,0x2f,0x4f,0x4b,0x4e,0xfb,0x13,0xfa,0x5a,0xb1,0xf8,0xe5,0x1f,0x4d,0x91,0xf7,0x99,0x82,0x70,0x11,0x37,0xe7,0x68,0x4f,0x51,0x28,0xd3,0x2b,0x6e,0x6f,0x44,0x0f,0x62,0x3c,0x49,0x38,0xb1,0xcd,0xc7,0x3f,0xe7,0xd3,0x44,0x43,0x30,0x86,0x7a,0x8a,0x46,0x19,0xc3,0xb4,0xc1,0x76,0x9c,0x3f,0xd3,0xbd,0xc3,0x11,0xff,0x42,0x74,0x03,0xac,0x0e,0xc8,0x1f,0x04,0x82,0x8e,0x04,0x23,0x88,0xe3,0x9b,0xa9,0x41,0x71,0x52,0x1b,0x4d,0x15,0xad,0x29,0xaa,0xf2,0x5f,0x5f,0x49,0xc4,0x31,0xc0,0x38,0x52,  
0xc3,0xfd,0x3d,0x0d,0xb9,0xea,0xe2,0xef,0x2e,0xc2,0x9f,0xea,0x94,0xfc,0x47,0x48,0xdb,0x8b,0xcb

};
//5 204
static const unsigned char RSA_E[] = {
	0x10, 0x00, 0x01
};

//256 205-6
static const unsigned char RSA_Q[] = {
	0xD9,0x90,0x7C,0xFA,0x42,0xCD,0xA2,0x14,0xC3,0x58,0x24,0x85,0x3A,0x91,0x69,0x66,0x59,0x06,0x48,0xAA,0x59,0x5D,0x21,0x4F,0x03,0x2E,0x9D,0x0E,0x7D,0x2F,0xE7,0xE7,0x33,0xED,0x34,0x3B,0xB6,0x16,0x11,0x2F,0x43,0x41,0x6F,0x7D,0xA0,0x6A,0x63,0x19,0xB6,0xBA,0x2B,0x99,0xF9,0x09,0x71,0x76,0x9D,0xCA,0x57,0x8F,0x59,0x49,0xD4,0x33,0xFE,0x29,0x72,0xDC,0xF9,0xC1,0xDD,0x66,0x0B,0x39,0x41,0x39,0x34,0xD2,0x1A,0x86,0xA8,0xD4,0x92,0x1D,0xE6,0xA3,0x81,0x44,0xB9,0x51,0xB2,0x81,0x87,0x2E,0x8C,0x43,0xFA,0x83,0x8D,0x03,0x2A,0xFE,0xE1,0x73,0x1E,0xDC,0xE9,0x9D,0xAF,0xE7,0x3F,0x29,0x2C,0x10,0xA1,0xC6,0x37,0x7B,0xE5,
0x7F,0x2C,0x68,0xF4,0xA8,0x84,0xB7,0xBD,0xE3    



};
//256 207-8
static const unsigned char RSA_P[] = 
{
   0xC6,0x68,0x0B,0xDA,0xAD,0x0E,0xBC,0x1E,0x43,0x01,0x75,0x21,0x87,0x31,0xE8,0xF5,0x0A,0x3B,0xE3,0x67,0x01,0x1B,0x5D,0xCE,0x24,0x99,0xA4,0xC8,0xDA,0x70,0x4D,0x5F,0xEC,0xDC,0x7C,0x20,0x2D,0xAC,0x41,0x97,0x1B,0x3A,0xFE,0xE2,0x04,0xFA,0xE1,0x5E,0xA0,0x88,0x4E,0x45,0x02,0x4B,0xD9,0x9E,0x2E,0xC7,0x9F,0x0B,0xDC,0xC2,0x6A,0xAC,0x78,0x9A,0x3B,0x66,0x7B,0xE4,0x0B,0xC9,0x2F,0x11,0xCA,0x53,0x4D,0xF5,0x82,0x25,0xDD,0xAA,0x6D,0x30,0x13,0xE5,0x46,0x18,0x61,0x86,0xA6,0x58,0x2D,0xA7,0xA5,0x8C,0x21,0x8F,0xFF,0x0C,0xC0,0xB7,0xA2,0x15,0x19,0x22,0xB7,0xFF,0x52,0x6A,0x61,0x7E,0x8F,0xC8,0xE0,0xDE,0xF5,0xCF,0x67,  
0xAC,0xA7,0x18,0xD6,0x3C,0x1B,0x7B,0x4C,0x07  



};

//258... WHYHYHYHYHHYHHYHYHHYHHY 209-11
static const unsigned char RSA_DP[] = {
	0x22,0xeb,0x77,0x94,0xec,0x9f,0x3d,0x03,0xdf,0x0d,0xd2,0x14,0x9b,0xa6,0x80,0x4c,0x34,0x53,0xf5,0x7e,0x1f,0x97,0x40,0x7d,0xb9,0xe6,0x55,0x31,0x9d,0xab,0x40,0xfc,0x08,0x7c,0x55,0x64,0x61,0x03,0x54,0xfb,0xbe,0xcd,0x92,0x24,0x13,0xd2,0xf7,0x8f,0x7f,0x47,0xfb,0x97,0xaa,0x02,0x08,0xe8,0xf1,0xe8,0xb6,0x38,0xe9,0x12,0x9a,0x08,0x2e,0xb6,0xc2,0xd2,0x52,0xdd,0xe0,0xfb,0xa9,0x43,0xcb,0x2f,0x68,0x98,0x0f,0x19,0x8f,0x18,0x7f,0x25,0x12,0x70,0xa2,0x03,0x61,0x59,0x83,0xe6,0xb1,0xf1,0x04,0x1c,0x60,0xfc,0x5a,0x68,0x28,0x7c,0xae,0x49,0x50,0xdd,0xdf,0x2c,0x42,0x5b,0xa5,0x36,0x61,0x1a,0xdb,0xe9,0xfe,0x54,0xc1,0xec,0xea,0x1a,0x23,0xc8,0x7d,0x59,0x7f,0x8e,0x07


};
//256 212-13
static const unsigned char RSA_DQ[] = {
	0x7d,0x8b,0xda,0x86,0xf8,0x39,0x47,0x70,0x85,0x81,0xdc,0xa3,0x51,0x5a,0x06,0xaa,0xb1,0x10,0xb2,0x4a,0xd0,0xc3,0x19,0xf2,0x2c,0x9d,0xe5,0xbb,0x61,0xd2,0xa4,0x88,0x25,0x33,0x81,0x32,0x74,0x60,0xe1,0xf8,0x2d,0x0a,0x17,0x28,0xcf,0xf1,0x49,0x27,0x74,0x92,0x68,0x6d,0x20,0xd1,0x9d,0x12,0x85,0x68,0x4c,0xba,0x29,0xd4,0xd0,0x35,0x02,0x04,0x91,0xd2,0x15,0x7a,0x15,0x3c,0x7d,0x35,0x29,0x55,0x69,0x9d,0x74,0x8e,0xb7,0xe9,0x5b,0xd5,0x86,0x54,0xd4,0xd9,0x18,0xb1,0x0f,0x08,0xf4,0xd6,0xa5,0xb1,0xc5,0x68,0x1a,0x51,0x27,0xc1,0x0e,0x60,0xf9,0xf9,0xd2,0x59,0x8e,0x3e,0x37,0x87,0x33,0x5e,0xde,0xa4,0x89,0x2a,0xe1,
0x0f,0xd8,0x6d,0x53,0x6a,0x8d,0x2e,0x81,0x49   


};
//256 214-16
static const unsigned char RSA_IQ[] = {
	0x38,0xfa,0x61,0xb6,0x84,0x6d,0x27,0xf8,0x56,0xe6,0x43,0x89,0xa6,0x3b,0xb6,0xae,0x68,0x45,0xb0,0x79,0x44,0xec,0x6a,0x70,0x35,0xc1,0x97,0x2c,0x75,0xcd,0x68,0x3f,0x2a,0x0c,0xce,0x3e,0x8e,0x42,0x5a,0x89,0xbb,0x42,0x9b,0x10,0x89,0xa6,0x3d,0x3e,0x67,0x71,0x5b,0xe9,0xfc,0xb6,0x2d,0xa2,0x9c,0x56,0xbe,0x65,0x40,0xa3,0x7a,0xea,0xa6,0xf5,0x21,0x88,0x3e,0x40,0xb3,0x4f,0xa4,0x24,0xf4,0xe6,0x23,0xb4,0x1b,0x84,0x78,0x29,0x78,0x98,0x0f,0x89,0x4a,0xac,0x61,0xa0,0xc8,0xbc,0x5e,0xcc,0x8c,0x45,0x9a,0x29,0x82,0x4d,0x46,0xc9,0xe2,0xe6,0x8d,0x04,0xcc,0xc7,0xa8,0x4f,0x48,0xb5,0xcc,0xf7,0x86,0x32,0xdf,0xe2,0x79,
0xd3,0x8b,0x70,0x22,0x94,0x9f,0xcc,0xf1,0xe5


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
int provisionlaz();
static size_t hextobin(unsigned char *dst, const char *src);
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
    /*
    for(int i = 0; i < 128; i++)
    {
        cardnum[i] = 'a';
    }
    CySysFlashWriteRow(150, cardnum); //write num to memory
    db = (uint8_t*) (CY_FLASH_BASE + 150*128); //look to make sure its good
    memcpy(readrow, db, CY_FLASH_SIZEOF_ROW);
    */
    //UART_PutString("Testing ... Testing ...\n\r"); IT WORKS BABYYYYYYYYYYYy
    //writeUART(readrow, (uint8_t) CY_FLASH_SIZEOF_ROW);

    //recieve and write bank sig to mem
    /*
    UART_PutString("Give me the Bank signature\n\r");
    //RSA sign #TODO !MIGHT JUST BE THE PUBLIC KEY COME BACK TO THIS
    banksig = (uint8_t*)&RSA_PK;
    UART_PutString("signature recieved\n\r");
    CySysFlashWriteRow(151, banksig);
    CySysFlashWriteRow(152, banksig+128);
    */
    
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
    char* msg = "0b1e950e6de96a8e07d9cf467eeffafe4de9b27fca52d812b49d79f5a12cc71fa0863b915dbaf77bd3d4b3fbefa9a62563740b88095981a7801507e6dbb6db241a70163547ae7d0363ed94ac256a79c8d49c2771e1799ddaca4624bb303535eb6ee5e034b558d25ff9ecd4830f72aefe9d61657c06c65740af4062f8ab19349fc7ac4d9f7994471a519d743e38dd7b59694ea45ed9ed9fecf53b8e92ab560cd4a37057c8eec89e3a47619aabd05a2798ff42e5f324f0395a9a68f61f33dc3b15abc1a0fde0f6231ff80f3a66f11195df10c281fcc1dfcbd074934d3322d64ee65c0030f9d3a72ac43981ab0820125b3459ad7908e1142834dabaa4a8847f7153";
    RSA_decrypt256(&br_rsa_i31_private, msg,(uint8_t) KEY_SIZE*2 );
     
    //UART_PutString("WRITE SUCCESSFUL\n\r");
    
    //UART_PutString("Card Provisioning finished, dump all memory to double check\n\r");
    //writeUART(dump, (uint8_t) KEY_SIZE*4); //REMEMBER TO GET RID OF THIS SO THEY CAN'T EXPLOIT THIS
    /*
	for(;;)
    {
        char* command[3];
		getValidBytes((uint8_t*) command, 3);
        if(strcmp((char*)command, "cir") == 0)
        {
            pushMessage(cardnum, 32);
        }
        else if(strcmp((char*)command, "cvw") == 0)
        {
            computeVerify(readVerify());
        }
        else if(strcmp((char*)command, "own") == 0)
        {
            computeOnion(readOnion(), privkey);
        }
        else if(strcmp((char*)command, "prv") == 0)
        {
            provisionlaz();
        }
    }
    */

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

int provisionlaz(){
	uint8_t cardNum[32];
	getValidBytes(cardNum, 32);
    /*
	uint8_t outerLayerPrivateKey[256];
	getValidBytes(outerLayerPrivateKey, 256);
	uint8_t innerLayerPublicKey[256];
	getValidBytes(innerLayerPublicKey, 256);
    */
	//TODO: write this shit to memory william
    CySysFlashWriteRow(150, cardNum);
    //The rest of the things done at dec
	return 0;
}

int computeOnion(struct onionPacket pack, uint8_t* privkey){
	//privkey = (uint8_t*) (CY_FLASH_BASE + 153*128);
    privkey = (uint8_t*) &RSA_SK;
   
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
    //unsigned char* tmp = malloc(size*sizeof(unsigned char));
    unsigned char tmp[KEY_SIZE*2];
    unsigned char t1[KEY_SIZE*2];
    unsigned char check[8] = "Fuck off";
    memcpy(tmp, msg, size);
    
    hextobin(t1, (const char*)tmp);
    //decrypt first
    if (!fpriv(t1, &RSA_SK))
    {
		//fprintf(stderr, "RSA private operation failed\n");
        UART_PutString("RSA PRIV OP FAILED\n\r");
		exit(EXIT_FAILURE);
	}
    if(check_equals(t1, check, 8) == 1)
    {
         UART_PutString("Sucess");
    }
    else
    {
        UART_PutString("Failed");
        UART_PutString((const char8*) t1);
    }
    return t1;

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
	int i = check_equals(hv, tmp, sizeof tmp);
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

static size_t hextobin(unsigned char *dst, const char *src)
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
