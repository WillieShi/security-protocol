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
#define RSAP ((uint8_t*)(CY_FLASH_BASE + 200))
#define WriteRSAP(p) (200, p);
#define RSAQ ((uint8_t*)(CY_FLASH_BASE + 201))
#define WriteRSAQ(a) (201, a);
#define RSADP ((uint8_t*)(CY_FLASH_BASE + 202))
#define WriteRSADP(b) (202, b);
#define RSADQ ((uint8_t*)(CY_FLASH_BASE + 203))
#define WriteRSADQ(c) (203, c);
#define RSAIQ ((uint8_t*)(CY_FLASH_BASE + 204))
#define WriteRSAIQ(d) (204, d);
#define RSAN ((uint8_t*)(CY_FLASH_BASE + 205))
#define WriteRSAN(e) (205, e);
#define RSAE ((uint8_t*)(CY_FLASH_BASE + 207))
#define WriteRSAE(f) (207, f);

static br_rsa_public_key RSA_PK = {
	(void *)RSAN, 256,
	(void *)RSAE, 3
};

static br_rsa_private_key RSA_SK = {
	2048,
	(void *)RSAP, 128,
	(void *)RSAQ, 128,
	(void *)RSADP, 128,
	(void *)RSADQ, 128,
	(void *)RSAIQ, 128
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
    uint8_t p[128];
    getValidBytes(p, 128);
    WriteRSAP(p);

    uint8_t q[128];
    getValidBytes(q, 128);
    WriteRSAQ(q);

    uint8_t dp[128];
    getValidBytes(dp, 128);
    WriteRSADP(dp);

    uint8_t dq[128];
    getValidBytes(dq, 128);
    WriteRSADQ(dq);

    uint8_t inq[128];
    getValidBytes(inq, 128);
    WriteRSAIQ(inq);

    uint8_t N[256];
    getValidBytes(N, 256);
    WriteRSAN(N);

    uint8_t E[3];
    getValidBytes(E, 128);
    WriteRSAE(E);


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
