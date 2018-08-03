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
#include <project.h>
#include <stdlib.h>
#include <strong-arm/aes.h>
#include "aes256_tables.h"
#include "usbserialprotocol.h"
#include <strong-arm/sha256.h>

#define SIGNATURE_SIZE 256
#define KEY_SIZE 256



const uint8_t row[CY_FLASH_SIZEOF_ROW] CY_ALIGN(CY_FLASH_SIZEOF_ROW) = {0};

<<<<<<< HEAD
//Memory Row Constants
=======
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
#define AESrow 150
#define ivrow 151
#define cardrow 152
#define passrow 153

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

void getValidBytes(uint8_t* buffer, int n);
int provisionlaz();
void mark_provisioned();
void provision();
void init();
int aesdec(uint8_t* balance, uint8_t* iv);
void req();
void loadmem(int row, int size, uint8* buf);

int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    UART_Start();
<<<<<<< HEAD


=======
    
   
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
    uint8_t balance[16];
    uint8_t iv[16];
    //loop over and await commands from overlord
    for(;;)
    {
<<<<<<< HEAD
        syncConnection(SYNC_NORM);
        char* command[3];
		    getValidBytes((uint8_t*) command, 3);
=======
        char* command[3];
		getValidBytes((uint8_t*) command, 3);
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
        if(strcmp((char*)command, "req") == 0)
        {
            req();
        }
        else if(strcmp((char*)command, "key") == 0)
        {
            getValidBytes(balance, 16);
            getValidBytes(iv, 16);
            aesdec(balance, iv);
        }
        else if(strcmp((char*)command, "prv") == 0)
        {
            provisionlaz();
        }
    }
<<<<<<< HEAD

=======
    
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
}

void req()
{
    uint8_t cardnum[16];
    uint8_t pass[16];
    uint8_t aes[32];
    uint8_t iv[16];
    uint8_t hashpass[32];
    uint8_t bigboi[48];
    uint8_t cipherhp[32];
<<<<<<< HEAD

=======
    
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
    //load aes,iv, cardnum, pass
    loadmem(AESrow, 32, aes);
    loadmem(ivrow, 16, iv);
    loadmem(cardrow, 16, cardnum);
    loadmem(passrow, 16, pass);
<<<<<<< HEAD

    //hash pass out:32
    SHA256(hashpass, pass, 16);

    //encrpyt pass out:32
    aes256_crypt_ctr(cipherhp, aes, iv, hashpass, 32);

    //put it all into one boi
    memcpy(bigboi, cardnum, 16);
    memcpy(bigboi+16, cipherhp, 32);

=======
    
    //hash pass out:32
    SHA256(hashpass, pass, 16);
    
    //encrpyt pass out:32
    aes256_crypt_ctr(cipherhp, aes, iv, hashpass, 32);
    
    //put it all into one boi
    memcpy(bigboi, cardnum, 16);
    memcpy(bigboi+16, cipherhp, 32);
    
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
    //send the boi
    pushMessage(bigboi, 48);
}

void loadmem(int row, int size, uint8* buf)
{
    for(int i = 0; i < size; i++)
    {
<<<<<<< HEAD
        buf[i] = *((uint8_t*)CY_FLASH_BASE + (row*128) + i);
=======
        buf[i] = CY_FLASH_BASE + (row*128) + i;
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
    }
}

int provisionlaz(){
<<<<<<< HEAD

=======
    
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
    //write aes to flash
    uint8_t aeskey[32];
    getValidBytes(aeskey, 32);
    CySysFlashWriteRow(AESrow, aeskey);
<<<<<<< HEAD

=======
    
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
    //write iv to flash
    uint8_t iv[16];
    getValidBytes(iv, 16);
    CySysFlashWriteRow(ivrow, iv);
<<<<<<< HEAD

    //write cardNum to flash
    uint8_t cardNum[16];
	  getValidBytes(cardNum, 32);
    CySysFlashWriteRow(cardrow, cardNum);

=======
    
    //write cardNum to flash
    uint8_t cardNum[16];
	getValidBytes(cardNum, 32);
    CySysFlashWriteRow(cardrow, cardNum);
    
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
    //write pass to flash
    uint8_t pass[16];
    getValidBytes(pass, 16);
    CySysFlashWriteRow(passrow, pass);

    return 0;
}

<<<<<<< HEAD
=======
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


>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
void getValidBytes(uint8_t* buffer, int size)
{
    for(int i = 0; i < size; i++){
      while(UART_GetRxBufferSize() < 1); // wait for byte
      buffer[i] = UART_GetByte();
    }
}

int aesdec(uint8_t* balancesent, uint8_t* ivsent)
{
    uint8_t aes[32];
    uint8_t hashaes[32];
    uint8_t aesplusbalance[48];
    uint8_t iv[16];
    uint8_t pt[16];
    uint8_t balance[16];
<<<<<<< HEAD

    //load aes key from flash
    loadmem(AESrow, 32, aes);

    //load iv and load balance
    loadmem(ivrow, 32, iv);
    memcpy(balance, balancesent, 16);

    //decrypt balance
    aes256_crypt_ctr(balance,aes, iv, pt ,16);

=======
     
    //load aes key from flash
    loadmem(AESrow, 32, aes);
    
    //load iv and load balance
    loadmem(ivrow, 32, iv);
    memcpy(balance, balancesent, 16);
    
    //decrypt balance
    aes256_crypt_ctr(balance,aes, iv, pt ,16);
    
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
    //hash old key + balance
    memcpy(aesplusbalance, aes, 32);
    memcpy(aesplusbalance+32, balance, 16);
    SHA256(hashaes, aesplusbalance, 48);
<<<<<<< HEAD

    //store new aes key and iv to flash
    CySysFlashWriteRow(AESrow, hashaes);
    CySysFlashWriteRow(ivrow, ivsent);

=======
    
    //store new aes key and iv to flash
    CySysFlashWriteRow(AESrow, hashaes);
    CySysFlashWriteRow(ivrow, ivsent);
    
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
    return 0;
}
