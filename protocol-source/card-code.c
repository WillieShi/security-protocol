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
#include "mbedtls\rsa.h"

#include <stdlib.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define SIGNATURE_SIZE 25
#define KEY_SIZE 256
#define SALT_SIZE 256
#define ENCRYPTION_NUMBER_SIZE 64;


const uint8_t row[CY_FLASH_SIZEOF_ROW] CY_ALIGN(CY_FLASH_SIZEOF_ROW) = {0};

static uint8_t* readUART();
static void writeUART(uint8_t* buffer);
static void writeMemory(int row, uint8_t* buffer);
static uint8_t* readMemory(int row,  int size);
int checkArrays(uint8_t* array1, uint8_t* array2, int size);
uint8_t* readData(uint8_t* buffer);
uint8_t* readSignature(uint8_t* buffer);
uint8_t* readSalt(uint8_t* buffer);

int main(void)
{
    CyGlobalIntEnable; /* Enable global interrupts. */
    uint32_t vc_length;
    uint32_t hashlength;
    uint8_t vcbuf[vc_length];
    uint8_t* pubbuf;
    uint8_t rdata[CY_FLASH_SIZEOF_ROW];

    uint8_t* privKey = readMemory(0, KEY_SIZE);
    uint8_t* bankSig = readMemory(2, SIGNATURE_SIZE);
    int* cardNum = (int*)readMemory(4, KEY_SIZE);

    //rsa BSVARIABLES
    mbedtls_rsa_context rsa;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    int return_val;

    UART_Start();
    /* Place your initialization/startup code here (e.g. MyInst_Start()) */

    for(;;)
    {
        /* Place your application code here. */
        //UART_PutString("Test String \n");
        //TODO Card checking ATM identity
        //code for sending hash
        writeUART((uint8_t*)"___Sending card number___");
        writeUART((uint8_t*)cardNum);
        writeUART((uint8_t*)"___Sent card number___");




        //Read checknum, decrypt and return with salt to ATM
        uint8_t* checkNumE = readUART();
        writeUART((uint8_t*)"___Received checkNum___");
        uint8_t* checkNumD = readData(rsaDecrypt(checkNumE, privKey));
        uint8_t* candBankSig = readSignature(rsaDecrypt(checkNumE, privKey));
        uint8_t* salt = readSalt(rsaDecrypt(checkNumE, privKey));
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
        uint8_t* onionD = readData(rsaDecrypt(onionE, privKey));
        candBankSig = readSignature(rsaDecrypt(onionE, privKey));
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





/* [] END OF FILE */
