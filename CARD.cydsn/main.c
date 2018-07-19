/* ========================================
 *
 * Copyright Onion Labs, 2018
 * All Rights Reserved
 * UNPUBLISHED, LICENSED SOFTWARE.
 *
 * CONFIDENTIAL AND PROPRIETARY INFORMATION
 * WHICH IS THE PROPERTY OF ONION LABS.
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

uint8_t* readUART();
void writeUART(uint8_t* buffer);
void writeMemory(int row, uint8_t* buffer);
uint8_t* readMemory(int row,  int size);
int checkArrays(uint8_t* array1, uint8_t* array2, int size);
uint8_t* readData(uint8_t* buffer);
uint8_t* readSignature(uint8_t* buffer);
uint8_t* readSalt(uint8_t* buffer);

//MAIN TEST CLASS
/*
int main(void)
{
  uint8_t* testKey = malloc(KEY_SIZE*sizof(uint8_t));
  *testKey = (uint8_t)"MIIEpAIBAAKCAQEAoovcZ/Vu6ZdrjQRr/OK4RUIBm/nEX0q+Xqbt7YAjNgJsi6Vn
2Y7NmYMXvGhHuEI86EYNZNP5iNXIRbmtDKGKbvlkoH07JdZ7GBfxyUuuvkeI4yJu
gtux6Me7b4as3tdnq5/hPIeTarjRAQ8ETtFzQAQgWpEf4r4puoFh9wSqbWuzpx04
lkGFJtK7RbE/fNMfOjMMgGaLS6eMc8TjfKeISFMa8Yljl0i7fppckCx/5LbuO9v2
ehiMvdnYd6rqcT4kNnzwnHxZGKOKsc55bhG2HwQyUe9uXynHm00RwByl2t3xUWGg
ZuKFKGC80bCkNWrD049pVKaK+LTkBdIzHm0i2wIDAQABAoIBAQCh5N9fg6o2aiQq
ze6obz/Na1KjAX++0XkOWQC8/lUTpBJsfBAVNhA9B76KXuqf8Qks5yjL9fyhdxwD
pk1fOT3iDe9VkaVpqFftxVuCfCjNR/5lC5Q6LYrjKJvdFqvzP2P4IkN5wCbpsq4o
ecZ2olJBvlpjGgxCD9kL83WZTEJau8ZU/s01Ka6+Ts8/1ul3dzDwnzE8ryV6K4Ow
1axOlYtGFNPyQzmIoaorbwDob+/5pbO1H4GbjRVzN+APQ6VYqqowpyTJY17zYTd9
PJPBVr8Xa5euwk0Z3TtvtPQVKZBrf0vQzumGv+JtziEu8D/VYzD/cBJaWe+l030e
qOy1kMlBAoGBAM2ZsXLMFb5qsrF79CB+e8EIAGWNzc2b6sbiypnfuApafrbkdRug
g/OmmrHiEKcZyMWeoSYSOhijJnw34dJ3T1aLyd+wO/rJt8RjyVcMQddVFt0SSHsO
MpX+SLqqidUDz7WT/6QOr4kGIAmwj89+fZ6EDRc1WwQjKv7BXcGZGoVrAoGBAMpk
V5jwTenD/IfkJf0DL6spJ0Nu34v9j21MSqCxzP7ED4qPZnxMeUvJ8BppBEpFe+hU
nUhzq9dN7HVoZPLfpeQwbplpaEzWSiYFhuAsIm7bNFTO2YU2HWFk+plTQErM0AjF
HSuU4a2+VeHR2EGqy7Szobh3naDcact35w1yacRRAoGAMGQJOOzB/WRdlJqJFhDP
DdrVRRHAK7GT66W7a8YVKhKsml1hFtSL2hAPfuinZL0T3Td91Fkb5WqZB0mb1A6S
1Nrn88cmBtvtbcLSw7M11/nF/NhtyNDJpTYJZi33bPSNsb4YwENYm1aeuckdwAeU
h3erIRhEyM+CMh3O9F8Vt+sCgYBkD6HjQgMzLKsgQCKr6TRbCdiYlSs+WdjcL5jB
w8XWuvX4ChegImrhlm/3jq4JTjsJTTQJiu6NXsAl97vY+8tXer5jaGKhglxcWeUp
1YgciJFh0HZoTq3N5g+jWC50DLhZbaKTVmMQ9AYfxBCHvrpBl4G/4pty2SYQ6zG3
SzaRUQKBgQC3J7YkJajdGm8vqvh6DXozIlSMbxK6220r80jvfF2cQ6VrstbCQTFD
lZ1hbp7NPp8JB4zLUShPqFUV7Rh97veYCsigeOlgCC9QqoaydgIEy6EsTJdTVVnc
L/avHk6Fvp+9bFMuhDTIow2O2HTZZpi6fvRs91Kezt09tIL9U1TytA=="
  writeMemory(0, testKey);

  if(checkArrays(readMemory(0), testKey)
  {
    writeUART((uint8_t*)"Successful read/write of key");
  }else{
    writeUART((uint8_t*)"Unsuccessful read/write of key");
  }
  writeUART((uint8_t*)"Waiting for 3*256 byte input");

  uint8_t* read = readUART();
  writeUART((uint8_t*)"Writing first value");
  writeUART(readData());
  writeUART((uint8_t*)"Writing first value");
  writeUART(readSignature);
  writeUART((uint8_t*)"Writing first value");
  writeUART(readSalt);
  return 0;
}
*/



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
        uint8_t* checkNumE = readUART(3*KEY_SIZE);
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
        uint8_t* onionE = readUART(3*KEY_SIZE);
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

uint8_t* readUART(int bytes){
  uint8_t* result = malloc(bytes*sizeof(uint8_t));
  for(int i = 0; i < bytes;){
    uint8_t rxData = (uint8_t)UART_GetChar();
    if(rxData)
    {
        result[i] = rxData;
    }
  }
  return result;
}

void writeUART(uint8_t* buffer)
{
  for(int i = 0; i < KEY_SIZE; i++)
  {
    UART_PutChar((char)buffer[i]);
  }
}

//TEST TOMORROW
void writeMemory(int row, uint8_t* buffer){
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
uint8_t* readMemory(int row, int size){
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
