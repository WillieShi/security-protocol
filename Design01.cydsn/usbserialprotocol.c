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

#include "usbserialprotocol.h"

#define RECV_OK 0
#define RECV_ER 1
#define RDY_MSG_RECV "READY"
#define RDY_MSG_NORM "CARD_N"
#define RDY_MSG_PROV "CARD_P"
#define RDY_BAD "BAD"
#define GO_MSG "GO"


uint8 getValidByte()
{
    uint8 retval = 0u;
    while(UART_SpiUartGetRxBufferSize() < 1); // wait for byte
    retval = UART_UartGetByte();
    return retval;
}

uint8_t* getValidBytes(int size)
{
    uint8_t retval[size];
    for(int i = 0; i < size; i++){
      while(UART_SpiUartGetRxBufferSize() < 1); // wait for byte
      retval[i] = UART_UartGetByte();
    }
    return retval;
}

struct verificationPacket{
  uint8_t[256] encryptedRandNum;
  uint8_t[256] signature;
}

struct onionPacket{
  uint8_t[512] outerLayer;
  uint8_t[256] signature;
}

verificationPacket readVerify(){
  verificationPacket result;
  result.encryptedRandNum = getValidBytes(256);
  result.signature = getValidBytes(256);
  return result
}

onionPacket readOnion(){
  onionPacket result;
  result.outerLayer = getValidBytes(512);
  result.signature = getValidBytes(256);
  return result
}

int pushMessage(const uint8 data[], uint8 size)
{
    int i;

    UART_UartPutChar(size);

    for (i = 0; i < size; i++) {
        UART_UartPutChar(data[i]);
    }

    return RECV_OK;
}


uint8 pullMessage(uint8 data[])
{
    int i, len;

    len = getValidByte();

    for (i = 0; i < len; i++) {
        data[i] = getValidByte();
    }

   return len;
}

/*
 * generic PSoC synchronization protocol:
 *
 * 1) ATM -> "READY" -> PSoC
 * 2) if bad:  PSoC -> received bad message -> ATM; goto 1)
 *    if good: PSoC -> PSoC name (prov/norm) -> ATM
 * 3) ATM -> "GO" -> PSoC
 * 4) if bad: goto 1)
 */
void syncConnection(int prov)
{
    uint8 message[32];

    // marco-polo with bank until connection is in sync
    do {
        pullMessage(message);                               // 1)

        if (strcmp((char*)message, RDY_MSG_RECV)) {
            pushMessage(message, strlen((char*)message));   // 2) bad
            strcpy((char*)message, RDY_BAD);
        } else if (prov) {
            pushMessage((uint8*)RDY_MSG_PROV,
                        strlen(RDY_MSG_PROV));              // 2) good prov

            pullMessage(message);                           // 3)
        } else {
            pushMessage((uint8*)RDY_MSG_NORM,
                        strlen(RDY_MSG_NORM));              // 2) good norm

            pullMessage(message);                           // 3
        }

    } while (strcmp((char*)message, GO_MSG));               // 4)
}

/* [] END OF FILE */
