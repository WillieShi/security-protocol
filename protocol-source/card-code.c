//Includes

//Function definitions
static uint8_t* rsaEncrypt(uint8_t* buffer, uint8_t* key){

}

static uint8_t* rsaDecrypt(uint8_t* buffer, uint8_t* key){

}

static void writeMemory(int row){

}

static uint8_t* readMemory(int row){

}

static void writeUART(uint8_t* buffer){

}

static uint8_t* readUART(){

}
/*
  Data structure
  Row 0: Private Key
  Row 1: Card signature
  Row 2: Bank signature
  Row 3: Card number
*/

//Main
int main() {
  uint8_t*
  uint8_t* privKey = readMemory(0);
  uint8_t* cardSig = readMemory(1);
  uint8_t* bankSig = readMemory(2);
  int* cardNum = (int*)readMemory(3);

  writeUART((uint8_t*)"Sending card number");
  writeUART((uint8_t*)cardNum);
  writeUART((uint8_t*)"Send card number");

  uint8_t* checkNum = readUART();
  writeUART(rsaDecrypt(checkNum, privKey));

  uint8_t* onion = readUART();
  writeUART(rsaDecrypt(onion, privKey));


  return 0;
}
