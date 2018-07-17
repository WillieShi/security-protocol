//Includes

//Definitions
#define SIGNATURE_SIZE 256;
#define KEY_SIZE 256;
#define SALT_SIZE 256;


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

//Reads the third 256 byte segment of data: salt
static uint8_t* readSalt(uint8_t* buffer){
  uint8_t* result = (uint8_t*)malloc(SALT_SIZE*sizeof(uint8_t));
  for(int i = KEY_SIZE + SIGNATURE_SIZE; i < KEY_SIZE + SIGNATURE_SIZE + SALT_SIZE; i++){
    result[i - KEY_SIZE - SIGNATURE_SIZE] = buffer[i];
  }
  return result;
}

//Reads the second 256 byte segment of data: signature
static uint8_t* readSignature(uint8_t* buffer){
  uint8_t* result = (uint8_t*)malloc(SIGNATURE_SIZE*sizeof(uint8_t));
  for(int i = KEY_SIZE; i < KEY_SIZE + SIGNATURE_SIZE; i++){
    result[i - KEY_SIZE] = buffer[i];
  }
  return result;
}

//Reads the first 256 byte segment of data: contents
static uint8_t* readData(uint8_t* buffer){
  uint8_t* result = (uint8_t*)malloc(KEY_SIZE*sizeof(uint8_t));
  for(int i = 0; i < KEY_SIZE; i++){
    result[i] = buffer[i];
  }
  return result;
}

//Checks arrays against each other: for testing keys
static int checkArrays(uint8_t array1, uint8_t array2){
  for(int i = 0; i < sizeof(array1)/sizeof(uint8_t); i++){
    if(array1[i] != array2[i]){
      return 0;
    }
  }
  return 1;
}


int main() {
  //Read memory and move to RAM
  uint8_t* privKey = readMemory(0);
  uint8_t* bankSig = readMemory(1);
  int* cardNum = (int*)readMemory(2);

  //Send card number to ATM
  writeUART((uint8_t*)"___Sending card number___");
  writeUART((uint8_t*)cardNum);
  writeUART((uint8_t*)"___Sent card number___");

  //Read checknum, decrypt and return with salt to ATM
  uint8_t* checkNumE = readUART();
  writeUART((uint8_t*)"___Received checkNum___");
  checkNumD = readData(rsaDecrypt(checkNumE, privKey));
  uint8_t* candBankSig = readSignature(rsaDecrypt(checkNumE, privKey));
  uint8_t* salt = readSalt(rsaDecrypt(checkNumE, privKey));
  if(checkArrays(candBankSig, bankSig)){
    writeUART(checkNumD);
    writeUART(salt);
    writeUART((uint8_t*)"___Correct signature sent checknum___");
  }else{
    writeUART((uint8_t*)"___Incorrect signature did not send checknum___");
  }



  //Read onion, decrypt, and send back inner layer with salt back to ATM
  uint8_t* onionE = readUART();
  writeUART((uint8_t*)"___Received onion___");
  onionD = readData(rsaDecrypt(onionE, privKey));
  candBankSig = readSignature(rsaDecrypt(onionE, privKey));
  salt = readSalt(rsaDecrypt(onionE, privKey));
  if(checkArrays(candBankSig, bankSig)){
    writeUART(onionD);
    writeUART(salt);
    writeUART((uint8_t*)"___Correct signature sent onion___");
  }else{
    writeUART((uint8_t*)"___Incorrect signature did not send onion___");

  }
  return 0;
}
