// Allocate 1 row of flash... make it aligned to the row size
// and initializde it with 0's
// the const keeps it in the flash (not in the data segment)
const uint8_t row[CY_FLASH_SIZEOF_ROW] CY_ALIGN(CY_FLASH_SIZEOF_ROW) = {0};

void dump(uint8_t *array, int size)
{
    int i,j;
    j=0;
    for(i=0;i<size;i++)
    {
        dbgprintf("%2X ",array[i]);
        j=j+1;
        if(j==16) // 16 values per line
        {
            j = 0;
            dbgprintf("\n");
        }
    }
    UART_UartPutString("\n");
}

int main(){
    uint8_t data[CY_FLASH_SIZEOF_ROW];
    int rowNum;
    // calculate which row in the flash that the "row" array resides
    rowNum = ((int)row - CY_FLASH_BASE) / CY_FLASH_SIZEOF_ROW;
    for(;;){
      char c;
      c = UART_UartGetChar();
      switch(c)
      {
          case 'f':
              UART_UartPutString("Dumping Flash\n");
              dump((uint8_t *)row,CY_FLASH_SIZEOF_ROW);
              break;
          case 'r':
              UART_UartPutString("Reading Flash into RAM\n");
              memcpy(data,row,(int)CY_FLASH_SIZEOF_ROW);
          break;

          case 'i':
              UART_UartPutString("Incrementing RAM Array\n");
              data[0] = data[0] + 1;
              for(i=1;i<(int)CY_FLASH_SIZEOF_ROW;i++)
              {
                  data[i] = data[i-1]+1;
              }
          break;
          case 'R':
              dbgprintf("Dumping RAM Array\n");
              dump(data,CY_FLASH_SIZEOF_ROW);
          break;

          case 'q':
              dbgprintf("Row Number = %d\n",rowNum);
              dbgprintf("RowSize = %d\n",CY_FLASH_SIZEOF_ROW);
              dbgprintf("Flash Address = %X\n",CY_FLASH_BASE);
              dbgprintf("Row Address = %X\n",(unsigned int)row);
              dbgprintf("Data Address = %X\n",(unsigned int)data);

          break;
          case 'w':
              dbgprintf("Writing Flash from RAM Buffer\n");
              rval = CySysFlashWriteRow(rowNum,data);
              if(rval == CY_SYS_FLASH_SUCCESS )
              {
                  dbgprintf("Flash Write Sucess\n");
              }
              else if (rval == CY_SYS_FLASH_INVALID_ADDR)
              {
                  dbgprintf("Flash Write Failed: Invalid Address\n");
              }
              else if (rval == CY_SYS_FLASH_PROTECTED)
              {
                  dbgprintf("Flash Write Failed: Flash Protected\n");
              }
              else {
                  dbgprintf("Flash Write Failed: Unknown\n");
              }
          break;
}
