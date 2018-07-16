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
#include <stdio.h>

int main (void)
{
    CyGlobalIntEnable;      /* Enable global interrupts */
    UART_Start();
    char ch;
    /* Place your initialization/startup code here (e.g. MyInst_Start()) */
    UART_UartPutChar("Enter a character:\n\r");
    for(;;)
    {
        /* Place your application code here */
        
        
        ch = UART_UartGetChar();
        if (0u != ch)
        {
            
            /* Transmit the data through UART.
            * This functions is blocking and waits until there is a place in
            * the buffer.
            */
            UART_UartPutChar(ch);
        }
 
        printf("%d\n", ch);
        
        
    }
}
