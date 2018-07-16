int main()
{
    uint32 ch;

    /* Start SCB (UART mode) operation */
    UART_Start();

    UART_UartPutString("\r\n***********************************************************************************\r\n");
    UART_UartPutString("Welcome to the CE95366 example project\r\n");
    UART_UartPutString("If you are able to read this text the terminal connection is configured correctly.\r\n");
    UART_UartPutString("Start typing characters to see an echo in the terminal.\r\n");
    UART_UartPutString("\r\n");

    for (;;)
    {
        /* Get received character or zero if nothing has been received yet */
        ch = UART_UartGetChar();

        if (0u != ch)
        {
            /* Transmit the data through UART.
            * This functions is blocking and waits until there is a place in
            * the buffer.
            */
            UART_UartPutChar(ch);
        }
    }
}
