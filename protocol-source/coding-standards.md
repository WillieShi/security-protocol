Data standards
================

# Communication

### UART transaction items
Item 0: ___ Beginning of transaction message ___ (String)

Item 1: 2 byte data (uint8_t)

Item 2: 256 byte signature (uint8_t)

Item 3: 256 byte salt (uint8_t)

Item 4: ___ End of transaction message ___ (String)

### Card commands
cir: (32 bytes of string) send the card number to the atm pls (as 32 bytes por favor)

cvw: im gonna send you the encrypted verification number thing (256 bytes ofnumber and 256 bytes of signature and then 32 bytes of transaction id)
pls return a 32 bytes number as a result

own: im gonna send you the onion as 512 bytes of data, then 256 bytes of signature, then 32 bytes of transaction id.  pls respond w 256 bytes of inner layer

### Method descriptions

###### writeUART
Instantly writes buffer data to standard pins

###### readUART
Hangs program until receiving data, returns as uint8_t*

# Storage

### Data item sizes
RSA keys: 256 bytes

Signatures: 256 bytes

Salts: 256 bytes

### Storage standards
1 256 byte variable per row

### Card storage layout
Row 0: Card number

Row 1: Bank signature (Bank's Public Key)

Row 2: Private Key

### Method descriptions

######readMemory
Reads from flash over standard pins, outputs 256 byte uint8_t array

######writeMemory
Writes to flash over standard pins using data from buffer
