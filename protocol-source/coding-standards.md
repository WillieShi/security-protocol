Data standards
================

# Communication

### UART transaction items

Item 1: 256 byte verification code (uint8_t)

Item 2: 256 byte signature (uint8_t)

break; end of verification step onto actual protcol

Item 3 : 512 byte data (uint8_t)

Item 4: 256 byte salt (uint8_t)

Item 6: 256 byte signature

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

Row 2: Private Key (If have time sign )


### Method descriptions

######readMemory
Reads from flash over standard pins, outputs 256 byte uint8_t array

######writeMemory
Writes to flash over standard pins using data from buffer
