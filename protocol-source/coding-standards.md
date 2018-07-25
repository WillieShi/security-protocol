Data standards
================

# Communication

### UART transaction items
Item 0: ___ Beginning of transaction message ___ (String)

Item 1: 2 byte data (uint8_t)

Item 2: 256 byte signature (uint8_t)

Item 3: 256 byte salt (uint8_t)

Item 4: ___ End of transaction message ___ (String)

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
