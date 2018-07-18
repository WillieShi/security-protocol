Data standards
================

# Communication

### UART transaction items
Item 0: ___ Beginning of transaction message ___ (String)

Item 1: 256 byte data (uint8_t)

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

Fancy number 0: 64 bytes

Fancy number 1: 64 bytes

Fancy number 2: 64 bytes

Fancy number 3: 64 bytes

### Storage standards
1 256 byte variable per 2 rows

### Card storage layout
Row 0: Private Key

Row 2: Bank signature

Row 4: Card number

Row 6:

### Method descriptions

######readMemory
Reads from flash over standard pins, outputs 256 byte uint8_t array

######writeMemory
Writes to flash over standard pins using data from buffer
