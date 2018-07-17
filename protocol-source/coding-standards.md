---
layout: post
title:  "Coding Standards"
date:   2018-07-17 21:20:49 -0400
---

# Communication

### UART transaction items
Item 0: ___ Beginning of transaction message ___ (String)
Item 1: 128 byte data (uint8_t)
Item 2: 128 byte signature (uint8_t)
Item 3: ___ End of transaction message ___ (String)

### Method descriptions

###### writeUART
Instantly writes buffer data to standard pins

###### readUART
Hangs program until receiving data, returns as uint8_t*

# Storage

### Data item sizes
RSA keys: 128 bytes
Signatures: 128 bytes

### Storage standards
1 128 byte variable per row

### Card storage layout
Row 0: Private Key
Row 1: Bank signature
Row 2: Card number

### Method descriptions

######readMemory
Reads from flash over standard pins, outputs 256 byte uint8_t array

######writeMemory
Writes to flash over standard pins using data from buffer
