# Project Description
This project is compiled into a module to use the extended header to implement encryption of the source IPv6 address of the data packet, and encryption and decryption will be performed on each hop of the transmission path

At the same time, the data packet will be transmitted according to the specified encryption path

## Project Structure
* alp: includes definitions related to the extended header and the specific implementation of adding the extended header to the data packet
* hook_in: Processing received data packets
* hook_out: Processing data packets to be sent
* control: Control module, including maintenance of hash tables and their own secret values
* tools: Tool module, including XOR, MAC operations (Message Authentication Code)

## Dependencies
``` Shell
sudo apt install linux-headers-$(uname -r) libcurl4-openssl-dev
```

## Deployment Instructions
Execute in the following order:

Compile the project: `make all`
Insert kernel module: `sudo insmod alp.ko`

## Test Instructions
The following files need to be modified according to the test environment:
Path information, previous hop routing identifier, next hop mac address, etc. in `hash_map.c`
Fake device information inserted in `local_out.c`