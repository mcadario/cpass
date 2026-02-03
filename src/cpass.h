#ifndef CPASS_H //avoid double-pasting of this header file
#define CPASS_H

//the following constants are used in cpass.c, they are declared here for general order
#define FILENAME "passwords.bin" //path of password file
#define KEY 0xF //weak key for XOR, kept for legacy toggle_xor1
#define MASTER_FILE "master.key" //path of master key file
#define ENC_SALT_SIZE 16
#define SALT_SIZE 16
#define HASH_SIZE 32
#define HEX_HASH_SIZE (HASH_SIZE * 2)// 64 chars
#define HEX_HASH_BUFFER (HEX_HASH_SIZE) +1 // 65 with null terminator


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

typedef struct {
    bool del; // true if deleted, tombstoning
    char site[50];
    char usr[50];

    //aes requirements
    uint8_t pwd[64];
    uint8_t iv[16];
    uint8_t len;

} Credential;

// prototypes

void cleanup_session();

void print_usage(char *cmd);
/*
print_usage()
Helps with printing guidance for the user, prints usage instruction based on the command you pass (add, list, find).
Can be used to print usage for all the commands if the command in none of add, list or find (e.g print_usage("")).
------------------------*/

void toggle_xor(char *str);
/*
toggle_xor
simple encryption for password (NOT MASTER PWD), in later version will
be discontuinued as it is weak :)
------------------------*/

void save_pwd(char *site, char *usr, char *pwd);
/*
save_pwd
Saves password. site, usr and pwd are parameters of the add command in this order.
Passwords are saved in a file "passwords.bin" as a struct of type Credential.
------------------------*/

int count_pwd();
/*
count_pwd
counts with a for cycle the number of pwds,
filters out pwds with c.del true
------------------------*/

int count_pwd_all();
/*
count_pwd_all
Little helper function used to count the number of pwd in the file.
Count the number of bytes by subtracting ftell(file) (at this stage file is the pointer to the first element in the file)
to fseek(SEEK_END), then divides by sizeof(Credential) to get the number of entries.
COUNTS ALSO DELETE PWDS as it doesn't check c.del
------------------------*/

void read_pwd(bool check_del);
/*
read_pwd
Simply prints password while the eof.

if check_del is true the function prints only deleted ones and returns the number of deletd
------------------------*/

int find_pwd(char *site, bool verbose, bool check_del);
/*
find_pwd
Finds all the stored passwords of the input site.
It is a simple while cycle that prints password till eof.

if verbose is false, it doesnt print anything and just return the number of found pwds, 
otherwise prints and returns

if check_del is true the function prints only deleted ones and returns the number of deletd
------------------------*/

void del_pwd(char *site);

bool master_auth(); 
/*
master_auth
Function to hash the master key if it is being created,
or to compare to hashed stored if the master.key file already there.
>> Uses argon2 Monocypher implementation: https://github.com/LoupVaillant/Monocypher.git
(did not copy the whole repo but just monocypher.c and monocypher.h in /src)
------------------------*/

void generate_iv(uint8_t *iv);
/*
generate_iv
Helper function to generate random iv for aes
------------------------*/

void trim(char *str);
void encrypt_entry(Credential *c, char *plain_text);
void decrypt_entry(Credential *c, char *output_buffer);
/*
encrypt_entry
decrypt_entry
uses argon2 with hardcoded static salt to generate the aes key
the key is saved in SESSION_KEY that exists only in RAM, once the program exit it is not stored
>> Uses tiny-AES-c: https://github.com/kokke/tiny-AES-c.git
(did not copy the whole repo but just aes.c and aes.h)
------------------------*/

#endif // CPASS_H
