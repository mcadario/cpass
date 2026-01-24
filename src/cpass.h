#ifndef CPASS_H //avoid double-pasting of this header file
#define CPASS_H

//the following constants are used in cpass.c, they are declared here for general order
#define FILENAME "passwords.bin" //path of password file
#define KEY 0xF //weak key for XOR
#define MASTER_FILE "master.key" //path of master key file
#define SALT_SIZE 16
#define HASH_SIZE 32
#define HEX_HASH_SIZE (HASH_SIZE * 2) + 1 // 64 chars + null terminator

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef struct {
    char site[50];
    char usr[50];
    char pwd[50];
} Credential;

// prototypes

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
Little helper function used to count the number of pwd in the file.
Count the number of bytes by subtracting ftell(file) (at this stage file is the pointer to the first element in the file)
to fseek(SEEK_END), then divides by sizeof(Credential) to get the number of entries.
Is used in read_pwd and find_pwd
------------------------*/

void read_pwd();
/*
read_pwd
Simply prints password while the eof.
------------------------*/

void find_pwd(char *site);
/*
find_pwd
Finds all the stored passwords of the input site.
It is a simple while cycle that prints password till eof.
------------------------*/

bool master_auth(); 
/*
master_auth
Function to hash the master key if it is being created,
or to compare to hashed stored if the master.key file already there.
Uses argon2 Monocypher implementation: https://github.com/LoupVaillant/Monocypher.git
(did not copy the whole repo but just monocypher.c and monocypher.h in /src)
------------------------*/

/* TO BE IMPLEMENTED:
    - stronger encryption with AES instead of xor
    DONE - search password with algv[0] = "find"
    DONE - support for special char
    - <delete> command, if more than one pwd then display a menu (1.usr1 \n 2.usr2, ...)
    DONE - master password when listing/finding with bcrypt
    - Makefile installation

*/

#endif
