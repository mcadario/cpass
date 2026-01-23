#ifndef CPASS_H //avoid double-pasting
#define CPASS_H

#define FILENAME "passwords.bin" //define file path
#define KEY 0xF //weak key for XOR

typedef struct {
    char site[50];
    char usr[50];
    char pwd[50];
} Credential;

// prototypes
void toggle_xor(char *str);
void save_password(char *site, char *usr, char *pwd);
void read_passwords();

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ecrypt / decrypt
void toggle_xor(char *str) {
    for (int i = 0; i < strlen(str); i++) {
        str[i] = str[i] ^ KEY;
    }
}

// saving pwd
void save_password(char *s, char *u, char *p) {
    Credential c;
    FILE *file = fopen(FILENAME, "ab");

    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }

    strncpy(c.site, s, sizeof(c.site) - 1);
    strncpy(c.usr, u, sizeof(c.usr) - 1);
    strncpy(c.pwd, p, sizeof(c.pwd) - 1);

    /*
    printf("Enter Website: ");
    scanf("%s", c.site);
    printf("Enter Username: ");
    scanf("%s", c.usr);
    printf("Enter Password: ");
    scanf("%s", c.pwd);
    */

    toggle_xor(c.pwd);

    fwrite(&c, sizeof(Credential), 1, file);
    fclose(file);
    printf("Password saved successfully!\n");
}

// reading pwds
void read_passwords() {
    Credential c;
    FILE *file = fopen(FILENAME, "rb");

    if (file == NULL) {
        printf("No passwords found yet.\n");
        return;
    }

    printf("\n--- SAVED PASSWORDS ---\n");
    while (fread(&c, sizeof(Credential), 1, file)) {
        toggle_xor(c.pwd);
        printf("Site: %s | User: %s | Pass: %s\n", c.site, c.usr, c.pwd);
    }
    printf("-----------------------\n");
    fclose(file);
}


#endif
