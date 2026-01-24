#ifndef CPASS_H //avoid double-pasting of this header file
#define CPASS_H

#define FILENAME "passwords.bin" //define file path
#define KEY 0xF //weak key for XOR

typedef struct {
    char site[50];
    char usr[50];
    char pwd[50];
} Credential;

// prototypes
void print_usage(char *cmd);
void toggle_xor(char *str);
void save_pwd(char *site, char *usr, char *pwd);
void read_pwd();
int count_pwd();
void find_pwd(char *site);

void print_usage(char *cmd){
    if (strcmp(cmd, "add")==0)
        printf("Usage: cpass add <site> <username> <password>\n");
    else if (strcmp(cmd, "list")==0)
        printf("Usage: cpass list [no parameters[] \n");
    else if (strcmp(cmd, "find")==0)
        printf("Usage: cpass find <site> \n");
    else {
        printf("Command not found! \n -- COMMANDS --\n");
        print_usage("add");
        print_usage("list");
        print_usage("find");
    }
}

/* TO BE IMPLEMENTED:
    - stronger encryption
    DONE - search password with algv[0] = "find"
    DONE - support for special char
    - delete, if more than one pwd then display a menu (1.usr1 \n 2.usr2, ...)
    
    - Makefile installation

*/

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
void save_pwd(char *s, char *u, char *p) {

    size_t len = strlen(p);
    if (len <= 2 && p[0] != '\'' && p[len - 1] != '\'') {
        printf("Wrap your assword in single quotes.!\n");
        return;
    }

    Credential c;
    FILE *file = fopen(FILENAME, "ab");

    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }

    // write in the file as a struct Credential instance
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

int count_pwd() {
    FILE *file = fopen("passwords.bin", "rb");
    if (file == NULL) return 0;

    fseek(file, 0, SEEK_END); // move to the end, SEEK_END is defined in stdio.h
    long total_bytes = ftell(file); // get position in bytes
    int count = total_bytes / sizeof(Credential);

    fclose(file);
    return count;
}

// reading pwds
void read_pwd() {
    Credential c;
    FILE *file = fopen(FILENAME, "rb");

    if (file == NULL) {
        printf("No passwords found yet.\n");
        return;
    }

    if (count_pwd()==0){
        printf("No password in the file.");
        fclose(file);
        return;
    }

    printf("\n--- SAVED PASSWORDS ---\n");
    while (fread(&c /* assign output to our temp var */, sizeof(Credential), 1, file)) {
        toggle_xor(c.pwd);
        printf("Site: %s | User: %s | Pass: %s\n", c.site, c.usr, c.pwd);
    }
    printf("-----------------------\n");
    fclose(file);
}

void find_pwd(char *site){
    Credential c;
    FILE *file = fopen(FILENAME, "rb");
    int count_found = 0;
    Credential *found = NULL; //null ponter that will be reasinged with realloc

    if (file == NULL) {
        printf("No passwords found yet.\n");
        return;
    }

    
    while (fread(&c /* assign output to our temp var */, sizeof(Credential), 1, file)) {
        if (strcmp(c.site, site) == 0){
            Credential *temp = realloc(found, ++count_found*sizeof(Credential)); // resizing found array
            if (temp==NULL){
                free(found);
                fclose(file);
                return;
            }
            found = temp;
            found[count_found-1] = c;
        }
        
    }

    if (count_found>0) printf("\n--- RESULTS FOR %s ---\n", site);
    else printf("No passwords for %s\n", site);

    for (int i = 0; i < count_found; i++){ //outside condition because if count_found is 0 the for is not executed
        toggle_xor(found[i].pwd);
        printf("Site: %s | User: %s | Pass: %s\n", found[i].site, found[i].usr, found[i].pwd);
    }

    fclose(file);
    free(found);
}

#endif
