#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "./headers/cpass.h" 

int main(int argc, char* argv[]) {

    // printf("%d", argc);
    
    //printf("\n1. Add Password\n2. View Passwords\n3. Exit\nChoice: ");
    //scanf("%d", &choice);
    if(argc < 2) {
        printf("Commands:\n - add\n - list\n");
        return 0;
    }

    if (strcmp(argv[1], "add")==0){
        if (argc < 5) {
            printf("Usage: %s add <site> <username> <password>\n", argv[0]);
            return 1;
        }
        save_password(argv[2], argv[3], argv[4]);
    } else if (strcmp(argv[1], "list")==0) {
        read_passwords();
    }    

    return 0;
}