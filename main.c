#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "./headers/cpass.h" 

int main(int argc, char* argv[]) {

    // printf("%d", argc);
    
    //printf("\n1. Add Password\n2. View Passwords\n3. Exit\nChoice: ");
    //scanf("%d", &choice);
    if(argc < 2) {
        printf("Commands:\n - add\n - list\n - find\n");
        return 0;
    }

    if (strcmp(argv[1], "add")==0){
        if (argc != 5) {
            print_usage(argv[1]);
            return 1;
        }      
        save_pwd(argv[2], argv[3], argv[4]);
    } else if (strcmp(argv[1], "list")==0) {
        if (argc != 2) {
            print_usage(argv[1]);
            return 1;
        }   
        read_pwd();
    } else if (strcmp(argv[1], "find")==0) {
        if (argc != 3){
            print_usage(argv[1]);
            return 1;
        }
        find_pwd(argv[2]);
    } else {
        print_usage(""); //call it with empty str so that it will fall in the else case
    }

    return 0;
}