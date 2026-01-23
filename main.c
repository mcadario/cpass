#include <stdio.h>
#include <stdlib.h>
#include "./headers/cpass.h" 

int main() {
    int choice;

    while(1) {
        printf("\n1. Add Password\n2. View Passwords\n3. Exit\nChoice: ");
        scanf("%d", &choice);

        switch(choice) {
            case 1: save_password(); break;
            case 2: read_passwords(); break;
            case 3: exit(0);
            default: printf("Invalid choice.\n");
        }
    }
    return 0;
}