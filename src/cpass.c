#include "cpass.h"
#include "../lib/monocypher.h"

// implementations of cpass.h

void print_usage(char *cmd){
    if (strcmp(cmd, "add")==0)
        printf("Usage: cpass add <site> <username> <password>\n");
    else if (strcmp(cmd, "list")==0)
        printf("Usage: cpass list [no parameters[] \n");
    else if (strcmp(cmd, "find")==0)
        printf("Usage: cpass find <site> \n");
    else {
        printf("\n -- COMMANDS --\n");
        print_usage("add");
        print_usage("list");
        print_usage("find");
    }
}

// ecrypt / decrypt DISMISSED
void toggle_xor(char *str) {
    for (int i = 0; i < strlen(str); i++) {
        str[i] = str[i] ^ KEY;
    }
}

// saving pwd
void save_pwd(char *s, char *u, char *p) {

    size_t len = strlen(p);
    if (len <= 2 || p[0] != '\'' || p[len - 1] != '\'') {
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
    if(!master_auth()) return; // authentication

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

    printf("\n--- SAVED PASSWORDS (%d) ---\n", count_pwd());
    while (fread(&c /* assign output to our temp var */, sizeof(Credential), 1, file)) {
        toggle_xor(c.pwd);
        printf("Site: %s | User: %s | Pass: %s\n", c.site, c.usr, c.pwd);
    }
    printf("-----------------------\n");
    fclose(file);
}

/*
THE FOLLOWING FUNCTION IS DISCONTINUED AS IT WAS
HEAVY ON RAM AND OS CALLS, 

it was mainly done for educational purposes

*/

/*
void find_pwd(char *site){
    if(!master_auth()) return; // authentiction

    Credential c;
    FILE *file = fopen(FILENAME, "rb");
    int count_found = 0;
    Credential *found = NULL; //null ponter that will be reasinged with realloc

    if (file == NULL) {
        printf("No passwords found yet.\n");
        return;
    }

    
    while (fread(&c, sizeof(Credential), 1, file)) {
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

    if (count_found>0) printf("\n--- RESULTS FOR %s (%d) ---\n", site, count_found);
    else printf("No passwords for %s\n", site);

    for (int i = 0; i < count_found; i++){ //outside condition because if count_found is 0 the for is not executed
        toggle_xor(found[i].pwd);
        printf("Site: %s | User: %s | Pass: %s\n", found[i].site, found[i].usr, found[i].pwd);
    }

    fclose(file);
    free(found);
}
*/

void find_pwd(char *site) {
    if (!master_auth()) return; 

    FILE *file = fopen(FILENAME, "rb");
    if (file == NULL) {
        printf("No passwords found yet.\n");
        return;
    }

    Credential c;
    int count_found = 0;


    while (fread(&c, sizeof(Credential), 1, file)) {
        if (strcmp(c.site, site) == 0) {
            count_found++;
            if (count_found==1) printf("\n--- RESULTS FOR %s ---\n", site);
            toggle_xor(c.pwd); 
            printf("Site: %s | User: %s | Pass: %s\n", c.site, c.usr, c.pwd);
        }
    }

    if (count_found == 0) {
        printf("No passwords found for %s\n", site);
    } else {
        printf("Total found: %d\n", count_found);
    }

    fclose(file);
}

// convert to hex string
void to_hex(uint8_t *bytes, char *hex_str, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';
}

// hash with argon2, output will be in output_hex
void compute_argon2(char *password, uint8_t *salt, char *output_hex) {
    uint8_t hash[HASH_SIZE];
    
    // allocate work area
    void *work_area = malloc(1024 * 1024);
    if (work_area == NULL) {
        printf("CRITICAL ERROR: Out of memory.\n");
        exit(1);
    }

    //prepare configuration
    crypto_argon2_config config = {
        .algorithm = CRYPTO_ARGON2_I, 
        .nb_blocks = 1024,            
        .nb_passes = 3,               
        .nb_lanes  = 1                
    };

    crypto_argon2_inputs inputs = {
        .pass      = (uint8_t *)password,
        .pass_size = (uint32_t)strlen(password),
        .salt      = salt,
        .salt_size = 16
    };

    crypto_argon2_extras extras = {0}; // No extra data/keys needed

    // actually compute argon2
    crypto_argon2(hash, HASH_SIZE, work_area, config, inputs, extras);

    free(work_area);
    
    // convert to hex and store in output_key
    to_hex(hash, output_hex, HASH_SIZE);
}

void trim(char *str) {
    str[strcspn(str, "\n")] = 0;
}

//uses argon2
bool master_auth() {
    FILE *f = fopen(MASTER_FILE, "rb"); // open in binary mode
    char input[100];
    char stored_hex_hash[HEX_HASH_SIZE];
    uint8_t salt[SALT_SIZE];

    // if first run create new master key
    if (f == NULL) {
        printf("CREATE MASTER KEY:\n");
        printf("set your master pwd (NOT CHANGEABLE): ");
        if (!fgets(input, sizeof(input), stdin)) return 0;
        trim(input);

        // random salt
        for (int i = 0; i < SALT_SIZE; i++) salt[i] = rand() % 256;

        // compute hash
        char hex_hash[HEX_HASH_SIZE];
        compute_argon2(input, salt, hex_hash);

        // save salt+hash, we'll need both later
        f = fopen(MASTER_FILE, "wb");
        fwrite(salt, 1, SALT_SIZE, f);
        fwrite(hex_hash, 1, HEX_HASH_SIZE, f); 
        fclose(f);

        printf("Master Password Set!\n");
        print_usage("");
        return 0;
    }

    //normal login
    
    // read salt and hash
    if (fread(salt, 1, SALT_SIZE, f) != SALT_SIZE) {
        printf("Error reading key file (salt).\n"); fclose(f); return 0;
    }
    if (fread(stored_hex_hash, 1, HEX_HASH_SIZE, f) != HEX_HASH_SIZE) {
        printf("Error reading key file (hash).\n"); fclose(f); return 0;
    }
    fclose(f);

    // ask for master pwd
    printf("enter master pwd: ");
    if (!fgets(input, sizeof(input), stdin)) return 0;
    trim(input);

    // 3. re-compute hash
    char current_hex_hash[HEX_HASH_SIZE];
    compute_argon2(input, salt, current_hex_hash);

    // 4. compare the two hashes
    if (strcmp(stored_hex_hash, current_hex_hash) == 0) {
        return true; // they coincide
    } else {
        //printf("Access Denied.\n");
        return false;
    }
}