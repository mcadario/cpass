#include "cpass.h"
#include "../lib/monocypher.h"
#include "../lib/aes.h"

#define CBC 1       // use cbc
#define AES256 1    // 256b keys

// implementations of cpass.h

//the salt is hardcoded which doesn't make this program completely secure for multi-user environments.
//but since this tool is thought to be single-user only, it should be ok i guess :)))
uint8_t ENC_SALT[16] = { 'S','T','A','T','I','C','_','S','A','L','T','_','K','E','Y','!' };
uint8_t SESSION_KEY[32]; // temp key for aes that exists in RAM only

void print_usage(char *cmd){
    if (strcmp(cmd, "add")==0)
        printf("Usage: cpass add <site> <username> <password>\n");
    else if (strcmp(cmd, "list")==0)
        printf("Usage: cpass list [no parameters[] \n");
    else if (strcmp(cmd, "find")==0)
        printf("Usage: cpass find <site> \n");
    else if (strcmp(cmd, "delete")==0)
        printf("Usage: cpass delete <site> \n");
    else {
        printf("\n -- COMMANDS --\n");
        print_usage("add");
        print_usage("list");
        print_usage("find");
        print_usage("delete");
    }
}

// ecrypt / decrypt DISMISSED
void toggle_xor(char *str) {
    for (int i = 0; i < strlen(str); i++) {
        str[i] = str[i] ^ KEY;
    }
}

void get_path(char *filename, char *output_buffer) {
    const char *home_dir = getenv("HOME");
    if (!home_dir) {
        // if HOME isn't set
        strcpy(output_buffer, filename); 
        return;
    }

    // set folder path
    char folder_path[256];
    sprintf(folder_path, "%s/.cpass", home_dir);

    // create folder if isn't set
    struct stat st = {0};
    if (stat(folder_path, &st) == -1) {
        mkdir(folder_path, 0700);// drwx permissions
    }

    // final path, output in output_buffer
    sprintf(output_buffer, "%s/%s", folder_path, filename);
}


// saving pwd
void save_pwd(char *s, char *u, char *p) {
    if (!master_auth()) return; 
    
    // strip quotes
    char *plain_pwd = p;
    size_t len = strlen(p);
    if (len >= 2 && p[0] == '\'' && p[len - 1] == '\'') {
        p[len - 1] = '\0'; // null terminate
        plain_pwd = p + 1; // skip first quote
    }

    Credential c;
    char path[256];
    get_path(FILENAME, path);
    FILE *file = fopen(path, "ab");

    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }

    // write in the file as a struct Credential instance
    strncpy(c.site, s, sizeof(c.site) - 1);
    strncpy(c.usr, u, sizeof(c.usr) - 1);
    //strncpy(c.pwd, p, sizeof(c.pwd) - 1);

    /*
    printf("Enter Website: ");
    scanf("%s", c.site);
    printf("Enter Username: ");
    scanf("%s", c.usr);
    printf("Enter Password: ");
    scanf("%s", c.pwd);
    */

    //toggle_xor(c.pwd);

    encrypt_entry(&c, plain_pwd);

    fwrite(&c, sizeof(Credential), 1, file);
    fclose(file);
    printf("Password saved successfully!\n");
}

int count_pwd() {
    char path[256];
    get_path(FILENAME, path);
    FILE *file = fopen(path, "rb");
    if (file == NULL) return 0;
    
    Credential c;
    int count = 0;
    
    while (fread(&c, sizeof(Credential), 1, file)) {
        if (!c.del) {  //only count if not del
            count++;
        }
    }
    
    fclose(file);
    return count;
}

//counts all pwds also the deleted ones
int count_pwd_all(){
    char path[256];
    get_path(FILENAME, path);
    FILE *file = fopen(path, "rb");
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
    
    char path[256];
    get_path(FILENAME, path);
    FILE *file = fopen(path, "rb");

    if (file == NULL) {
        printf("No passwords found yet.\n");
        return;
    }

    if (count_pwd()==0){
        printf("No password in the file.");
        fclose(file);
        return;
    }

    char decpwd[64];

    printf("\n--- SAVED PASSWORDS (%d) ---\n", count_pwd());
    while (fread(&c /* assign output to our temp var */, sizeof(Credential), 1, file)) {
        decrypt_entry(&c, decpwd);

        if(!c.del)
            printf("Site: %s | User: %s | Pass: %s\n", c.site, c.usr, decpwd);
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

int find_pwd(char *site, bool verbose) {
    if (!master_auth()) return 0; 

    char path[256];
    get_path(FILENAME, path);
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        printf("No passwords found yet.\n");
        return 0;
    }

    Credential c;
    int count_found = 0;
    char decpwd[64];
    while (fread(&c, sizeof(Credential), 1, file)) {
        if (strcmp(c.site, site) == 0 && !c.del) {
            count_found++;
            if(verbose){
                if (count_found==1) printf("\n--- RESULTS FOR %s ---\n", site);
                decrypt_entry(&c, decpwd);
                printf("Site: %s | User: %s | Pass: %s\n", c.site, c.usr, decpwd);
            }
        }
    }

    if(verbose)
        if (count_found == 0) {
            printf("ERROR: No passwords found for %s\n", site);
        } else {
            printf("Total found: %d\n", count_found);
        }

    fclose(file);
    return count_found;
}

// helper to get full path: ~/.cpass/filename,
// with this function you can execute from every location an still saves in HOME/.cpass/

void del_pwd(char *site) {
    int count = find_pwd(site, true); // find pwd and print pwd

    if (count == 0) {printf("ERROR: no password found for %s", site); return;} // nothing to delete

    char target_user[50];
    
    // choose which one to delete
    if (count > 1) {
        printf("\nMore than one entry found,\n enter the USERNAME to delete: ");
        if (!fgets(target_user, sizeof(target_user), stdin)) return;
        trim(target_user);
    } else {
        // If only 1 exists, don't need to ask for the username, 
        // but still set it to empty for next comparisons
        target_user[0] = '\0'; 
    }

    // open file in rb+ (read and write)
    char path[256];
    get_path(FILENAME, path);
    FILE *file = fopen(path, "rb+"); 
    
    Credential c;
    bool deleted = false;

    while (fread(&c, sizeof(Credential), 1, file)) {
        // skip deleted ones
        if (c.del == true) continue;

        // site match
        if (strcmp(c.site, site) == 0) {
            
            // username match
            if (strcmp(c.usr, target_user) != 0) {
                continue; //if its not the targeted user
            }

            //found target
            c.del = true;

            /* wipe password for security
            memset(c.pwd, 0, 64);
            memset(c.iv, 0, 16);
            */

            // move cursore back one entry
            fseek(file, -sizeof(Credential), SEEK_CUR);

            //overwrite
            fwrite(&c, sizeof(Credential), 1, file);
            
            printf("deleted entry for site: %s, user: %s\n", c.site, c.usr);
            deleted = true;
            break; // Stop after deleting one
        }
    }

    if (!deleted && count > 1) {
        printf("ERROR: user '%s' not found for site '%s'.\n", target_user, site);
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

// hash with argon2, output will be in output (raw bytes now)
void compute_argon2(char *password, uint8_t *salt, uint8_t *output) {
    
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
    // We output to the buffer directly (HASH_SIZE = 32)
    crypto_argon2(output, HASH_SIZE, work_area, config, inputs, extras);

    free(work_area);
    
    // convert to hex and store in output_key
    // Removed to_hex here to allow raw byte output for AES key
}

void trim(char *str) {
    str[strcspn(str, "\n")] = 0;
}

//char enc_hex[HEX_HASH_SIZE];

//uses argon2
bool master_auth() {
    char path[256];
    get_path(MASTER_FILE, path);
    FILE *f = fopen(path, "rb"); // open in binary mode
    char input[100];
    char stored_hex_hash[HEX_HASH_SIZE];
    uint8_t salt[SALT_SIZE];
    uint8_t raw_hash[HASH_SIZE]; // temp buffer for raw bytes

    srand(time(NULL)); //seed random generator

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
        compute_argon2(input, salt, raw_hash);
        to_hex(raw_hash, hex_hash, HASH_SIZE);

        // save salt+hash, we'll need both later
        f = fopen(path, "wb");
        fwrite(salt, 1, SALT_SIZE, f);
        fwrite(hex_hash, 1, HEX_HASH_SIZE, f); 
        fclose(f);

        printf("Master Password Set!\n");
        memset(input, 0, sizeof(input));
        print_usage("");
        return true;
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

    //compute key for aes
    //uses the hardcoded ENC_SALT and writes raw bytes to SESSION_KEY
    compute_argon2(input, ENC_SALT, SESSION_KEY);

    // 3. re-compute hash
    char current_hex_hash[HEX_HASH_SIZE];
    compute_argon2(input, salt, raw_hash);
    to_hex(raw_hash, current_hex_hash, HASH_SIZE);

    // 4. compare the two hashes
    if (strcmp(stored_hex_hash, current_hex_hash) == 0) {
        return true; // they coincide
    } else {
        printf("ERROR: wrong master pwd\n");
        memset(SESSION_KEY, 0, 32); // wipe key
        return false;
    }
}

void generate_iv(uint8_t *iv) {
    // random iv bytes
    for(int i=0; i<16; i++) iv[i] = rand() % 256; 
}


void encrypt_entry(Credential *c, char *plain_text) {
    struct AES_ctx ctx;
    
    //save len to cut off padding later
    c->len = strlen(plain_text);
    c->del = false;

    // clear buffer and copy pwd
    memset(c->pwd, 0, 64); //set 64B of c->pwd to 0
    strcpy((char*)c->pwd, plain_text);

    // generate random iv
    generate_iv(c->iv);//used to init

    // encrypt
    // here we are using the SESSION_KEY generated during auth
    AES_init_ctx_iv(&ctx, SESSION_KEY, c->iv);
    
    // AES_CBC_encrypt_buffer overwrites c->pwd with encrypted
    AES_CBC_encrypt_buffer(&ctx, c->pwd, 64);
}

void decrypt_entry(Credential *c, char *output_buffer) {
    struct AES_ctx ctx;

    // init with master key and specific iv
    // we use the SESSION_KEY from RAM
    AES_init_ctx_iv(&ctx, SESSION_KEY, c->iv);

    // decrypt c->pwd into temp
    // copy it to a temp buffer so we don't modify the struct permanently
    uint8_t temp[64];
    memcpy(temp, c->pwd, 64);
    
    AES_CBC_decrypt_buffer(&ctx, temp, 64);

    // cutoff padding zeros
    memcpy(output_buffer, temp, c->len);
    output_buffer[c->len] = '\0'; //null terminate
}
