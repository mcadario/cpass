#include "./cpass.h"

// cmd handler
typedef int (*cmd_handler_t)(int argc, char *argv[]);

// cmd structure
typedef struct {
    const char *name;
    int required_argc; 
    cmd_handler_t handler;
} command_t;

// handlers
static int handle_add(int argc, char *argv[]) {
    save_pwd(argv[2], argv[3], argv[4]);
    return 0;
}

static int handle_list(int argc, char *argv[]) {
    read_pwd(false);
    return 0;
}

static int handle_find(int argc, char *argv[]) {
    find_pwd(argv[2], true, false);
    return 0;
}

static int handle_delete(int argc, char *argv[]) {
    del_pwd(argv[2]);
    return 0;
}

static int handle_bin(int argc, char *argv[]) {
    read_pwd(true);
    return 0;
}

// dispatch table
static const command_t commands[] = {
    {"add",    5, handle_add},
    {"list",   2, handle_list},
    {"find",   3, handle_find},
    {"delete", 3, handle_delete},
    {"bin",    2, handle_bin},
    {NULL,     0, NULL}  // "else" case
};

int main(int argc, char *argv[]) {
    atexit(cleanup_session);

    if (argc < 2) {
        print_usage("");
        return 0;
    }

    // search the dispatch table
    for (const command_t *cmd = commands; cmd->name != NULL; cmd++) {
        if (strcmp(argv[1], cmd->name) == 0) {
            if (argc != cmd->required_argc) {
                print_usage(argv[1]);
                return 1;
            }
            return cmd->handler(argc, argv);
        }
    }

    // if unknown command
    print_usage("");
    return 0;
}