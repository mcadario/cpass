# cpass (in development)
As the name suggests it is a simple, lightweight C PASSword manager. Works only on unix-lke platforms.

## tool overview
This is a simple password manager fully written in C, mainly realized for 
educational purposes but still valid for daily use.

It features argon2 hashing algorithm to store the master key to manage saved passwords,
and AES to crypt and decrypt the password when saving/reading. AES uses a static salt
which makes this tool unsuitable for multi-user environments, as a potential malicious person
can unlock the second password.bin file once discovered the key for the first.

algon2 algorithm is taken from [this site](https://github.com/LoupVaillant/Monocypher.git),
while AES is taken from [that site](https://github.com/kokke/tiny-AES-c.git).

All passwords and the master key are saved in HOME/.cpass/ that is created when the master key is created with the function 'get_path'.


## Brief usage instructions
As of now I am yet to implement an actual installation.
If you want to use this tool you'll need to clone the repo and compile:

    gcc ./src/main.c ./src/cpass.c ./lib/monocypher.c ./lib/aes.c -o cpass

Then you will have a cpass executable

    -rwxr-xr-x. 1 <user> <user> 96720 Jan 24 22:43 cpass

Then:

    cd cpass

IMPORTANT: you must be in the cpass folder to continue.

Running that executable with 

    ./cpass

will give you all the information to use the tool.

Have fun!

## to be implemented
- Memory locking with memlock()
- Implement a non static salt
- Vacuum function to definitely remove all "tombstoned" entries
- Implementing a proper installation to use the tool as the command `cpass`.
