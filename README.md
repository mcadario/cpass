# cpass (in development)
As the name suggests it is a simple, lightweight C PASSword manager. Works only on unix-lke platforms.

## tool overview
This is a simple password manager fully written in C, mainly realized for 
educational purposes but still valid for daily use.

It features argon2 hashing algorithm to store the master key to manage saved passwords,
and AES to crypt and decrypt the password when saving/reading. AES uses a static salt
which makes this tool unsuitable for multi-user environments, as a potential malicious person
can unlock the second password.bin file once discovered the key for the first.

algon2 algorithm is taken from [this repo](https://github.com/LoupVaillant/Monocypher.git),
while AES is taken from [that repo](https://github.com/kokke/tiny-AES-c.git).

All passwords and the master key are saved in HOME/.cpass/ that is created when the master key is created with the function 'get_path'.

## Prerequisites:

Prerequisites:
- gcc compiler
- make (there is a shell script otherwise)
- works only on linux systems


## Installation with make

Clone the repo:

    git clone https://github.com/mcadario/cpass.git
    cd cpass

Install:

    sudo make
    sudo make install

You should get the following outputs:

    $ sudo make
    Build complete! Binary: ./cpass

    $ sudo make install
    Installing cpass to /usr/local/bin...
    Installation complete!
    You can now use 'cpass' from anywhere.

Then verify installation (you can run this globally):

    cpass

If you get

     -- COMMANDS --
    Usage: cpass add <site> <username> <password>
    Usage: cpass list [no parameters] 
    Usage: cpass find <site> 
    Usage: cpass delete <site> 
    mic@fedora:~$ ls

then you are good to go!!!

## Installation with install script

Clone the repo:

    git clone https://github.com/mcadario/cpass.git
    cd cpass

Install using the script:

    sudo ./install.sh

You will get a bunch of informative output saying what the script is doing, if nothing is red or yellow you are done! Try to run it globally!

## manual compilation (works only in cloned repo directory)
Clone the repo and compile:

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

## uninstalling 
If you really really want to uninstall...

    make uninstall 

or 

    ./install.sh --uninstall

depending if you installed with make (1) or with the shell script (2).

## to be implemented
- Memory locking with mlock()
- Implement a non static salt
- Vacuum function to definitely remove all "tombstoned" entries
