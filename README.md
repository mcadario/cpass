# cpass (in development)
As the name suggests it is a simple, lightweight C PASSword manager.

## Brief usage instructions
As of now I am yet to implement an actual installation.
If you want to use this tool you'll need to clone the repo and compile:

    gcc ./src/main.c ./src/cpass.c ./lib/monocypher.c  -o cpass

Then you will have a cpass executable

    -rwxr-xr-x. 1 <user> <user> 96720 Jan 24 22:43 cpass

Then:

    cd cpass

IMPORTANT: you must be in the cpass folder to continue.

Running that executable with 

    ./cpass

will give you all the information to use the tool.

Have fun!
