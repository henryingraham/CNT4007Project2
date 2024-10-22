# UFmyMusic - Project 2

## Description
This project implements a networked application where multiple machines can synchronize their music libraries. The client communicates with the server to send, receive, and compare files based on commands like `LIST`, `DIFF`, `PULL`, and `LEAVE`.

## Files
- `client.c`: Contains the client-side logic for synchronizing music files.
- `server.c`: Contains the server-side logic for handling multiple clients and managing the music library.
- `Makefile`: Used for compiling the client and server programs.

## Directories
- `clientFiles/`: Directory containing the client’s music files (represented as `.png` files for simplicity).
- `serverFiles/`: Directory containing the server’s music files (represented as `.png` files for simplicity).

## Dependencies
- `gcc` (GNU Compiler Collection)
- `libcrypto`: Used for cryptographic operations in the project.

## Compilation Instructions

1. Ensure you have `gcc` and `libcrypto` installed on your system.

2. Open a terminal and navigate to the project directory.

3. Run the following command to compile the project:

    ```bash
    make
    ```

    This will generate two executables:
    - `myMusic`: The client executable.
    - `musicServer`: The server executable.

## Running the Program

1. **Start the server**:

    In one terminal window, start the server with the following command:

    ```bash
    ./musicServer
    ```

2. **Start the client**:

    In another terminal window, start the client with the following command:

    ```bash
    ./myMusic
    ```

    The client will now connect to the server and allow you to synchronize files using the available commands.

## Important Notes
- **Run the `DIFF` command before `PULL`**: Before using the `PULL` command to fetch missing files from the server, you must first run the `DIFF` command. This compares the files between the `clientFiles` and `serverFiles` directories and identifies the missing files that need to be synchronized.

- **Client and Server Files**: Make sure that both `clientFiles` and `serverFiles` directories exist in the project folder. These directories contain the files for the client and server, respectively.

## Cleanup

To remove the compiled executables, run:

```bash
make clean
