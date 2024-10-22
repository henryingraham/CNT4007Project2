/*///////////////////////////////////////////////////////////
*
* FILE:		client.c
* AUTHOR:	Henry Ingraham and Anski Saint-Fleur
* PROJECT:	CNT 4007 Project 2 - Professor Traynor
* DESCRIPTION:	Network Client Code
*
*////////////////////////////////////////////////////////////

/* Included libraries */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <openssl/evp.h>


#define PORT 3001
#define BUF_SIZE 1024
#define CLIENT_DIR "./clientFiles/"
#define MAX_MISSING_FILES 1024
char missing_files[MAX_MISSING_FILES][BUF_SIZE];

// Compute the hash of a file (SHA-256)
void compute_file_hash(const char* file_path, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("File open error");
        return;
    }

    unsigned char buffer[BUF_SIZE];
    size_t bytes_read;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();

    if (mdctx == NULL || EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        perror("EVP initialization error");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return;
    }

    while ((bytes_read = fread(buffer, 1, BUF_SIZE, file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            perror("EVP update error");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return;
        }
    }

    if (EVP_DigestFinal_ex(mdctx, hash, NULL) != 1) {
        perror("EVP finalization error");
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);
}

// Send LIST command to the server
void list_files(int sock) {
    char message[] = "LIST";
    send(sock, message, strlen(message), 0);
    //printf("Sent LIST command to server\n");  // Debugging line

    char server_reply[BUF_SIZE];
    int received;

    printf("\nFiles on server:\n");

    // Initialize a file count
    int file_count = 1;

    // Loop to receive the file list until there are no more files
    while (1) {
        // Receive the server's reply
        received = recv(sock, server_reply, BUF_SIZE, 0);

        if (received < 0) {
            perror("Failed to receive data");
            break;
        } else if (received == 0) {
            printf("Server disconnected\n");
            break;
        }

        server_reply[received] = '\0'; 

        // Debugging line
        //printf("Received data from server: %s\n", server_reply);

        // Split the data by newline and print numbered list
        char *file = strtok(server_reply, "\n");

        while (file != NULL) {
            if (strcmp(file, "") != 0) { // Exclude empty strings
                printf("%d. %s\n", file_count++, file);
            }
            file = strtok(NULL, "\n");
        }
        break; 
    }
}

// Function to send the DIFF command with the client files' hashes
void diff_files(int sock) {
    memset(missing_files, 0, sizeof(missing_files));
    char message[BUF_SIZE] = "DIFF ";
    char client_file_hashes[BUF_SIZE * 10] = "";
    DIR *d;
    struct dirent *dir;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char file_path[BUF_SIZE];

    // Read client files from CLIENT_DIR
    d = opendir(CLIENT_DIR);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG) {  // Regular file
                // Compute the hash of the file
                snprintf(file_path, sizeof(file_path), "%s%s", CLIENT_DIR, dir->d_name);
                compute_file_hash(file_path, hash);

                // Convert the hash to a string representation
                char hash_str[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                    sprintf(&hash_str[i * 2], "%02x", hash[i]);
                }

                // Append the hash and file name to the message
                strcat(client_file_hashes, hash_str);
                strcat(client_file_hashes, " ");
                strcat(client_file_hashes, dir->d_name);
                strcat(client_file_hashes, "\n");
            }
        }
        closedir(d);
    }

    strcat(message, client_file_hashes);  // Attach the client hashes to the DIFF command
    send(sock, message, strlen(message), 0);  // Send diff message to the server

    // Receive and display the diff result from the server
    char server_reply[BUF_SIZE];
    int received = recv(sock, server_reply, BUF_SIZE, 0);
    server_reply[received] = '\0';  // Null-terminate the response

    // Split the server reply into missing files
    char *file = strtok(server_reply, "\n");
    int index = 0;
    while (file != NULL && index < MAX_MISSING_FILES) {
        strcpy(missing_files[index++], file);
        file = strtok(NULL, "\n");
    }

    printf("\nFiles missing or with different content on client:\n");
    for (int i = 0; i < index; i++) {
        printf("%s\n", missing_files[i]);  // Print the files missing or with different content
    }
}


// Function to send the PULL command and receive missing files
void pull_files(int clientSock, char missing_files[][BUF_SIZE]) {
    printf("Gathering missing files for PULL command...\n");

    for (int i = 0; missing_files[i][0] != '\0'; i++) {
        // Construct and send the PULL message
        char pull_message[BUF_SIZE];
        snprintf(pull_message, sizeof(pull_message), "PULL %s", missing_files[i]);
        send(clientSock, pull_message, strlen(pull_message), 0);
        printf("Sent request for file: %s\n", missing_files[i]);

        // Prepare to receive the file
        char buffer[BUF_SIZE];
        size_t bytes_received;

        // Create the file path for each missing file
        char file_path[BUF_SIZE];
        snprintf(file_path, sizeof(file_path), "%s%s", CLIENT_DIR, missing_files[i]);

        // Open the file for writing
        FILE *file = fopen(file_path, "w");
        if (!file) {
            printf("Error creating file\n");
            perror("Error creating file");
            continue;  // Move to the next file if there was an error
        }

        printf("File opened for writing: %s\n", file_path);

        // Read the file content from the server
        while (1) {
            bytes_received = recv(clientSock, buffer, BUF_SIZE, 0);
            if (bytes_received <= 0) {
                printf("Error or connection closed by server.\n");
                break;  // Stop reading if there's an error or the connection is closed
            }

            // Write to the file
            fwrite(buffer, sizeof(char), bytes_received, file);
            printf("Received %zu bytes of %s.\n", bytes_received, missing_files[i]);
            break;
        }

        fclose(file);  // Close the file after writing
        printf("File %s received and saved successfully.\n", missing_files[i]);
    }
}


// Send LEAVE command to the server
void leave_server(int sock) {
    char message[] = "LEAVE";
    send(sock, message, strlen(message), 0);
    printf("\nBye!\n");
}


int main() {
    int sock;
    struct sockaddr_in server;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Could not create socket");
        exit(1);
    }
    
    server.sin_addr.s_addr = inet_addr("127.0.0.1");  // Server IP address
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);  // Server port
    
    // Connect to remote server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection failed");
        return 1;
    }
    
    printf("Connected to server\n");
    
    int choice;
    while (1) {
        // Display menu
        printf("\nMenu:\n1. List Files\n2. Diff Files\n3. Pull File\n4. Leave\n");
        printf("Enter choice: ");
        scanf("%d", &choice);
        getchar(); // To consume the newline character after scanf

        switch (choice) {
            case 1:
                list_files(sock);
                break;
            case 2:
                diff_files(sock);
                break;
            case 3:
                pull_files(sock, missing_files);
                break;
            case 4:
                leave_server(sock);
                close(sock);
                exit(0);
        }
    }

    close(sock);
    return 0;
}