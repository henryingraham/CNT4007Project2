/*///////////////////////////////////////////////////////////
*
* FILE:		server.c
* AUTHOR:	Henry Ingraham and Anski Saint-Fleur
* PROJECT:	CNT 4007 Project 2 - Professor Traynor
* DESCRIPTION:	Network Server Code
*
*////////////////////////////////////////////////////////////

/*Included libraries*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/stat.h>

#define PORT 3001
#define BUF_SIZE 1024
#define SERVER_DIR "./serverFiles/"  // Directory for server files

// Function prototypes
void compute_file_hash(const char* file_path, unsigned char hash[SHA256_DIGEST_LENGTH]);
void send_file_list(int sock);
void send_diff(int sock, const char* client_file_hashes);
void send_files(int client_sock, char *file_name);
void* client_handler(void* socket_desc);

// Function to compute the hash of a file
void compute_file_hash(const char* file_path, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("File open error");
        return;
    }

    unsigned char buffer[BUF_SIZE];
    size_t bytes_read;
    
    // Use the EVP interface for hashing
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

// Function to send the list of files (names only) from the server directory
void send_file_list(int sock) {
    char file_list[BUF_SIZE] = "";
    DIR *d = opendir(SERVER_DIR);
    struct dirent *dir;

    if (!d) {
        perror("Could not open server directory");
        return;
    }

    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_REG) {  // Regular file
            strcat(file_list, dir->d_name);
            strcat(file_list, "\n");
        }
    }
    closedir(d);

    // Send the file list
    ssize_t bytes_sent = send(sock, file_list, strlen(file_list), 0);
    
    if (bytes_sent < 0) {
        perror("Failed to send file list");
    } else {
        printf("Sent file list to client:\n%s\n", file_list);
    }
}

// Function to send the diff (file hashes) between server and client
void send_diff(int sock, const char* client_file_hashes) {
    char diff[BUF_SIZE] = "";  // Buffer to hold the filenames of missing or different files
    DIR *d = opendir(SERVER_DIR);
    struct dirent *dir;
    unsigned char server_hash[SHA256_DIGEST_LENGTH];
    char file_path[BUF_SIZE];

    if (!d) {
        perror("Could not open server directory");
        return;
    }

    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_REG) {  // Regular file
            // Compute the hash of the server file
            size_t path_length = strlen(SERVER_DIR) + strlen(dir->d_name) + 1; // +1 for '\0'
            if (path_length < sizeof(file_path)) {
                snprintf(file_path, sizeof(file_path), "%s%s", SERVER_DIR, dir->d_name);
            } else {
                fprintf(stderr, "Warning: file_path in send_diff truncated\n");
            }
            compute_file_hash(file_path, server_hash);
            
            // Convert the hash to a string representation
            char server_hash_str[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                sprintf(&server_hash_str[i * 2], "%02x", server_hash[i]);
            }
            
            // Check if the server's file hash matches any of the client file hashes
            if (strstr(client_file_hashes, server_hash_str) == NULL) {
                // Append the filename to the diff buffer if it's missing or different
                strcat(diff, dir->d_name);
                strcat(diff, "\n");
            }
        }
    }
    closedir(d);
    
    // Send only the filenames to the client
    send(sock, diff, strlen(diff), 0);  // Send the diff result to the client
}

// Function to send files based on client request
void send_files(int client_sock, char *file_name) {
    // Construct the full path to the file
    char file_path[BUF_SIZE];
    snprintf(file_path, sizeof(file_path), "%s/%s", SERVER_DIR, file_name);

    // Open the requested file
    FILE *file = fopen(file_path, "r");
    if (!file) {
        // Send an error message if the file is not found
        char error_msg[BUF_SIZE];
        snprintf(error_msg, sizeof(error_msg), "ERROR: %s not found\n", file_name);
        send(client_sock, error_msg, strlen(error_msg), 0);
        printf("File %s not found.\n", file_name);
        return;
    }

    printf("Sending file: %s\n", file_name);

    // Send file content in chunks
    char buffer[BUF_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, sizeof(char), BUF_SIZE, file)) > 0) {
        send(client_sock, buffer, bytes_read, 0);
    }

    fclose(file);

    // Send an end-of-file (EOF) marker to signal the end of transmission
    // char eof_marker[] = "EOF";
    // send(client_sock, eof_marker, strlen(eof_marker), 0);
    printf("File %s sent successfully.\n", file_name);
}

// Function to handle communication with a client
void* client_handler(void* socket_desc) {
    int sock = *(int*)socket_desc;
    char client_message[BUF_SIZE];
    
    while (1) {
        memset(client_message, 0, BUF_SIZE);
        int read_size = recv(sock, client_message, BUF_SIZE, 0);
        
        if (read_size <= 0) {
            printf("Client disconnected\n");
            close(sock);
            free(socket_desc);
            pthread_exit(NULL);
        }

        printf("Received message from client: %s\n", client_message);  // Debugging line

        if (strncmp(client_message, "LIST", 4) == 0) {
            send_file_list(sock);
        } 
        else if (strncmp(client_message, "DIFF", 4) == 0) {
            send_diff(sock, client_message + 5);
        } 
        else if (strncmp(client_message, "PULL", 4) == 0) {
            // Extract the filename from the PULL message
            char file_name[BUF_SIZE];
            sscanf(client_message, "PULL %s", file_name);
            printf("PULL requested for file: %s\n", file_name);

            // Send the requested file
            send_files(sock, file_name);
        } 
        else if (strncmp(client_message, "LEAVE", 5) == 0) {
            printf("Client left session\n");
            break;
        } 
        else {
            printf("Unknown command received: %s\n", client_message);  // Corrected format specifier
        }
    }
    
    close(sock);
    free(socket_desc);
    pthread_exit(NULL);
}

// Main function to set up the server
int main() {
    int server_fd, new_socket, *new_sock;
    struct sockaddr_in server, client;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    // Create the socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        exit(1);
    }
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);
    
    // Bind the socket to the address and port
    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Bind failed");
        exit(1);
    }
    
    // Listen for incoming connections
    listen(server_fd, 3);
    printf("Server listening on port %d\n", PORT);
    
    // Accept incoming connections
    while (1) {
        new_socket = accept(server_fd, (struct sockaddr *)&client, &addr_len);
        if (new_socket < 0) {
            perror("Accept failed");
            continue;  // Continue accepting other clients
        }
        
        printf("Client connected\n");
        
        pthread_t client_thread;
        new_sock = malloc(sizeof(int));
        *new_sock = new_socket;
        
        // Create a new thread for each client
        if (pthread_create(&client_thread, NULL, client_handler, (void*)new_sock) < 0) {
            perror("Could not create thread");
            free(new_sock);  // Free memory on thread creation failure
            return 1;
        }
    }

    // Close the server socket (this will never be reached in this loop)
    close(server_fd);
    return 0;
}
