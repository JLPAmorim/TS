#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define FILEPATH_SIZE 512
#define USER_DIR_SIZE (FILEPATH_SIZE - 14)  

void activate_user(int client_sock, const char *username);
void deactivate_user(int client_sock, const char *username);
void send_message(int client_sock, const char *from_username, const char *to_username, const char *message);
void send_group_message(int client_sock, const char *from_username, const char *groupname, const char *message);
void manage_group(int client_sock, const char *action, const char *groupname, const char *username);
int add_user_to_group(const char *username, const char *groupname);
int remove_user_from_group(const char *username, const char *groupname);

int main() {
    // Verifica se é superuser
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This server must be started with sudo or as root.\n");
        exit(EXIT_FAILURE);
    }

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        printf("Waiting for a connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(address.sin_port);
        printf("New connection from %s:%d\n", client_ip, client_port);

        pid_t pid = fork();
        if (pid == 0) { 
            close(server_fd); 
            while (1) {
                int read_size = read(new_socket, buffer, BUFFER_SIZE);
                if (read_size <= 0) {
                    printf("Client %s:%d disconnected\n", client_ip, client_port);
                    close(new_socket);
                    exit(0);
                }
                buffer[read_size] = '\0'; 
                printf("Received command from %s:%d - %s\n", client_ip, client_port, buffer);
                char *command = strtok(buffer, " ");
                
                if (strcmp(command, "activate") == 0) {
                    char *username = strtok(NULL, " ");
                    activate_user(new_socket, username);
                } else if (strcmp(command, "deactivate") == 0) {
                    char *username = strtok(NULL, " ");
                    deactivate_user(new_socket, username);
                } else if (strcmp(command, "send") == 0) {
                    char *from_username = strtok(NULL, " ");
                    char *to_username = strtok(NULL, " ");
                    char *message = strtok(NULL, "\n");
                    send_message(new_socket, from_username, to_username, message);
                } else if (strcmp(command, "send_group") == 0) {
                    char *from_username = strtok(NULL, " ");
                    char *groupname = strtok(NULL, " ");
                    char *message = strtok(NULL, "\n");
                    send_group_message(new_socket, from_username, groupname, message);
                } else if (strcmp(command, "manage_group") == 0) {
                    char *action = strtok(NULL, " ");
                    char *groupname = strtok(NULL, " ");
                    char *username = strtok(NULL, " ");
                    manage_group(new_socket, action, groupname, username);
                } else {
                    char response[BUFFER_SIZE];
                    snprintf(response, sizeof(response), "Unknown command: %s\n", command);
                    send(new_socket, response, strlen(response), 0);
                }
            }
        } else if (pid > 0) { 
            close(new_socket); 
        } else {
            perror("fork");
            close(new_socket);
        }
    }

    close(server_fd);
    return 0;
}

void activate_user(int client_sock, const char *username) {
    char response[BUFFER_SIZE];
    char command[BUFFER_SIZE];

    snprintf(command, sizeof(command), "./scripts/activate_user.sh %s", username);
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen");
        snprintf(response, sizeof(response), "Failed to execute activate_user.sh for user %s.\n", username);
        printf("Activation Response : %s\n",response);
        send(client_sock, response, strlen(response), 0);
        return;
    }

    while (fgets(response, sizeof(response), fp) != NULL) {
        printf("Activation Response: %s\n",response);
        send(client_sock, response, strlen(response), 0);
    }

    int status = pclose(fp);
    if (status == -1) {
        perror("pclose");
    } else {
        printf("Script exited with status %d\n", status);
    }
}

void deactivate_user(int client_sock, const char *username) {
    char user_dir[FILEPATH_SIZE];
    snprintf(user_dir, sizeof(user_dir), "/var/djumbai/users/%s", username);
    char response[BUFFER_SIZE];

    if (access(user_dir, F_OK) == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            execlp("sudo", "sudo", "rm", "-rf", user_dir, (char *)NULL);
            perror("execlp");
            exit(EXIT_FAILURE);
        } else if (pid > 0) {
            wait(NULL);
            snprintf(response, sizeof(response), "User %s deactivated.\n", username);
            send(client_sock, response, strlen(response), 0);
        } else {
            perror("fork");
            snprintf(response, sizeof(response), "Failed to deactivate user %s.\n", username);
            send(client_sock, response, strlen(response), 0);
        }
    } else {
        snprintf(response, sizeof(response), "User %s does not exist.\n", username);
        send(client_sock, response, strlen(response), 0);
    }
}

void send_message(int client_sock, const char *from_username, const char *to_username, const char *message) {
    char filepath[FILEPATH_SIZE];
    snprintf(filepath, sizeof(filepath), "/var/djumbai/users/%s/messages.txt", to_username);
    char response[BUFFER_SIZE];

    printf("Attempting to open file: %s\n", filepath);

    FILE *file = fopen(filepath, "a");
    if (file == NULL) {
        perror("fopen");
        snprintf(response, sizeof(response), "Failed to send message. User %s does not exist or cannot open file.\n", to_username);
        send(client_sock, response, strlen(response), 0);
        return;
    }
    fprintf(file, "Sender: %s; Message: %s\n", from_username, message);
    fclose(file);

    printf("Message sent to user: %s\n", to_username); 
    fflush(stdout);

    snprintf(response, sizeof(response), "Message sent to %s.\n", to_username);
    send(client_sock, response, strlen(response), 0);
}

int user_in_group(const char *username, const char *groupname) {
    struct group *grp = getgrnam(groupname);
    if (grp == NULL) {
        return 0; 
    }
    char **members = grp->gr_mem;
    while (*members) {
        if (strcmp(*members, username) == 0) {
            return 1; 
        }
        members++;
    }
    return 0; 
}

void send_group_message(int client_sock, const char *from_username, const char *groupname, const char *message) {
    struct group *grp;
    char response[BUFFER_SIZE];

    if ((grp = getgrnam(groupname)) == NULL) {
        snprintf(response, sizeof(response), "Group %s does not exist.\n", groupname);
        send(client_sock, response, strlen(response), 0);
        return;
    }

    if (!user_in_group(from_username, groupname)) {
        snprintf(response, sizeof(response), "User %s does not belong to group %s.\n", from_username, groupname);
        send(client_sock, response, strlen(response), 0);
        return;
    }

    char filepath[FILEPATH_SIZE];
    snprintf(filepath, sizeof(filepath), "/var/djumbai/groups/%s/messages.txt", groupname);

    FILE *file = fopen(filepath, "a");
    if (file == NULL) {
        perror("fopen");
        snprintf(response, sizeof(response), "Failed to send message to group %s.\n", groupname);
        send(client_sock, response, strlen(response), 0);
        return;
    }

    fprintf(file, "Group: %s; Sender: %s; Message: %s\n", groupname, from_username, message);
    fclose(file);

    snprintf(response, sizeof(response), "Message sent to group %s.\n", groupname);
    send(client_sock, response, strlen(response), 0);
}


void manage_group(int client_sock, const char *action, const char *groupname, const char *username) {
    char response[BUFFER_SIZE];
    char base_group_dir[FILEPATH_SIZE] = "/var/djumbai/groups";
    char group_dir[FILEPATH_SIZE + 100]; // Aumenta o buffer para evitar truncamento
    char message_file[FILEPATH_SIZE + 120]; // Buffer maior para o caminho do ficheiro messages.txt

    snprintf(group_dir, sizeof(group_dir), "%s/%s", base_group_dir, groupname);
    snprintf(message_file, sizeof(message_file), "%s/messages.txt", group_dir);

    if (strcmp(action, "create") == 0) {
        struct group *grp = getgrnam(groupname);
        if (grp == NULL) {
            pid_t pid = fork();
            if (pid == 0) {
                execlp("sudo", "sudo", "groupadd", groupname, (char *)NULL);
                perror("execlp");
                exit(EXIT_FAILURE);
            } else if (pid > 0) {
                wait(NULL);
                if (mkdir(group_dir, 0750) == -1) {
                    perror("mkdir");
                    snprintf(response, sizeof(response), "Failed to create directory for group %s.\n", groupname);
                    send(client_sock, response, strlen(response), 0);
                    return;
                }
                if (chown(group_dir, 0, getgrnam(groupname)->gr_gid) == -1) {
                    perror("chown");
                    snprintf(response, sizeof(response), "Failed to set ownership for group directory %s.\n", groupname);
                    send(client_sock, response, strlen(response), 0);
                    return;
                }
                FILE *file = fopen(message_file, "w");
                if (file == NULL) {
                    perror("fopen");
                    snprintf(response, sizeof(response), "Failed to create messages.txt for group %s.\n", groupname);
                    send(client_sock, response, strlen(response), 0);
                    return;
                }
                fclose(file);
                if (chown(message_file, 0, getgrnam(groupname)->gr_gid) == -1) {
                    perror("chown");
                    snprintf(response, sizeof(response), "Failed to set ownership for messages.txt in group directory %s.\n", groupname);
                    send(client_sock, response, strlen(response), 0);
                    return;
                }
                chmod(message_file, 0640); 
                snprintf(response, sizeof(response), "Group %s created.\n", groupname);
                send(client_sock, response, strlen(response), 0);
            } else {
                perror("fork");
                snprintf(response, sizeof(response), "Failed to create group %s.\n", groupname);
                send(client_sock, response, strlen(response), 0);
            }
        } else {
            snprintf(response, sizeof(response), "Group %s already exists.\n", groupname);
            send(client_sock, response, strlen(response), 0);
        }
    } else if (strcmp(action, "delete") == 0) {
        struct group *grp = getgrnam(groupname);
        if (grp != NULL) {
            pid_t pid = fork();
            if (pid == 0) {
                execlp("sudo", "sudo", "groupdel", groupname, (char *)NULL);
                perror("execlp");
                exit(EXIT_FAILURE);
            } else if (pid > 0) {
                wait(NULL);
                if (remove(message_file) == -1) {
                    perror("remove");
                    snprintf(response, sizeof(response), "Failed to remove messages.txt for group %s.\n", groupname);
                    send(client_sock, response, strlen(response), 0);
                    return;
                }
                if (rmdir(group_dir) == -1) {
                    perror("rmdir");
                    snprintf(response, sizeof(response), "Failed to remove directory for group %s.\n", groupname);
                    send(client_sock, response, strlen(response), 0);
                    return;
                }
                snprintf(response, sizeof(response), "Group %s deleted.\n", groupname);
                send(client_sock, response, strlen(response), 0);
            } else {
                perror("fork");
                snprintf(response, sizeof(response), "Failed to delete group %s.\n", groupname);
                send(client_sock, response, strlen(response), 0);
            }
        } else {
            snprintf(response, sizeof(response), "Group %s does not exist.\n", groupname);
            send(client_sock, response, strlen(response), 0);
        }
    } else if (strcmp(action, "add_user") == 0) {
        if (add_user_to_group(username, groupname) == -1) {
            perror("add_user_to_group");
            snprintf(response, sizeof(response), "Failed to add user %s to group %s.\n", username, groupname);
            send(client_sock, response, strlen(response), 0);
            return;
        }
        snprintf(response, sizeof(response), "User %s added to group %s.\n", username, groupname);
        send(client_sock, response, strlen(response), 0);
    } else if (strcmp(action, "remove_user") == 0) {
        if (remove_user_from_group(username, groupname) == -1) {
            perror("remove_user_from_group");
            snprintf(response, sizeof(response), "Failed to remove user %s from group %s.\n", username, groupname);
            send(client_sock, response, strlen(response), 0);
            return;
        }
        snprintf(response, sizeof(response), "User %s removed from group %s.\n", username, groupname);
        send(client_sock, response, strlen(response), 0);
    } else {
        snprintf(response, sizeof(response), "Unknown action: %s\n", action);
        send(client_sock, response, strlen(response), 0);
    }
}

int add_user_to_group(const char *username, const char *groupname) {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("sudo", "sudo", "usermod", "-aG", groupname, username, (char *)NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return 0;
        } else {
            return -1;
        }
    } else {
        perror("fork");
        return -1;
    }
}

int remove_user_from_group(const char *username, const char *groupname) {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("sudo", "sudo", "gpasswd", "-d", username, groupname, (char *)NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return 0;
        } else {
            return -1;
        }
    } else {
        perror("fork");
        return -1;
    }
}


/*

#define AES_KEY_LENGTH 32
#define AES_BLOCK_SIZE 16


void handle_openssl_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_openssl_errors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_openssl_errors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handle_openssl_errors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_openssl_errors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void send_message(int client_sock, const char *from_username, const char *to_username, const char *message) {
    char filepath[FILEPATH_SIZE];
    snprintf(filepath, sizeof(filepath), "/var/djumbai/users/%s/messages.txt", to_username);
    char response[BUFFER_SIZE];

    printf("Attempting to open file: %s\n", filepath);

    FILE *file = fopen(filepath, "a");
    if (file == NULL) {
        perror("fopen");
        snprintf(response, sizeof(response), "Failed to send message. User %s does not exist or cannot open file.\n", to_username);
        send(client_sock, response, strlen(response), 0);
        return;
    }

    // Carregar a chave de criptografia AES
    unsigned char key[AES_KEY_LENGTH];
    unsigned char iv[AES_BLOCK_SIZE];

    FILE *keyfile = fopen("/usr/local/djumbai/scripts/aes_key", "rb");
    if (!keyfile) {
        perror("fopen");
        fclose(file);
        return;
    }
    fread(key, 1, AES_KEY_LENGTH, keyfile);
    fclose(keyfile);

    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        perror("RAND_bytes");
        fclose(file);
        return;
    }

    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len = encrypt((unsigned char *)message, strlen(message), key, iv, ciphertext);

    fwrite(iv, 1, AES_BLOCK_SIZE, file);
    fwrite(ciphertext, 1, ciphertext_len, file);
    fclose(file);

    printf("Message sent to user: %s\n", to_username); 
    fflush(stdout);

    snprintf(response, sizeof(response), "Message sent to %s.\n", to_username);
    send(client_sock, response, strlen(response), 0);
}

void send_group_message(int client_sock, const char *from_username, const char *groupname, const char *message) {
    struct group *grp;
    char response[BUFFER_SIZE];

    // Verificar se o grupo existe
    if ((grp = getgrnam(groupname)) == NULL) {
        snprintf(response, sizeof(response), "Group %s does not exist.\n", groupname);
        send(client_sock, response, strlen(response), 0);
        return;
    }

    // Verificar se o usuário pertence ao grupo
    if (!user_in_group(from_username, groupname)) {
        snprintf(response, sizeof(response), "User %s does not belong to group %s.\n", from_username, groupname);
        send(client_sock, response, strlen(response), 0);
        return;
    }

    // O caminho correto é baseado no nome do grupo, não nos membros do grupo
    char filepath[FILEPATH_SIZE];
    snprintf(filepath, sizeof(filepath), "/var/djumbai/groups/%s/messages.txt", groupname);

    FILE *file = fopen(filepath, "a");
    if (file == NULL) {
        perror("fopen");
        snprintf(response, sizeof(response), "Failed to send message to group %s.\n", groupname);
        send(client_sock, response, strlen(response), 0);
        return;
    }

    // Carregar a chave de criptografia AES
    unsigned char key[AES_KEY_LENGTH];
    unsigned char iv[AES_BLOCK_SIZE];

    FILE *keyfile = fopen("/usr/local/djumbai/scripts/aes_key", "rb");
    if (!keyfile) {
        perror("fopen");
        fclose(file);
        return;
    }
    fread(key, 1, AES_KEY_LENGTH, keyfile);
    fclose(keyfile);

    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        perror("RAND_bytes");
        fclose(file);
        return;
    }

    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len = encrypt((unsigned char *)message, strlen(message), key, iv, ciphertext);

    fwrite(iv, 1, AES_BLOCK_SIZE, file);
    fwrite(ciphertext, 1, ciphertext_len, file);
    fclose(file);

    snprintf(response, sizeof(response), "Message sent to group %s.\n", groupname);
    send(client_sock, response, strlen(response), 0);
}
*/