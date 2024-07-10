#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define FILEPATH_SIZE 512

void activate_user(int sock, const char *username);
void deactivate_user(int sock, const char *username);
void send_message(int sock, const char *from_username, const char *to_username, const char *message);
void read_messages(const char *username);
void send_group_message(int sock, const char *from_username, const char *groupname, const char *message);
void read_group_messages(const char *groupname);
void manage_group(int sock, const char *action, const char *groupname, const char *username);
void list_activated_users();
void list_user_groups(const char *username);
void menu(int sock, const char *username);
void admin_menu(int sock);

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char username[BUFFER_SIZE];

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server at 127.0.0.1:%d\n", PORT);

    // Obter o username do utilizador com sessão iniciada
    struct passwd *pw = getpwuid(geteuid());
    if (pw == NULL) {
        perror("getpwuid");
        close(sock);
        exit(EXIT_FAILURE);
    }
    strncpy(username, pw->pw_name, BUFFER_SIZE - 1);
    username[BUFFER_SIZE - 1] = '\0'; 
    printf("Username: %s\n", username);
    
    if (geteuid() == 0) {
        printf("Running with superuser privileges.\n");
        admin_menu(sock);
    } else {
        // Ativar o utilizador automaticamente
        activate_user(sock, username);
        // Apresentar opções de menu
        menu(sock, username);
    }

    close(sock);
    return 0;
}

void activate_user(int sock, const char *username) {
    char buffer[BUFFER_SIZE] = {0};
    snprintf(buffer, sizeof(buffer), "activate %s", username);
    send(sock, buffer, strlen(buffer), 0);
    printf("Sent command to server: %s\n", buffer);
    read(sock, buffer, BUFFER_SIZE);
    printf("Response from server: %s\n", buffer);

    if (strstr(buffer, "already exists") != NULL) {
        printf("User %s is already activated.\n", username);
    } else {
        printf("%s\n", buffer);
    }
}

void deactivate_user(int sock, const char *username) {
    char buffer[BUFFER_SIZE] = {0};
    snprintf(buffer, sizeof(buffer), "deactivate %s", username);
    send(sock, buffer, strlen(buffer), 0);
    printf("Sent command to server: %s\n", buffer);
    read(sock, buffer, BUFFER_SIZE);
    printf("%s\n", buffer);
}

void send_message(int sock, const char *from_username, const char *to_username, const char *message) {
    char buffer[BUFFER_SIZE] = {0};
    snprintf(buffer, sizeof(buffer), "send %s %s %s", from_username, to_username, message);
    send(sock, buffer, strlen(buffer), 0);
    printf("Sent command to server: %s\n", buffer);
    read(sock, buffer, BUFFER_SIZE);
    printf("Response from server: %s\n", buffer);
}

void read_messages(const char *username) {
    char filepath[FILEPATH_SIZE];
    snprintf(filepath, sizeof(filepath), "/var/djumbai/users/%s/messages.txt", username);

    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("fopen");
        printf("Failed to read messages. User %s does not exist or cannot open file.\n", username);
        return;
    }

    printf("Messages for %s:\n", username);
    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file) != NULL) {
        printf("%s", line);
    }
    fclose(file);
}

void send_group_message(int sock, const char *from_username, const char *groupname, const char *message) {
    char buffer[BUFFER_SIZE] = {0};
    snprintf(buffer, sizeof(buffer), "send_group %s %s %s", from_username, groupname, message);
    send(sock, buffer, strlen(buffer), 0);
    printf("Sent command to server: %s\n", buffer);
    read(sock, buffer, BUFFER_SIZE);
    printf("Response from server: %s\n", buffer);
}

void read_group_messages(const char *groupname) {
    char filepath[FILEPATH_SIZE];
    snprintf(filepath, sizeof(filepath), "/var/djumbai/groups/%s/messages.txt", groupname);

    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("fopen");
        printf("Failed to read messages. Group %s does not exist or user has no permissions.\n", groupname);
        return;
    }

    printf("Messages for group %s:\n", groupname);
    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file) != NULL) {
        printf("%s", line);
    }
    fclose(file);
}

void manage_group(int sock, const char *action, const char *groupname, const char *username) {
    char buffer[BUFFER_SIZE] = {0};
    snprintf(buffer, sizeof(buffer), "manage_group %s %s %s", action, groupname, username);
    send(sock, buffer, strlen(buffer), 0);
    printf("Sent command to server: %s\n", buffer);
    read(sock, buffer, BUFFER_SIZE);
    printf("%s\n", buffer);
}

void list_activated_users() {
    struct dirent *entry;
    DIR *dp = opendir("/var/djumbai/users");

    if (dp == NULL) {
        perror("opendir");
        return;
    }

    printf("Activated users:\n");
    while ((entry = readdir(dp))) {
        if (entry->d_name[0] != '.') {
            char path[BUFFER_SIZE];
            snprintf(path, sizeof(path), "/var/djumbai/users/%s", entry->d_name);
            struct stat statbuf;
            if (stat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
                printf("%s\n", entry->d_name);
            }
        }
    }

    closedir(dp);
}

void list_user_groups(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw == NULL) {
        perror("getpwnam");
        return;
    }

    int ngroups = 0;
    getgrouplist(username, pw->pw_gid, NULL, &ngroups);

    gid_t groups[ngroups];
    getgrouplist(username, pw->pw_gid, groups, &ngroups);

    printf("Groups for user %s:\n", username);
    for (int i = 0; i < ngroups; i++) {
        struct group *grp = getgrgid(groups[i]);
        if (grp != NULL) {
            printf("%s\n", grp->gr_name);
        }
    }
}

void menu(int sock, const char *username) {
    int choice;
    char buffer[BUFFER_SIZE];

    while (1) {
        printf("\nMenu:\n");
        printf("1. Send Message\n");
        printf("2. Read Messages\n");
        printf("3. List My Groups\n");
        printf("4. Send Group Message\n");
        printf("5. Read Group Messages\n");
        printf("6. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar();  

        switch (choice) {
            case 1:
                printf("Enter recipient username: ");
                fgets(buffer, BUFFER_SIZE, stdin);
                buffer[strcspn(buffer, "\n")] = 0;  
                char to_username[BUFFER_SIZE];
                strcpy(to_username, buffer);

                printf("Enter message: ");
                fgets(buffer, BUFFER_SIZE, stdin);
                buffer[strcspn(buffer, "\n")] = 0;  

                send_message(sock, username, to_username, buffer);
                break;

            case 2:
                read_messages(username);
                break;

            case 3:
                list_user_groups(username);
                break;

            case 4:
                printf("Enter group name: ");
                fgets(buffer, BUFFER_SIZE, stdin);
                buffer[strcspn(buffer, "\n")] = 0;  
                char groupname[BUFFER_SIZE];
                strcpy(groupname, buffer);

                printf("Enter message: ");
                fgets(buffer, BUFFER_SIZE, stdin);
                buffer[strcspn(buffer, "\n")] = 0;  

                send_group_message(sock, username, groupname, buffer);
                break;

            case 5:
                printf("Enter group name: ");
                fgets(buffer, BUFFER_SIZE, stdin);
                buffer[strcspn(buffer, "\n")] = 0;  
                read_group_messages(buffer);
                break;

            case 6:
                printf("Exiting...\n");
                return;

            default:
                printf("Invalid choice. Please try again.\n");
        }
    }
}

void admin_menu(int sock) {
    int choice;
    char username[BUFFER_SIZE];

    while (1) {
        printf("\nAdmin Menu:\n");
        printf("1. Activate User\n");
        printf("2. Deactivate User\n");
        printf("3. List Activated Users\n");
        printf("4. Manage Groups\n");
        printf("5. User Menu\n");
        printf("6. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar();  

        switch (choice) {
            case 1:
                printf("Enter username to activate: ");
                fgets(username, BUFFER_SIZE, stdin);
                username[strcspn(username, "\n")] = 0;  
                activate_user(sock, username);
                break;

            case 2:
                printf("Enter username to deactivate: ");
                fgets(username, BUFFER_SIZE, stdin);
                username[strcspn(username, "\n")] = 0; 
                deactivate_user(sock, username);
                break;

            case 3:
                list_activated_users();
                break;
            
            case 4:
                printf("Enter action (create/delete/add_user/remove_user): ");
                char action[BUFFER_SIZE];
                fgets(action, BUFFER_SIZE, stdin);
                action[strcspn(action, "\n")] = 0;  

                printf("Enter group name: ");
                char groupname[BUFFER_SIZE];
                fgets(groupname, BUFFER_SIZE, stdin);
                groupname[strcspn(groupname, "\n")] = 0; 

                printf("Enter username (if applicable): ");
                char membername[BUFFER_SIZE];
                fgets(membername, BUFFER_SIZE, stdin);
                membername[strcspn(membername, "\n")] = 0;  

                manage_group(sock, action, groupname, membername);
                break;

            case 5:
                menu(sock, "joao");
                break;

            case 6:
                printf("Exiting...\n");
                return;

            default:
                printf("Invalid choice. Please try again.\n");
        }
    }
}





// Implementação da criptografia das mensagens.
// No caso do Cliente, é feita a descriptografia das mensagens no momento em que o Utilizador pede para ler as suas mensagens

/*
#define AES_KEY_LENGTH 32
#define AES_BLOCK_SIZE 16

void handle_openssl_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_openssl_errors();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) handle_openssl_errors();
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) handle_openssl_errors();
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) handle_openssl_errors();
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void read_messages(const char *username) {
    char filepath[FILEPATH_SIZE];
    snprintf(filepath, sizeof(filepath), "/var/djumbai/users/%s/messages.txt", username);

    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("fopen");
        printf("Failed to read messages. User %s does not exist or cannot open file.\n", username);
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

    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char decryptedtext[BUFFER_SIZE];
    int decryptedtext_len;

    while (fread(iv, 1, AES_BLOCK_SIZE, file) == AES_BLOCK_SIZE) {
        int ciphertext_len = fread(ciphertext, 1, BUFFER_SIZE, file);
        decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
        decryptedtext[decryptedtext_len] = '\0';
        printf("%s\n", decryptedtext);
    }

    fclose(file);
}

void read_group_messages(const char *groupname) {
    char filepath[FILEPATH_SIZE];
    snprintf(filepath, sizeof(filepath), "/var/djumbai/groups/%s/messages.txt", groupname);

    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("fopen");
        printf("Failed to read messages. Group %s does not exist or user has no permissions.\n", groupname);
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

    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char decryptedtext[BUFFER_SIZE];
    int decryptedtext_len;

    while (fread(iv, 1, AES_BLOCK_SIZE, file) == AES_BLOCK_SIZE) {
        int ciphertext_len = fread(ciphertext, 1, BUFFER_SIZE, file);
        decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
        decryptedtext[decryptedtext_len] = '\0';
        printf("%s\n", decryptedtext);
    }

    fclose(file);
}
*/
