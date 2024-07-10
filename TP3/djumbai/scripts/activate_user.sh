#!/bin/bash
USERNAME=$1
BASE_DIR="/var/djumbai"
USERS_DIR="$BASE_DIR/users"
USER_DIR="$USERS_DIR/$USERNAME"
MESSAGE_FILE="$USER_DIR/messages.txt"

# Garantir que a pasta BASE_DIR tenha as permissões corretas
if [ ! -d "$BASE_DIR" ]; then
    sudo mkdir -p "$BASE_DIR"
    sudo chmod 755 "$BASE_DIR"
    sudo chown root:root "$BASE_DIR"
fi

# Garantir que a pasta USERS_DIR exista com as permissões corretas
if [ ! -d "$USERS_DIR" ]; then
    sudo mkdir -p "$USERS_DIR"
    sudo chmod 755 "$USERS_DIR"
    sudo chown root:root "$USERS_DIR"
fi

# Criar a pasta do usuário e o arquivo de mensagens se não existirem
if [ ! -d "$USER_DIR" ]; then
    sudo mkdir -p "$USER_DIR"
    sudo touch "$MESSAGE_FILE"
    sudo chown $USERNAME:$USERNAME "$USER_DIR" "$MESSAGE_FILE"
    sudo chmod 555 "$USER_DIR"
    sudo chmod 400 "$MESSAGE_FILE"
    echo "User $USERNAME activated."
else
    echo "User $USERNAME already exists."
fi







