#!/bin/bash
USERNAME=$1
USER_DIR="/var/djumbai/users/$USERNAME"

if [ -d "$USER_DIR" ]; then
    sudo rm -rf "$USER_DIR"
    if [ $? -eq 0 ]; then
        echo "User $USERNAME deactivated."
    else
        echo "Failed to deactivate user $USERNAME."
    fi
else
    echo "User $USERNAME does not exist."
fi

