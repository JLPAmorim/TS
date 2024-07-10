#!/bin/bash
ACTION=$1
GROUPNAME=$2
USERNAME=$3

case $ACTION in
    create)
        groupadd $GROUPNAME
        echo "Group $GROUPNAME created."
        ;;
    delete)
        groupdel $GROUPNAME
        echo "Group $GROUPNAME deleted."
        ;;
    add_user)
        usermod -a -G $GROUPNAME $USERNAME
        echo "User $USERNAME added to group $GROUPNAME."
        ;;
    remove_user)
        gpasswd -d $USERNAME $GROUPNAME
        echo "User $USERNAME removed from group $GROUPNAME."
        ;;
    *)
        echo "Unknown action: $ACTION"
        ;;
esac