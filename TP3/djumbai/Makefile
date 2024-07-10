CC = gcc
CFLAGS = -Wall
SRCDIR = /usr/local/djumbai/src
BINDIR = /usr/local/djumbai/bin
LDFLAGS = -lssl -lcrypto

CLIENT = $(BINDIR)/client
SERVER = $(BINDIR)/server

SETUP_DIRS = /var/djumbai/groups
SCRIPTDIR = /usr/local/djumbai/scripts
KEYFILE = $(SCRIPTDIR)/aes_key

all: setup_dirs generate_key $(CLIENT) $(SERVER)

$(CLIENT): $(SRCDIR)/client.c
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $(CLIENT) $(SRCDIR)/client.c $(LDFLAGS)

$(SERVER): $(SRCDIR)/server.c
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $(SERVER) $(SRCDIR)/server.c $(LDFLAGS)
	sudo chown root:root $(SERVER)
	sudo chmod 700 $(SERVER)

generate_key:
	mkdir -p $(SCRIPTDIR)
	openssl rand -base64 32 | sudo tee $(KEYFILE) > /dev/null
	sudo chmod 640 $(KEYFILE)
	sudo chown root:$(shell getent group users | cut -d: -f3) $(KEYFILE)


setup_dirs:
	@sudo mkdir -p $(SETUP_DIRS)
	@sudo chmod 755 $(SETUP_DIRS)
	@sudo chown root:root $(SETUP_DIRS)

clean:
	rm -rf $(BINDIR)

