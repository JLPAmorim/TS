Djumbai Messaging Application
Introdução
O Djumbai é uma aplicação de mensagens cliente-servidor projetada para funcionar num ambiente Linux. A aplicação suporta mensagens individuais e em grupo com criptografia AES para garantir a segurança dos dados em repouso.

Estrutura do Projeto

Copiar código
/usr/local/djumbai/
  - bin/
    - client
    - server
  - scripts/
    - activate_user.sh
    - deactivate_user.sh
    - manage_group.sh
    - aes_key
  - src/
    - client.c
    - server.c
  - Makefile
/var/djumbai/
  - users/
    - <username>/
      - messages.txt
  - groups/
    - <groupname>/
      - messages.txt

Pré-Requisitos

Sistema operacional Linux.
Biblioteca OpenSSL instalada.
Acesso root para configurar as permissões e executar certos comandos.

Passos para Configuração e Execução

1. Transferir o Diretório

Transferir o diretório djumbai para /usr/local/:

2. Executar o Makefile

Execute o Makefile para compilar a aplicação e configurar o ambiente:

sudo make

3. Configurar Permissões

Para garantir que todas as permissões estejam corretamente configuradas, é preciso executar:

sudo chown -R root:root /usr/local/djumbai
sudo chmod -R 755 /usr/local/djumbai
sudo chmod 700 /usr/local/djumbai/src
sudo chmod 740 /usr/local/djumbai/scripts
sudo chmod 600 /usr/local/djumbai/scripts/aes_key
sudo chmod 700 /usr/local/djumbai/bin/server
sudo chmod 755 /usr/local/djumbai/bin/client
sudo mkdir -p /var/djumbai/users
sudo mkdir -p /var/djumbai/groups
sudo chmod 755 /var/djumbai
sudo chmod 755 /var/djumbai/users
sudo chmod 755 /var/djumbai/groups

4. Iniciar o Servidor

Inicie o servidor:

sudo /usr/local/djumbai/bin/server

5. Executar o Cliente

Nm terminal separado, iniciar o cliente:

/usr/local/djumbai/bin/cliente - Utilizador Normal

ou

sudo /usr/local/djumbai/bin/cliente - Superuser