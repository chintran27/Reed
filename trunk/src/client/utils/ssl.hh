/*
 * ssl.hh
 */

#ifndef __SSL_HH__
#define __SSL_HH__

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <err.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define SSL_CA_CRT "./keys/ca/ca.crt"
#define SSL_CLIENT_CRT "./keys/client.crt"
#define SSL_CLIENT_KEY "./keys/private/client.key"

using namespace std;

class Ssl{
    private:
        /* port number */
        int hostPort_;

        /* ip address */
        char* hostName_;

        /* address structure */
        struct sockaddr_in myAddr_;

        /* host socket */
		SSL_CTX* ctx_;
		SSL* ssl_;

    public:

        /*
         * constructor: initialize sock structure and connect
         *
         * @param ip - server ip address
         * @param port - port number
         */
        Ssl(char *ip, int port, int userID);
        
		int hostSock_;

        /*
         * @ destructor
         */
        ~Ssl();

        /*
         * basic send function
         * 
         * @param raw - raw data buffer_
         * @param rawSize - size of raw data
         */
        int genericSend(char * raw, int rawSize);

        /*
         * data download function
         *
         * @param raw - raw data buffer
         * @param rawSize - the size of data to be downloaded
         * @return raw
         */
        int genericDownload(char *raw, int rawSize);

		void closeConn();
};

#endif
