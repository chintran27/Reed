#include "socket.hh"

using namespace std;

extern void timerStart(double *t);
extern double timerSplit(const double *t);
/*
 * constructor: initialize sock structure and connect
 *
 * @param ip - server ip address
 * @param port - port number
 */
Socket::Socket(char *ip, int port, int userID){

	/* get port and ip */
	hostPort_ = port;
	hostName_ = ip;
	int err;

	/* initializing socket object */
	hostSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(hostSock_ == -1){
		printf("Error initializing socket %d\n", errno);
	}
	int* p_int = (int *)malloc(sizeof(int));
	*p_int = 1;

	/* set socket options */
	if(
			(setsockopt(hostSock_, 
						SOL_SOCKET, 
						SO_REUSEADDR, 
						(char*)p_int, 
						sizeof(int))==-1) || 
			(setsockopt(hostSock_, 
						SOL_SOCKET, 
						SO_KEEPALIVE, 
						(char*)p_int, 
						sizeof(int))== -1)
	  ){
		printf("Error setting options %d\n", errno);
		free(p_int);
	}
	free(p_int);

	/* set socket address */
	myAddr_.sin_family = AF_INET;
	myAddr_.sin_port = htons(port);
	memset(&(myAddr_.sin_zero),0,8);
	myAddr_.sin_addr.s_addr = inet_addr(ip);

	/* trying to connect socket */
	if(connect(hostSock_, (struct sockaddr*)&myAddr_, sizeof(myAddr_)) == -1){
		if((err == errno) != EINPROGRESS){
			fprintf(stderr, "Error connecting socket %d\n", errno);
		}
	}

	/* prepare user ID and send it to server */
	int netorder = htonl(userID);
	int bytecount;
	if ((bytecount = send(hostSock_, &netorder, sizeof(int), 0)) == -1){
		fprintf(stderr, "Error sending userID %d\n", errno);
	}
}


/*
 * @ destructor
 */
Socket::~Socket(){
	close(hostSock_);
}

/*
 * basic send function
 * 
 * @param raw - raw data buffer_
 * @param rawSize - size of raw data
 */
int Socket::genericSend(char *raw, int rawSize){

	int bytecount;
	int total = 0;
	while (total < rawSize){
		if ((bytecount = send(hostSock_, raw+total, rawSize-total, 0)) == -1){
			fprintf(stderr, "Error sending data %d\n", errno);
			return -1;
		}
		total+=bytecount;
	}
	return total;
}

/*
 * metadata send function
 *
 * @param raw - raw data buffer_
 * @param rawSize - size of raw data
 *
 */
int Socket::sendMeta(char * raw, int rawSize){
	int indicator = SEND_META;

	memcpy(buffer_, &indicator, sizeof(int));
	memcpy(buffer_+sizeof(int), &rawSize, sizeof(int));
	memcpy(buffer_+2*sizeof(int), raw, rawSize);
	/*int bytecount;
	  if ((bytecount = send(hostSock_, &indicator, sizeof(int), 0)) == -1){
	  fprintf(stderr, "Error sending data %d\n", errno);
	  return -1;
	  }

	  if ((bytecount = send(hostSock_, &rawSize, sizeof(int), 0)) == -1){
	  fprintf(stderr, "Error sending data %d\n", errno);
	  return -1;
	  }*/

	genericSend(buffer_, sizeof(int)*2+rawSize);
	//genericSend(raw, rawSize);
	return 0;
}

/*
 * data send function
 *
 * @param raw - raw data buffer_
 * @param rawSize - size of raw data
 *
 */
int Socket::sendData(char * raw, int rawSize){
	int indicator = SEND_DATA;

	memcpy(buffer_, &indicator, sizeof(int));
	memcpy(buffer_+sizeof(int), &rawSize, sizeof(int));
	memcpy(buffer_+2*sizeof(int), raw, rawSize);
	/*
	   int bytecount;
	   if ((bytecount = send(hostSock_, &indicator, sizeof(int), 0)) == -1){
	   fprintf(stderr, "Error sending data %d\n", errno);
	   return -1;
	   }

	   if ((bytecount = send(hostSock_, &rawSize, sizeof(int), 0)) == -1){
	   fprintf(stderr, "Error sending data %d\n", errno);
	   return -1;
	   }
	 */
	//genericSend(raw, rawSize);
	genericSend(buffer_, sizeof(int)*2+rawSize);
	return 0;
}

/*
 * data download function
 *
 * @param raw - raw data buffer
 * @param rawSize - the size of data to be downloaded
 * @return raw
 */
int Socket::genericDownload(char * raw, int rawSize){

	int bytecount;
	int total = 0;
	while (total < rawSize){
		if ((bytecount = recv(hostSock_, raw+total, rawSize-total, 0)) == -1){
			fprintf(stderr, "Error sending data %d\n", errno);
			return -1;
		}
		total+=bytecount;
	}
	return 0;
}

/*
 * status recv function
 *
 * @param statusList - return int list
 * @param num - num of returned indicator
 *
 * @return statusList
 */
int Socket::getStatus(bool * statusList, int* num){
	//	double timer, split;
	int bytecount;
	int indicator = 0;

	//	timerStart(&timer);
	if ((bytecount = recv(hostSock_, &indicator, 4, 0)) == -1){
		fprintf(stderr, "Error sending data %d\n", errno);
		return -1;
	}
	//	split = timerSplit(&timer);
	//	printf("recv indicator: %lf\n",split);
	if (indicator != GET_STAT){
		fprintf(stderr, "Status wrong %d\n", errno);
		return -1;
	}
	//	timerStart(&timer);
	if ((bytecount = recv(hostSock_, num, 4, 0)) == -1){
		fprintf(stderr, "Error sending data %d\n", errno);
		return -1;
	}
	//	split = timerSplit(&timer);
	//	printf("recv size: %lf\n",split);

	//	timerStart(&timer);
	genericDownload((char*)statusList,sizeof(bool)*(*num));
	//	split = timerSplit(&timer);
	//	printf("recv list: %lf\n",split);
	return 0;
}

/*
 * initiate downloading a file
 *
 * @param filename - the full name of the targeting file
 * @param namesize - the size of the file path
 *
 *
 */
int Socket::initDownload(char* filename, int namesize){
	int indicator = INIT_DOWNLOAD;

	memcpy(buffer_, &indicator, sizeof(int));
	memcpy(buffer_+sizeof(int), &namesize, sizeof(int));
	memcpy(buffer_+2*sizeof(int), filename, namesize);

	/*int bytecount;
	  if ((bytecount = send(hostSock_, &indicator, sizeof(int), 0)) == -1){
	  fprintf(stderr, "Error sending data %d\n", errno);
	  return -1;
	  }

	  if ((bytecount = send(hostSock_, &namesize, sizeof(int), 0)) == -1){
	  fprintf(stderr, "Error sending data %d\n", errno);
	  return -1;
	  }

	  if ((bytecount = send(hostSock_, filename, namesize, 0)) == -1){
	  fprintf(stderr, "Error sending data %d\n", errno);
	  return -1;
	  }*/
	genericSend(buffer_, sizeof(int)*2+namesize);

	return 0;
}

/*
 * download a chunk of data
 *
 * @param raw - the returned raw data chunk
 * @param retSize - the size of returned data chunk
 * @return raw 
 * @return retSize
 */
int Socket::downloadChunk(char * raw, int* retSize){
	int indicator;

	int bytecount;
	if ((bytecount = recv(hostSock_, &indicator, sizeof(int), 0)) == -1){
		fprintf(stderr, "Error receiving data %d\n", errno);
		return -1;
	}

	int size;
	if ((bytecount = recv(hostSock_, &size, sizeof(int), 0)) == -1){
		fprintf(stderr, "Error receiving data %d\n", errno);
		return -1;
	}
	*retSize = ntohl(size);


	genericDownload(raw, *retSize);

	return 0;
}

