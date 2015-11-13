/*
 * main test program
 */
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <sys/time.h>

#include "chunker.hh"
#include "encoder.hh"
#include "decoder.hh"
#include "CDCodec.hh"
#include "uploader.hh"
#include "downloader.hh"
#include "CryptoPrimitive.hh"
#include "exchange.hh"
#include "conf.hh"

extern "C"{
#include "libhashfile.h"
}


#define MAIN_CHUNK

using namespace std;

Chunker* chunkerObj;
Decoder* decoderObj;
Encoder* encoderObj;
Uploader* uploaderObj;
CryptoPrimitive* cryptoObj;
CDCodec* cdCodecObj;
Downloader* downloaderObj;
Configuration* confObj;
KeyEx* keyObj;

struct hashfile_handle *handle;
const struct chunk_info *ci;

long get_total_file_size(char* hashfile_name, int* chunkNum){
	struct hashfile_handle *tmp = hashfile_open(hashfile_name);
	*chunkNum = hashfile_numchunks(tmp);
	return hashfile_numbytes(tmp);
}

int read_hashfile(char* hashfile_name){
	handle = hashfile_open(hashfile_name);
	return 1;
}

void timerStart(double *t){
	struct timeval tv;
	gettimeofday(&tv, NULL);
	*t = (double)tv.tv_sec+(double)tv.tv_usec*1e-6;
}

double timerSplit(const double *t){
	struct timeval tv;
	double cur_t;
	gettimeofday(&tv, NULL);
	cur_t = (double)tv.tv_sec + (double)tv.tv_usec*1e-6;
	return (cur_t - *t);
}

void usage(char *s){
	printf("usage: ./BACKUP [tracename] [userID] [version]\n- [tracename]: full path of the trace file;\n- [userID]: use ID of current client;\n- [version]: version number\n");
	exit(1);
}

int main(int argc, char *argv[]){
	/* argument test */
	if (argc != 4) usage(NULL);

	/* get options */
	int userID = atoi(argv[2]);
	int versionID = atoi(argv[3]);
	//char* opt = argv[3];
	//char* securesetting = argv[4];

	/* read file */
	int total_chunks;
	long size = get_total_file_size(argv[1], &total_chunks);
	read_hashfile(argv[1]);
	//FILE * fin = fopen(argv[1],"r");

	/* get file size */
	//fseek(fin,0,SEEK_END);
	//long size = ftell(fin);	
	//fseek(fin,0,SEEK_SET);

	unsigned char * buffer;
	int *chunkEndIndexList;
	int n, m, k, r, *kShareIDList;

	int i;

	/* initialize openssl locks */
	if (!CryptoPrimitive::opensslLockSetup()) {
		printf("fail to set up OpenSSL locks\n");

		return 0;
	}

	confObj = new Configuration();
	/* fix parameters here */
	/* TO DO: load from config file */
	n = confObj->getN();
	m = confObj->getM();
	k = confObj->getK();
	r = confObj->getR();

	/* initialize buffers */
	int bufferSize = confObj->getBufferSize();
	int chunkEndIndexListSize = confObj->getListSize();
	int secretBufferSize = confObj->getSecretBufferSize();
	int shareBufferSize = confObj->getShareBufferSize();

	unsigned char *secretBuffer, *shareBuffer;
	unsigned char tmp[secretBufferSize];
	memset(tmp,0,secretBufferSize);
	buffer = (unsigned char*) malloc (sizeof(unsigned char)*bufferSize);
	memset(buffer,0, bufferSize);
	chunkEndIndexList = (int*)malloc(sizeof(int)*chunkEndIndexListSize);
	secretBuffer = (unsigned char*)malloc(sizeof(unsigned char) * secretBufferSize);
	shareBuffer = (unsigned char*)malloc(sizeof(unsigned char) * shareBufferSize);

	/* initialize share ID list */
	kShareIDList = (int*)malloc(sizeof(int)*k);
	for (i = 0; i < k; i++) kShareIDList[i] = i;

	char name[50];
	sprintf(name, "backup%d_v%d", userID, versionID);
	/* full file name process */
	int namesize = 0;
	while(name[namesize] != '\0'){
		namesize++;
	}
	//namesize++;

	/* parse secure parameters */
	int securetype = HIGH_SEC_PAIR_TYPE;
	//int securetype = LOW_SEC_PAIR_TYPE;
	//if(strncmp(securesetting,"HIGH", 4) == 0) securetype = HIGH_SEC_PAIR_TYPE;

	/* ===============BEGIN================================ */

	/* object initialization */
	uploaderObj = new Uploader(n,n,userID);
	encoderObj = new Encoder(CAONT_RS_TYPE, n, m, r, securetype, uploaderObj);
	encoderObj->setTotalChunk(total_chunks);
	keyObj = new KeyEx(encoderObj, userID);
	keyObj->readKeyFile("./keys/public.pem");
	chunkerObj = new Chunker(VAR_SIZE_TYPE);
	double timer,split,bw;
	timerStart(&timer);

	/* init the file header */
	Encoder::Secret_Item_t header;
	header.type = 1;
	memcpy(header.file_header.data, argv[1], namesize);
	header.file_header.fullNameSize = namesize;
	header.file_header.fileSize = size;

	/* add the file header to encoder */
	encoderObj->add(&header);

	/* main loop for adding chunks */
	int totalSize = 0;
	int chunkCount = 0;
	int uploadedChunkNum = 0;
	int tchunk = 0;
	long tsize = 0;
	while (1){
		int ret = hashfile_next_file(handle);
		if(ret <= 0){ 
			break; 
		}

		int file_size = hashfile_curfile_size(handle);
		int chunks = hashfile_curfile_numchunks(handle);
		if(file_size <= 0){
			continue;
		}

		for(int j = 0; j < chunks; j++){
			ci = hashfile_next_chunk(handle);
			tsize += ci->size;

			if(totalSize + (int)ci->size > bufferSize){
				
				int count = 0;
				int preEnd = -1;
				while (count < chunkCount){
					KeyEx::Chunk_t input;
					input.chunkID = uploadedChunkNum;
					input.chunkSize = chunkEndIndexList[count]-preEnd;
					memcpy(input.data, buffer+preEnd+1, input.chunkSize);

					input.end = 0;
					if(uploadedChunkNum+1 == total_chunks) input.end = 1;

					keyObj->add(&input);

					uploadedChunkNum++;
					preEnd = chunkEndIndexList[count];
					count++;
				}
				memset(buffer, 0, bufferSize);
				chunkCount = 0;
				totalSize = 0;
			}

			memcpy(buffer+totalSize, ci->hash, 6);
			totalSize += (int)ci->size;
			chunkEndIndexList[chunkCount] = totalSize -1;
			chunkCount ++;
			tchunk ++;
		}
	}

	/* upload remaining part*/
	int count = 0;
	int preEnd = -1;
	while(count < chunkCount){
		KeyEx::Chunk_t input;
		input.chunkID = uploadedChunkNum;
		input.chunkSize = chunkEndIndexList[count] - preEnd;
		memcpy(input.data, buffer+preEnd+1, input.chunkSize);
		input.end = 0;
		if(uploadedChunkNum+1 == total_chunks) input.end = 1;

		keyObj->add(&input);
		uploadedChunkNum++;
		preEnd = chunkEndIndexList[count];
		count++;
	}

	long long tt, unique;
	tt = 0;
	unique = 0;
	uploaderObj->indicateEnd(&tt, &unique);
	split = timerSplit(&timer);

	bw = size/1024/1024/(split);
	printf("%lf\t%lld\t%lld\n",bw, tt, unique);

	delete uploaderObj;
	delete chunkerObj;
	delete encoderObj;



	free(buffer);
	free(chunkEndIndexList);
	free(secretBuffer);
	free(shareBuffer);
	free(kShareIDList);
	CryptoPrimitive::opensslLockCleanup();

	return 0;	


}

