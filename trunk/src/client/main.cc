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
	printf("usage: ./CLIENT [filename] [userID] [action] [secutiyType]\n- [filename]: full path of the file;\n- [userID]: use ID of current client;\n- [action]: [-u] upload; [-d] download;\n- [securityType]: [HIGH] AES-256 & SHA-256; [LOW] AES-128 & SHA-1\n");
	exit(1);
}

int main(int argc, char *argv[]){
	/* argument test */
	if (argc != 5) usage(NULL);

	/* get options */
	int userID = atoi(argv[2]);
	char* opt = argv[3];
	char* securesetting = argv[4];

	/* read file */
	FILE * fin = fopen(argv[1],"r");

	/* get file size */
	fseek(fin,0,SEEK_END);
	long size = ftell(fin);	
	fseek(fin,0,SEEK_SET);

	unsigned char * buffer;
	int *chunkEndIndexList;
	int numOfChunks;
	int n, m, k, r, *kShareIDList;

	int i;

	/* initialize openssl locks */
	if (!CryptoPrimitive::opensslLockSetup()) {
		printf("fail to set up OpenSSL locks\n");

		return 0;
	}

	confObj = new Configuration();
	/* load from config file 
	 *
	 * Get the total number of data stores
	 *
	 * */
	n = confObj->getN();

	/* initialize buffers 
	 *
	 * Based on CDStore settings: https://github.com/chintran27/CDStore
	 *
	 * Buffer Size: 1GB
	 * Chunk Index List Size: 1024KB
	 * Secret Buffer Size for each secret object: 16KB
	 * Share Buffer Size for aggregated cipher block: numOfStore*16KB
	 *
	 * m, k, r are deprecate in REED
	 *
	 * */

	m = 1; // @deprecate
	k = n - m; // @deprecate
	r = k - 1; // @deprecate

	int bufferSize = 1024*1024*1024;
	int chunkEndIndexListSize = 1024*1024;
	int secretBufferSize = 16*1024;
	int shareBufferSize = n*16*1024;

	unsigned char *secretBuffer, *shareBuffer;
	unsigned char tmp[secretBufferSize];
	memset(tmp,0,secretBufferSize);
	long zero = 0;
	buffer = (unsigned char*) malloc (sizeof(unsigned char)*bufferSize);
	chunkEndIndexList = (int*)malloc(sizeof(int)*chunkEndIndexListSize);
	secretBuffer = (unsigned char*)malloc(sizeof(unsigned char) * secretBufferSize);
	shareBuffer = (unsigned char*)malloc(sizeof(unsigned char) * shareBufferSize);

	/* initialize share ID list */
	kShareIDList = (int*)malloc(sizeof(int)*k);
	for (i = 0; i < k; i++) kShareIDList[i] = i;

	/* full file name process */
	int namesize = 0;
	while(argv[1][namesize] != '\0'){
		namesize++;
	}
	namesize++;

	/* parse secure parameters */
	int securetype = LOW_SEC_PAIR_TYPE;
	if(strncmp(securesetting,"HIGH", 4) == 0) securetype = HIGH_SEC_PAIR_TYPE;

	/* upload procedure */
	if (strncmp(opt,"-u",2) == 0 || strncmp(opt, "-a", 2) == 0){

		/* object initialization */
		uploaderObj = new Uploader(n,n,userID, confObj);
		encoderObj = new Encoder(CAONT_RS_TYPE, n, m, r, securetype, uploaderObj);
		keyObj = new KeyEx(encoderObj, securetype, confObj->getkmIP(), confObj->getksIP(), confObj->getksPort());
		keyObj->readKeyFile("./keys/public.pem");

		keyObj->new_file(userID, argv[1], namesize);

		chunkerObj = new Chunker(VAR_SIZE_TYPE);
		double timer,split,bw, timer2, split2;
		double total_t = 0;
		timerStart(&timer2);

		/* init the file header */
		Encoder::Secret_Item_t header;
		header.type = 1;
		memcpy(header.file_header.data, argv[1], namesize);
		header.file_header.fullNameSize = namesize;
		header.file_header.fileSize = size;

		/* add the file header to encoder */
		encoderObj->add(&header);

		/* main loop for adding chunks */
		long total = 0;
		int totalChunks = 0;
		while (total < size){
			timerStart(&timer);

			/* read in a batch of data in buffer */
			int ret = fread(buffer,1,bufferSize,fin);

			/* perform chunking on the data */
			chunkerObj->chunking(buffer,ret,chunkEndIndexList,&numOfChunks);
			split = timerSplit(&timer);
			total_t += split;

			int count = 0;
			int preEnd = -1;
			encoderObj->setTotalChunk(numOfChunks);

			/* adding chunks */
			while(count < numOfChunks){

				/* create structure */
				KeyEx::Chunk_t input;
				input.chunkID = totalChunks;
				input.chunkSize = chunkEndIndexList[count] - preEnd;
				memcpy(input.data, buffer+preEnd+1, input.chunkSize);

				/* zero counting */
				if(memcmp(buffer+preEnd+1, tmp, input.chunkSize) == 0){
					zero += input.chunkSize;
				}

				/* set end indicator */
				input.end = 0;
				if(ret+total == size && count+1 == numOfChunks){
					input.end = 1;
				}

				/* add chunk to key client */
				keyObj->add(&input);


				/* increase counter */
				totalChunks++;
				preEnd = chunkEndIndexList[count];
				count++;
			}
			total+=ret;
		}
		long long tt, unique;
		tt = 0;
		unique = 0;
		uploaderObj->indicateEnd(&tt, &unique);

		// encrypt stub file
		encoderObj->encStub(argv[1], keyObj->current_key);

		// upload stub file to server
		uploaderObj->uploadStub(argv[1]);

		//encoderObj->indicateEnd();
		split2 = timerSplit(&timer2);

		bw = size/1024/1024/(split2-total_t);
		//printf("%lf\t%lld\t%lld\t%ld\n",bw, tt, unique, zero);
		printf("%lf\t%lf\t%lld\t%lld\t%ld\n",bw,(split2-total_t), tt, unique, zero);
		delete uploaderObj;
		delete chunkerObj;
		delete encoderObj;
	}


	/* download procedure */
	if (strncmp(opt,"-d",2) == 0 || strncmp(opt, "-a", 2) == 0){
		/* init objects */
		decoderObj = new Decoder(CAONT_RS_TYPE, n, m, r, securetype, argv[1]);
		downloaderObj = new Downloader(n,n,userID,decoderObj,confObj);
		double timer,split,bw;
		FILE * fw = fopen("./decoded_copy","wb");

		decoderObj->setFilePointer(fw);
		decoderObj->setShareIDList(kShareIDList);

		timerStart(&timer);

		/* download stub first */
		downloaderObj->downloadStub(argv[1]);

		/* start download procedure */
		downloaderObj->downloadFile(argv[1], namesize, n);

		/* see if download finished */
		decoderObj->indicateEnd();
		split = timerSplit(&timer);
		bw = size/1024/1024/split;
		printf("%lf\t%lf\n",bw, split);

		fclose(fw);
		delete downloaderObj;
		delete decoderObj;
	}


	if (strncmp(opt,"-r",2) == 0){
		double timer,split,bw;
		timerStart(&timer);
		uploaderObj = new Uploader(n,n,userID,confObj);
		encoderObj = new Encoder(CAONT_RS_TYPE, n, m, r, securetype, uploaderObj);
		keyObj = new KeyEx(encoderObj, securetype, confObj->getkmIP(), confObj->getksIP(), confObj->getksPort());
		keyObj->readKeyFile("./keys/public.pem");

		keyObj->update_file(userID, argv[1], namesize);
		split = timerSplit(&timer);
		bw = size/1024/1024/split;
		printf("%lf\t%lf\n", bw, split);

		/*
		   int ret = fread(buffer,1,bufferSize,fin);
		   cryptoObj = new CryptoPrimitive(securetype);

		   unsigned char key[32];
		   memset(key, 0, 32);

		   int s = ret;
		   if (ret % 16 != 0) s = ((ret / 16)+1)*16;
		   cryptoObj->encryptWithKey(buffer, s, key, buffer);
		   cryptoObj->decryptWithKey(buffer,s,key,buffer);
		 */

	}


	free(buffer);
	free(chunkEndIndexList);
	free(secretBuffer);
	free(shareBuffer);
	free(kShareIDList);
	CryptoPrimitive::opensslLockCleanup();

	fclose(fin);
	return 0;	


}

