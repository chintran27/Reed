/*
 * main test program
 */
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <sys/time.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>

#include "./common/dirreader.hh"
#include "./chunkModule/Chunker.hh"
#include "./encodeModule/encoder.hh"
#include "./encodeModule/decoder.hh"
#include "./encodeModule/CDCodec.hh"
#include "./uploadModule/uploader.hh"
#include "./uploadModule/downloader.hh"
#include "./crypto/CryptoPrimitive.hh"

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


int main(int argc, char *argv[]){
    int userID = atoi(argv[2]);
    int versionID = atoi(argv[3]);

    int total_chunks;
    long size = get_total_file_size(argv[1], &total_chunks);
    read_hashfile(argv[1]);

#ifdef OPENSSL
    if (!CryptoPrimitive::opensslLockSetup()) {
        printf("fail to set up OpenSSL locks\n");

        return 0;
    } 
#endif


    int bufferSize = 128*1024*1024;
    unsigned char * buffer;
    int *chunkEndIndexList, chunkEndIndexListSize = 1024*1024;
    int numOfChunks;
    int n, m, k, r, *kShareIDList;

    int i;

    //fix parameters
    n = 4;
    m = 1;
    k = n-m;
    //use CAONT-RS
    r = k-1;

    int secretSize, shareSize, secretBufferSize = 1024*16, shareBufferSize = 1024*16*n;
    unsigned char *secretBuffer, *shareBuffer;

    buffer = (unsigned char*) malloc (sizeof(unsigned char)*bufferSize);
    memset(buffer, 0, bufferSize);
    chunkEndIndexList = (int*)malloc(sizeof(int)*chunkEndIndexListSize);
    secretBuffer = (unsigned char*)malloc(sizeof(unsigned char) * secretBufferSize);
    shareBuffer = (unsigned char*)malloc(sizeof(unsigned char) * shareBufferSize);
    kShareIDList = (int*)malloc(sizeof(int)*k);
    for (i = 0; i < k; i++) kShareIDList[i] = i;

    decoderObj = new Decoder(CAONT_RS_TYPE, n, m, r, HIGH_SEC_PAIR_TYPE);
    downloaderObj = new Downloader(k,k,userID,decoderObj);

    //====================================================== BEGIN ====

    char name[50];
    sprintf(name, "backup%d_v%d",userID, versionID);
    int namesize = 0;
    while(name[namesize] != '\0'){
        namesize++;
    }
    printf("file name: %s\nname size: %d\ntotal size %ld\ntotal chunks %d\n", name, namesize, size, total_chunks);

    double timer,split,bw;
    FILE * fw = fopen("./decoded_copy","wb");

    decoderObj->setFilePointer(fw);
    decoderObj->setShareIDList(kShareIDList);

    timerStart(&timer);
    downloaderObj->downloadFile(name, namesize, k);
    decoderObj->indicateEnd();
    split = timerSplit(&timer);
    bw = size/1024/1024/split;
    printf("download BW: %lf\n",bw);

    fclose(fw);
    delete downloaderObj;
    delete decoderObj;


    free(buffer);
    free(chunkEndIndexList);
    free(secretBuffer);
    free(shareBuffer);
    free(kShareIDList);

#ifdef OPENSSL
    CryptoPrimitive::opensslLockCleanup();
#endif



    return 0;	


}

