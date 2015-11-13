/*
 * aont.hh
 */

#ifndef __AONT_HH__
#define __AONT_HH__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "CryptoPrimitive.hh"

extern "C" {
#include "gf_complete.h"
}

// chunk size
#define CHUNK_SIZE (4*1024*1024)

// indicator SIM: baseline, AVD: enhanced.
#define SIM 0
#define AVD 1

#define REED_TYPE 7

using namespace std;

class Aont{
private:
	// encryption type indicator
    int type_;
    
	// crypto Obj
    CryptoPrimitive *cryptoObj_;

    // word size
    int bytesPerWord_;

    // aont key
    unsigned char *key_;

    // buffer for storing aligned data and its size
    int alignedBufferSize_;
    unsigned char *alignedBuffer_;

	// mask bufer
    unsigned char *mask_;

    // gf_t object
    gf_t gfObj_;

public:

	/* constructor
	 *
	 * @param cryptoObj - crypto object for hashing and AES
	 * @param type - encryption type indicator
	 *
	 */
    Aont(CryptoPrimitive *cryptoObj, int type);

	/*
	 * destructor
	 */ 
    ~Aont();

	/*
	 * general encode function
	 *
	 * @param buf - input buffer
	 * @param size - input size
	 * @param package - output buffer
	 * @param retSize - output size
	 * @param key - encryption key
	 * @param stub - output stub (64byte)
	 */ 
    int encode(unsigned char* buf, int size, unsigned char* package, int* retSize, unsigned char* key, unsigned char* stub);

	/*
	 * general decode function
	 *
	 * @param package - input buffer
	 * @param size - input size
	 * @param buf - output buffer
	 * @param retSize - output size
	 *
	 */ 
    int decode(unsigned char* package, int size, unsigned char* buf, int* retSize);


	/*
	 * baseline encode function
	 *
	 * @param buf - input buffer
	 * @param size - input size
	 * @param package - output buffer
	 * @param retSize - output size
	 * @param key - encryption key
	 * @param stub - output stub (64byte)
	 */ 
    int simple_encode(unsigned char* buf, int size, unsigned char* package, int* retSize, unsigned char* key, unsigned char* stub);

	/*
	 * baseline decode function
	 *
	 * @param package - input buffer
	 * @param size - input size
	 * @param buf - output buffer
	 * @param retSize - output size
	 *
	 */ 
    int simple_decode(unsigned char* package, int size, unsigned char* buf, int* retSize);

	/*
	 * enhanced encode function
	 *
	 * @param buf - input buffer
	 * @param size - input size
	 * @param package - output buffer
	 * @param retSize - output size
	 * @param key - encryption key
	 * @param stub - output stub (64byte)
	 */ 
    int adv_encode(unsigned char* buf, int size, unsigned char* package, int* retSize, unsigned char* key, unsigned char* stub);

	/*
	 * enhanced decode function
	 *
	 * @param package - input buffer
	 * @param size - input size
	 * @param buf - output buffer
	 * @param retSize - output size
	 *
	 */ 
    int adv_decode(unsigned char* package, int size, unsigned char* buf, int* retSize);

	/*
	 * hashing function
	 *
	 * @param buf - input buffer
	 * @param size - input size
	 * @param ret - returned hash value
	 */ 
    int getHash(unsigned char* buf, int size, unsigned char* ret);

};

#endif
