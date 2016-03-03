/*
 * exchange.hh
 */

#ifndef __EXCHANGE_HH__
#define __EXCHANGE_HH__

#include <string.h>
#include <map>
#include <string>
#include <utility>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "ssl.hh"
#include "socket.hh"
#include "CryptoPrimitive.hh"
#include "BasicRingBuffer.hh"
#include "HashTable.hh"
#include "encoder.hh"

/* init constants */
#define HASH_SIZE 32
#define COMPUTE_SIZE 128

#define MAX_CMD_LENGTH 65535
#define CHUNK_DATA_SIZE (16*1024)
#define CHUNK_RB_SIZE 1024

#define HASH_TABLE_SIZE (32*1024*1024)
#define SEND_THREADS 1

#define KEY_BATCH_SIZE_MAX (4096*1024*2)
#define KEY_BATCH_SIZE_MIN (2048*1024)
#define BATCH_COUNT 4100

#define VAR_SEG 77
#define FIX_SEG 88
#define CHARA_MIN_HASH 1007
#define CHARA_FIRST_HASH 1008
#define CHARA_FIRST_64 1009


using namespace std;

class KeyEx{
private:
	// total chunk number
	int n_;
    
	// key file object
    BIO* key_;

    // RSA object
    RSA *rsa_;

    // BN ctx
    BN_CTX *ctx_;

    // random number
    BIGNUM *r_;

    // inverse
    BIGNUM *inv_;

    // temp
    BIGNUM *mid_;

    // hash value convert to BN
    BIGNUM *h_;

	// array for record random numbers for each chunk
	BIGNUM **record_;

	// array for SSL structures
	Ssl* sock_[SEND_THREADS];

	int current_;

	int segType_;

	int charaType_;


public:

	// thread handler structure
	typedef struct{
		int index;
		KeyEx* obj;
	}param_keyex;

	// ring buffer item structure
	typedef struct{
		unsigned char data[CHUNK_DATA_SIZE];
		unsigned char key[HASH_SIZE];
		int chunkID;
		int chunkSize;
		int end;
	}Chunk_t;

	// encoder object
	Encoder* encodeObj_;

	// input ring buffer
	RingBuffer<Chunk_t>* inputbuffer_;
	
	// thread id
	pthread_t tid_;

	char current_key[32];

	// crpyto object
	CryptoPrimitive* cryptoObj_;

    /*
     * constructor of key exchange
     *
     *
     *
     */
    KeyEx(Encoder* obj, int securetype, int port, int seg, int chara);

    /*
     * destructor of key exchange
     */
    ~KeyEx();

	/*
	 * read rsa keys from key file
	 */
    bool readKeyFile(char * filename);

	/*
	 * add chunk to input buffer
	 */
	void add(Chunk_t* item);

	/*
	 * procedure for print a big number in hex
	 */
    void printBN(BIGNUM *input);

	/*
	 * procedure for print a buffer content
	 */ 
    void printBuf(unsigned char* buff, int size);

	/*
	 * procedure for remove blind in returned keys 
	 *
	 * @param buff - input big number buffer
	 * @param size - input big number size
	 * @param index - the index of recorded random number r
	 */ 
    void elimination(unsigned char* buff, int size, int index);


	/*
	 * procedure for blind hash value
	 *
	 * @param hash_buf - input buffer storing hash
	 * @param size - the size of input hash
	 * @param ret_buf - the returned buffer holding blinded hash
	 * @param index - the index of record random number r
	 *
	 */ 
    void decoration(unsigned char* hash_buf, int size, unsigned char* ret_buf, int index);

	/*
	 * procedure for verify returned keys
	 *
	 * @param original - the original hash value buffer
	 * @param buff - the buffer contains returned blinded key
	 * @param size - the size of hash value
	 *
	 * @return 0 if verify pass, otherwise means verification fails
	 *
	 */ 
	int verify(unsigned char* original, unsigned char* buff, int size);

	/*
	 * main procedure for init key generation with key server
	 *
	 * @param hash_buf - the buffer holding hash values
	 * @param size - the size of data
	 * @param num - the number of hashes
	 * @param key_buf - the returned buffer contains keys
	 * @param obj - the pointer to crypto object
	 *
	 */ 
	void keyExchange(unsigned char* hash_buf, int size, int num, unsigned char* key_buf, CryptoPrimitive* obj);

	/*
	 * thread handler
	 *
	 */ 
	static void* thread_handler(void* param);


	/*
	 * insert new key to key store
	 * (called when first upload file)
	 */ 
	void new_file(int user, char* filepath, int pathSize);

	/*
	 * update existing file's state cipher
	 * (called when update secrets)
	 */ 
	void update_file(int user, char* filepath, int pathSize);
};

#endif
