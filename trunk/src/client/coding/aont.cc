#include "aont.hh"

using namespace std;

/*
 * constructor
 *
 * @param cryptoObj - crypto object for hashing and AES
 * @param type - encryption type indicator
 */ 
Aont::Aont(CryptoPrimitive *cryptoObj, int type){

	// initialization
	type_ = type;
	cryptoObj_ = cryptoObj;
	bytesPerWord_ = cryptoObj_->getHashSize();
	alignedBufferSize_ = (4*1024*1024)+64;
	alignedBuffer_ = (unsigned char*)malloc(sizeof(unsigned char)*alignedBufferSize_);
	mask_ = (unsigned char*)malloc(sizeof(unsigned char)*alignedBufferSize_);

	int i;
	for(i = 0; i < alignedBufferSize_; i++){
		alignedBuffer_[i] = i & 0xff;
	}
}

/*
 * destructor
 *
 *
 */ 
Aont::~Aont(){
	free(alignedBuffer_);
}

/*
 * general encode function
 *
 */ 
int Aont::encode(unsigned char* buf, int size, unsigned char* package, int* retSize, unsigned char* key, unsigned char* stub){
	if (type_ == SIM) simple_encode(buf,size,package,retSize,key,stub);
	else adv_encode(buf,size,package,retSize,key,stub);
	return 0;
}

/*
 * general decode function
 *
 */ 
int Aont::decode(unsigned char* package, int size, unsigned char* buf, int* retSize){
	if (type_ == SIM) simple_decode(package,size, buf, retSize);
	else adv_decode(package,size, buf, retSize);
	return 0;
}

/*
 * hashing function
 *
 */ 
int Aont::getHash(unsigned char* buf, int size, unsigned char* ret){
	cryptoObj_->generateHash(buf,size,ret);
	return 1;
}

/*
 * enhanced encryption function
 *
 */ 
int Aont::adv_encode(unsigned char* buf, int size, unsigned char* package, int* retSize, unsigned char* key, unsigned char* stub){
	key_ = key;
	// mask encryption
	cryptoObj_->encryptWithKey(buf, size, key_, package);
	//int coef = 1;

	// concatenate MLK with encrypted package
	memcpy(package+size,key_,32);

	// generate hash of the (encrypted package || key)
	cryptoObj_->generateHash(package, size+32, package+size+32);

	// encrypt mask for second AES-CTR
	cryptoObj_->encryptWithKey(alignedBuffer_, size+64, package+size+32, mask_);

	//coef = 1;
	// XOR mask with package
	//gfObj_.multiply_region.w32(&gfObj_, mask_, package, coef, size+32, 1);

	for(int j = 0; j < size+32; j++){
		package[j] ^= mask_[j];
	}

	int total = size+32;
	while (total > 0){
		total -= 16;
		//coef = 1;
		//gfObj_.multiply_region.w32(&gfObj_, package+total, package+size+32, coef, 16, 1);
		for(int j = 0; j < 16; j++){
			*(package+size+32+j) ^= *(package+total+j);
		}
	}

	(*retSize) = size+bytesPerWord_*2;
	return 1;
}

/*
 * enhanced decryption function
 *
 */ 
int Aont::adv_decode(unsigned char* package, int size, unsigned char* buf, int* retSize){

	//int coef;

	int total = size-32;
	while (total > 0){
		total -= 16;
		//coef = 1;
		//gfObj_.multiply_region.w32(&gfObj_, package+total, package+size-32, coef, 16,1);
		for(int j = 0; j < 16; j++){
			*(package+size-32+j) ^= *(package+total+j);
		}
	}

	cryptoObj_->encryptWithKey(alignedBuffer_, size, package+size-32, mask_);
	//coef = 1;
	//gfObj_.multiply_region.w32(&gfObj_, mask_, package, coef, size-32, 1);
	for(int j = 0; j < size-32; j++){
		package[j] ^= mask_[j];
	}

	unsigned char tmp[32];
	cryptoObj_->generateHash(package, size-32, tmp);


	if(memcmp(tmp, package+size-32, 32)!=0){
		printf("Integrity check failed.\n");
		exit(1);
	}

	cryptoObj_->decryptWithKey(package, size-64, package+size-64, buf);

	(*retSize) = size-64;

	return 1;
}

/*
 * baseline encryption function
 *
 *
 *
 */ 
int Aont::simple_encode(unsigned char* buf, int size, unsigned char* package, int* retSize, unsigned char* key, unsigned char* stub){
	key_ = key;
	// mask encryption
	cryptoObj_->encryptWithKey(alignedBuffer_, size+64, key_, mask_);
	//int coef = 1;

	// move buffer content into package_buf
	memcpy(package,buf,size);
	memset(package+size, 0, 32);

	// XOR mask with package
	//gfObj_.multiply_region.w32(&gfObj_, mask_, package, coef, size+32, 1);
	for(int j = 0; j < size+32; j++){
		package[j] ^= mask_[j];
	}

	// concatenate MLK with encrypted package
	memcpy(package+size+32,key_,32);


	cryptoObj_->generateHash(package, size, package+size);

	(*retSize) = size+bytesPerWord_*2;
	return 1;
}

/*
 * baseline decryption function
 *
 */ 
int Aont::simple_decode(unsigned char* package, int size, unsigned char* buf, int* retSize){

	cryptoObj_->encryptWithKey(alignedBuffer_, size, package+size-32, mask_);
	//int coef = 1;
	//gfObj_.multiply_region.w32(&gfObj_, mask_, package, coef, size-32, 1);
	for(int j = 0; j < size-32; j++){
		package[j] ^= mask_[j];
	}

	char tmp[32];
	memset(tmp,0,32);
	if(memcmp(tmp, package+size-64, 32)!=0){
		printf("Integrity check failed.\n");
		exit(1);
	}

	memcpy(buf, package, size-64);

	(*retSize) = size-64;

	return 1;
}
