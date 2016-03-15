#include "exchange.hh"

using namespace std;

extern void timerStart(double *t);
extern double timerSplit(const double *t);

void fatalx(char* s){
	ERR_print_errors_fp(stderr);
	errx(EX_DATAERR, "%.30s", s);
}

void* KeyEx::thread_handler(void* param){
	KeyEx* obj = ((param_keyex*)param)->obj;
	free(param);

	map<string, string> hashtable;


	//int index_rcd[256];
	unsigned char hash_tmp[32];
	unsigned char* buffer = (unsigned char*)malloc(sizeof(Chunk_t)*KEY_BATCH_SIZE);
	unsigned char* hashBuffer = (unsigned char*)malloc(sizeof(unsigned char)*KEY_BATCH_SIZE*HASH_SIZE);
	unsigned char* keyBuffer = (unsigned char*)malloc(sizeof(unsigned char)*KEY_BATCH_SIZE*HASH_SIZE);

	while(true){
		int itemSize = sizeof(Chunk_t);
		int itemCount = 0;
		Chunk_t temp;

		int i;
		for (i = 0; i < KEY_BATCH_SIZE; i++){
			obj->inputbuffer_->Extract(&temp);
			memcpy(buffer+i*itemSize, &temp, itemSize);
			obj->cryptoObj_->generateHash(temp.data, temp.chunkSize, hashBuffer+i*HASH_SIZE);
			memcpy(hash_tmp, hashBuffer+i*HASH_SIZE, HASH_SIZE);
			//obj->cryptoObj_->generateHash(temp.data, temp.chunkSize, hash_tmp);
			string k((char*)hash_tmp, HASH_SIZE);
			string v(hashtable[k]);
			

			if (!v.empty()) {
				printf("entry exists\n");
			}

			itemCount ++;
			if (temp.end == 1) break;
		}

	//	double timer, split;
	//	timerStart(&timer);
		obj->keyExchange(hashBuffer, itemCount*COMPUTE_SIZE, itemCount, keyBuffer, obj->cryptoObj_);
	//	split=timerSplit(&timer);
	//	printf("KS delay: %lf\n", split);


		for(i = 0; i < itemCount; i++){
			Encoder::Secret_Item_t input;
			memcpy(&temp,buffer+i*itemSize,itemSize);
			input.type = SHARE_OBJECT;
			if (temp.end == 1) input.type = SHARE_END;

			memcpy(input.secret.data, temp.data, temp.chunkSize);
			memcpy(input.secret.key, keyBuffer+i*HASH_SIZE, HASH_SIZE);
			//memset(input.secret.key, 0, 32);
			input.secret.secretID = temp.chunkID;
			input.secret.secretSize = temp.chunkSize;
			input.secret.end = temp.end;

			obj->encodeObj_->add(&input);

			string k((char*)hashBuffer+i*HASH_SIZE, HASH_SIZE);
			string v((char*)keyBuffer+i*HASH_SIZE, HASH_SIZE);
			
			hashtable[k] = v;
		}
	}
}

KeyEx::KeyEx(Encoder* obj){
	rsa_ = RSA_new();
	ctx_ = BN_CTX_new();
	r_ = BN_new();
	inv_ = BN_new();
	mid_ = BN_new();
	h_ = BN_new();
	n_ = KEY_BATCH_SIZE;
	encodeObj_ = obj;

	record_ = (BIGNUM**)malloc(sizeof(BIGNUM*)*n_);
	for (int i = 0; i < n_; i++) record_[i] = BN_new();

	/* initialization */
	inputbuffer_ = new RingBuffer<Chunk_t>(CHUNK_RB_SIZE,true,1);
	cryptoObj_ = new CryptoPrimitive(SHA256_TYPE);
	param_keyex* temp = (param_keyex*)malloc(sizeof(param_keyex));
	temp->index = 0;
	temp->obj = this;

	pthread_create(&tid_,0,&thread_handler,(void*)temp);

}

KeyEx::~KeyEx(){

	RSA_free(rsa_);
	BN_CTX_free(ctx_);
	BN_clear_free(r_);
	BN_clear_free(inv_);
	BN_clear_free(mid_);
	BN_clear_free(h_);
	for (int i = 0; i < n_; i++) BN_clear_free(record_[i]);
	free(record_);
	delete(inputbuffer_);
	delete(cryptoObj_);
}

bool KeyEx::readKeyFile(char* filename){
	key_ = BIO_new_file(filename, "r");
	PEM_read_bio_RSAPublicKey(key_,&rsa_, NULL, NULL);
	return true;
}

void KeyEx::printBN(BIGNUM *input){
	char * str = BN_bn2hex(input);
	printf("%s\n",str);

}

void KeyEx::printBuf(unsigned char* buff, int size){
	BN_bin2bn(buff,size,mid_);
	char * str = BN_bn2hex(mid_);
	printf("%s\n",str);

}

void KeyEx::elimination(unsigned char* buff, int size, int index){
	BN_bin2bn(buff,size,h_);

	BN_mod_inverse(inv_, record_[index], rsa_->n, ctx_);
	BN_mod_mul(mid_,h_,inv_,rsa_->n,ctx_);
	memset(buff,0,size);
	BN_bn2bin(mid_,buff+(size-BN_num_bytes(mid_)));
	//BN_bn2bin(mid_,buff);
}

int KeyEx::verify(unsigned char* original, unsigned char* buff, int size){
	BN_bin2bn(buff,size,h_);
	BN_mod_exp(mid_, h_, rsa_->e, rsa_->n, ctx_);
	BN_bin2bn(original, 32,h_);
	return BN_cmp(h_, mid_);
}

void KeyEx::decoration(unsigned char* hash_buf, int size, unsigned char* ret_buf, int index){
	BN_pseudo_rand(record_[index], 256, -1, 0);

	BN_bin2bn(hash_buf,size,h_);

	BN_mod_exp(mid_, record_[index], rsa_->e, rsa_->n, ctx_);
	BN_mod_mul(mid_, mid_, h_, rsa_->n, ctx_);
	memset(ret_buf,0,128);
	BN_bn2bin(mid_, ret_buf+(128-BN_num_bytes(mid_)));
	//BN_bn2bin(mid_,ret_buf);
}

void KeyEx::keyExchange(unsigned char* hash_buf, int size, int num, unsigned char* key_buf, CryptoPrimitive* obj){
	unsigned char buffer[sizeof(int)+size];
	memcpy(buffer, &num, sizeof(int));

	int i;
	for(i = 0; i < num; i++){
		decoration(hash_buf+i*HASH_SIZE, HASH_SIZE, buffer+sizeof(int)+i*COMPUTE_SIZE,i);
	}


	sock_ = new Ssl("192.168.0.26",1101,0);
	//sock_ = new Socket("192.168.0.26",1101,0);
	sock_->genericSend((char*)buffer,size+sizeof(int));
	sock_->genericDownload((char*)buffer,size);

	for (i = 0; i < num; i++){
		elimination(buffer+i*COMPUTE_SIZE,COMPUTE_SIZE,i);
		obj->generateHash(buffer+i*COMPUTE_SIZE, COMPUTE_SIZE, key_buf+i*HASH_SIZE);
	}


}

void KeyEx::add(Chunk_t* item){
	inputbuffer_->Insert(item, sizeof(Chunk_t));
}
