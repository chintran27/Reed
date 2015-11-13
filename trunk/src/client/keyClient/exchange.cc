#include "exchange.hh"

using namespace std;

/* time measuring functions */
extern void timerStart(double *t);
extern double timerSplit(const double *t);

/* error printing */
void fatalx(char* s){
	ERR_print_errors_fp(stderr);
	errx(EX_DATAERR, "%.30s", s);
}

void* KeyEx::thread_handler(void* param){
	KeyEx* obj = ((param_keyex*)param)->obj;
	free(param);

	/* check if cache temp file exists */

	entry_t l;
	obj->create_table();
	FILE* fp = fopen("./cache.db","r");
	if (fp != NULL){

		/* read cache entries */
		while (!feof(fp)){
			unsigned char tmp[HASH_SIZE*2];
			int ret = fread(tmp,1,HASH_SIZE*2,fp);
			if (ret < 0){
				printf("fail to load cache file\n");
			}

			memcpy(l.hash,tmp,HASH_SIZE);
			memcpy(l.key,tmp+HASH_SIZE,HASH_SIZE);
			double now;
			timerStart(&now);
			entry_t* e1 = obj->hashtable_->find(&l,now,true);
			memcpy(e1->hash, l.hash, HASH_SIZE);
			memcpy(e1->key, l.key, HASH_SIZE);

		}

		fclose(fp);
		fp = fopen("./cache.db","w");
	}else{

		/* otherwise create cache db file */
		fp = fopen("./cache.db","w");
	}


	/* index recode array */
	int index_rcd[256];
	memset(index_rcd, -1, 256);

	/* hash temp buffer for query hash table */
	unsigned char hash_tmp[32];

	/* batch buffer */
	unsigned char* buffer = (unsigned char*)malloc(sizeof(Chunk_t)*KEY_BATCH_SIZE);

	/* hash buffer */
	unsigned char* hashBuffer = (unsigned char*)malloc(sizeof(unsigned char)*KEY_BATCH_SIZE*HASH_SIZE);

	/* key buffer */
	unsigned char* keyBuffer = (unsigned char*)malloc(sizeof(unsigned char)*KEY_BATCH_SIZE*HASH_SIZE);

	/* main loop for processing batches */
	while(true){
		int itemSize = sizeof(Chunk_t);
		int itemCount = 0;
		int totalCount = 0;
		entry_t e;
		Chunk_t temp;
		double timer;

		int i;
		for (i = 0; i < KEY_BATCH_SIZE; i++){

			/* getting a batch item from input buffer */
			obj->inputbuffer_->Extract(&temp);
			obj->cryptoObj_->generateHash(temp.data, temp.chunkSize, hash_tmp);
			memcpy(e.hash, hash_tmp, HASH_SIZE);
			timerStart(&timer);


			/* see if the hash value exists in hash table */
			entry_t* ret = obj->hashtable_->find(&e, timer, false);

			/* cache hits */

			if (ret != NULL) {
				memcpy(temp.key, ret->key, HASH_SIZE);
				memcpy(buffer+i*itemSize, &temp, itemSize);
				totalCount++;
				fwrite(ret->hash, 1, HASH_SIZE,fp);
				fwrite(ret->key, 1, HASH_SIZE,fp);
				if (temp.end == 1) break;
			}else{
				index_rcd[itemCount] = i;
				memcpy(buffer+i*itemSize, &temp, itemSize);
				memcpy(hashBuffer+i*HASH_SIZE, hash_tmp, HASH_SIZE);
				itemCount ++;
				totalCount ++;
				if (temp.end == 1) break;
			}

			/*
			   memcpy(buffer+i*itemSize, &temp, itemSize);
			   memcpy(hashBuffer+i*HASH_SIZE, hash_tmp, HASH_SIZE);
			   totalCount ++;
			   if (temp.end == 1) break;
			 */

		}

		//	double timer, split;
		//	timerStart(&timer);

		/* if there are some hash value cache miss */
		if (itemCount != 0){

			/* perform key generation */
			obj->keyExchange(hashBuffer, itemCount*COMPUTE_SIZE, itemCount, keyBuffer, obj->cryptoObj_);
		}


		//	split=timerSplit(&timer);
		//	printf("KS delay: %lf\n", split);

		/* get back the keys */
		int j = 0;
		for(i = 0; i < totalCount; i++){
			Encoder::Secret_Item_t input;
			memcpy(&temp,buffer+i*itemSize,itemSize);
			input.type = SHARE_OBJECT;
			if (temp.end == 1) input.type = SHARE_END;

			/* create encoder input object */
			memcpy(input.secret.data, temp.data, temp.chunkSize);

			if (index_rcd[j] == i){
				memcpy(input.secret.key, keyBuffer+j*HASH_SIZE, HASH_SIZE);
				j++;
			}else{
				memcpy(input.secret.key, temp.key, HASH_SIZE);
			}
			//memset(input.secret.key, 0, 32);
			input.secret.secretID = temp.chunkID;
			input.secret.secretSize = temp.chunkSize;
			input.secret.end = temp.end;

			/* add object to encoder input buffer*/
			obj->encodeObj_->add(&input);

			/* add key into hash table */
			memcpy(e.hash, hashBuffer+i*HASH_SIZE, HASH_SIZE);
			memcpy(e.key, keyBuffer+i*HASH_SIZE, HASH_SIZE);

			/* write cache file */
			fwrite(e.hash, 1, HASH_SIZE,fp);
			fwrite(e.key, 1, HASH_SIZE,fp);

			/* update hash entry */
			timerStart(&timer);
			entry_t* e1 = obj->hashtable_->find(&e,timer,true);
			memcpy(e1->hash, e.hash, HASH_SIZE);
			memcpy(e1->key, e.key, HASH_SIZE);


		}

	}
	fclose(fp);
	return NULL;
}

KeyEx::KeyEx(Encoder* obj, int securetype){
	/* init big number var */
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
	cryptoObj_ = new CryptoPrimitive(securetype);
	param_keyex* temp = (param_keyex*)malloc(sizeof(param_keyex));
	temp->index = 0;
	temp->obj = this;
	sock_[0] = new Ssl("192.168.0.26",1101,0);


	/* create key generation thread */
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
	/* convert buffer data into big number */
	BN_bin2bn(buff,size,h_);

	/* compute inverse */
	BN_mod_inverse(inv_, record_[index], rsa_->n, ctx_);

	/* compute (h^(-1))d mod n */
	BN_mod_mul(mid_,h_,inv_,rsa_->n,ctx_);

	/* convert big number back to char data */
	memset(buff,0,size);
	BN_bn2bin(mid_,buff+(size-BN_num_bytes(mid_)));
	//BN_bn2bin(mid_,buff);
}

int KeyEx::verify(unsigned char* original, unsigned char* buff, int size){
	/* convert buffer data into big number */
	BN_bin2bn(buff,size,h_);

	/* compute h^e mod n */
	BN_mod_exp(mid_, h_, rsa_->e, rsa_->n, ctx_);

	/* convert original data into big number */
	BN_bin2bn(original, 32,h_);

	/* compare two numbers */
	return BN_cmp(h_, mid_);
}

void KeyEx::decoration(unsigned char* hash_buf, int size, unsigned char* ret_buf, int index){

	/* random generate 256bits big number */
	BN_pseudo_rand(record_[index], 256, -1, 0);

	/* convert buffer data into big number */
	BN_bin2bn(hash_buf,size,h_);

	/* compute r^e mod n */
	BN_mod_exp(mid_, record_[index], rsa_->e, rsa_->n, ctx_);

	/* compute h*r^e mod n */
	BN_mod_mul(mid_, mid_, h_, rsa_->n, ctx_);

	/* convert the big number back to buffer data */
	memset(ret_buf,0,128);
	BN_bn2bin(mid_, ret_buf+(128-BN_num_bytes(mid_)));
	//BN_bn2bin(mid_,ret_buf);
}

void KeyEx::keyExchange(unsigned char* hash_buf, int size, int num, unsigned char* key_buf, CryptoPrimitive* obj){
	unsigned char buffer[sizeof(int)+size];
	memcpy(buffer, &num, sizeof(int));

	/* blind all hashes */
	int i;
	for(i = 0; i < num; i++){
		decoration(hash_buf+i*HASH_SIZE, HASH_SIZE, buffer+sizeof(int)+i*COMPUTE_SIZE,i);
	}


	/* init SSL connection to key server */
	//	sock_[0] = new Ssl("192.168.0.26",1101,0);

	/* send hashes to key server */
	sock_[0]->genericSend((char*)buffer,size+sizeof(int));

	/* get back the blinded keys */
	sock_[0]->genericDownload((char*)buffer,size);

	//	delete(sock_[0]);


	/* remove the blind in returned keys */
	for (i = 0; i < num; i++){
		elimination(buffer+i*COMPUTE_SIZE,COMPUTE_SIZE,i);

		/* hash 1024bit value back to 256bit */
		obj->generateHash(buffer+i*COMPUTE_SIZE, COMPUTE_SIZE, key_buf+i*HASH_SIZE);
	}


}

void KeyEx::add(Chunk_t* item){
	inputbuffer_->Insert(item, sizeof(Chunk_t));
}

/* hash table function*/
static unsigned int
HashFunc(const char* data, unsigned int n) {
	unsigned int hash = 388650013;
	unsigned int scale = 388650179;
	unsigned int hardener  = 1176845762;
	while (n) {
		hash *= scale;
		hash += *data++;
		n--;
	}
	return hash ^ hardener;
}

/* key hash function */
unsigned int KeyEx::key_hash_fcn(const entry_t* e){
	char tmp[HASH_SIZE];
	memcpy(tmp, e->hash, HASH_SIZE);
	return HashFunc(tmp, HASH_SIZE);
}

/* compare function */
bool KeyEx::key_cmp_fcn(const entry_t* e1, const entry_t* e2){
	int ret = memcmp(e1->hash, e2->hash, HASH_SIZE);
	if(ret == 0) return true; else return false;
}

/* init function */
void KeyEx::key_init_fcn(entry_t* e, void* arg){
	memset(e,0,sizeof(entry_t));
}

/* free function */
void KeyEx::key_free_fcn(entry_t* e, void* arg){
	memset(e,0, sizeof(entry_t));
}

/* hash table create function */
void KeyEx::create_table(){
	hashtable_ = new HashTable<entry_t>("keyTable",
			HASH_TABLE_SIZE,
			7200,
			key_hash_fcn,
			key_cmp_fcn,
			key_init_fcn,
			key_free_fcn,
			this);
}

void KeyEx::update_file(int user, char* filepath, int pathSize){
	int indicator = 2;

	Socket *sock = new Socket("192.168.0.30", 1101, user);
	// SEND 1: (4 byte) state update indicator
	sock->genericSend((char*)&indicator, sizeof(int));

	char* filename = (char*)malloc(sizeof(char)*pathSize+sizeof(int));

	memcpy(filename, &user, 4);
	memcpy(filename+4, filepath, pathSize);

	char namebuffer[32+4];
	int hash_length = 32;

	/* hash file name */
	memcpy(namebuffer, &hash_length, sizeof(int));
	cryptoObj_->generateHash((unsigned char*)filename, pathSize+4, (unsigned char*)namebuffer+4);

	// SEND 2: (36 bytes) send the hashed file name
	sock->genericSend(namebuffer, 36);

	// RECV 3: (4 bytes) download the cipher size
	int length;
	char tmp[4];
	sock->genericDownload(tmp, 4);
	memcpy(&length, tmp, 4);

	char* cipher = (char*)malloc(sizeof(char)*length);

	// RECV 4: (cipher length) download the cipher
	sock->genericDownload(cipher, length);

	FILE *fp = fopen("cipher.cpabe", "w");
	fwrite(cipher, 1, length, fp);
	fclose(fp);
	free(cipher);

	// dec the cipher with private secret
	char cmd[MAX_CMD_LENGTH];

	snprintf(cmd, sizeof(cmd), "cpabe-dec keys/pub_key keys/pk cipher.cpabe");

	system(cmd);

	// read cipher
	fp = fopen("cipher","r");
	fseek(fp, 0, SEEK_END);
	length = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (length != HASH_SIZE){
		printf("key length inconsistent\n");
	}

	// store old key
	char seed[HASH_SIZE];
	fread(seed,1, HASH_SIZE, fp);
	fclose(fp);

	// download meta length
	sock->genericDownload(tmp, sizeof(int));
	memcpy(&length, tmp, sizeof(int));


	// download meta
	char* meta = (char*)malloc(sizeof(char)*length);
	sock->genericDownload(meta, length);


	int ver;
	int id;
	BIGNUM *e = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *s = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	// convert seed into BN
	BN_bin2bn((unsigned char*)seed, HASH_SIZE, s);


	// read ID and state version
	memcpy(&id, meta, sizeof(int));
	memcpy(&ver, meta+sizeof(int), sizeof(int));

	// convert RSA e and n
	BN_bin2bn((unsigned char*)(meta+sizeof(int)*2), COMPUTE_SIZE, e);
	BN_bin2bn((unsigned char*)(meta+sizeof(int)*2+COMPUTE_SIZE), COMPUTE_SIZE, n);


	unsigned char old_key[HASH_SIZE];
	unsigned char new_key[HASH_SIZE];

	// compute old key
	cryptoObj_->generateHash((unsigned char*)seed, HASH_SIZE, old_key);

	// update the state to next version
	BN_mod_exp(s, s, e, n, ctx);

	memset(seed, 0, HASH_SIZE);

	// compute new seed
	BN_bn2bin(s, (unsigned char*)seed+(HASH_SIZE-BN_num_bytes(s)));

	// compute new key
	cryptoObj_->generateHash((unsigned char*)seed, HASH_SIZE, new_key);

	// write new key to file
	fp = fopen("temp_cpabe","w");
	fwrite(seed, 1, HASH_SIZE, fp);
	fclose(fp);

	// write policy
	
	int i;
	int tt = 500;

	fp = fopen("policy","w");

	for (i = 0; i < tt; i++){
		sprintf(cmd, "id = %d", i);

		fwrite(cmd,1,strlen(cmd),fp);

		if(i != tt-1){
			sprintf(cmd, " or ");
			fwrite(cmd,1, 4, fp);
		}
	}
	fclose(fp);

	// load policy
	fp = fopen("policy","r");
	fseek(fp, 0, SEEK_END);
	int pl = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char* p = (char*)malloc(sizeof(char)*(pl+1));
	fread(p, 1, pl, fp);
	fclose(fp);


	p[pl] = '\0';

	// re-encrypt the key state
	snprintf(cmd, sizeof(cmd), "cpabe-enc keys/pub_key temp_cpabe '%s'", p);

	system(cmd);
	

	// get new cipher size
	fp = fopen("temp_cpabe.cpabe","r");
	fseek(fp, 0, SEEK_END);
	length = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char* new_cipher = (char*)malloc(sizeof(char)*length+sizeof(int));

	memcpy(new_cipher, &length, sizeof(int));
	fread(new_cipher+sizeof(int), 1, length, fp);
	fclose(fp);

	// send new key cipher
	sock->genericSend(new_cipher, length+4);

	// update stub
	char name[256];
	sprintf(name, "%s.stub", filepath);
	fp = fopen(name, "r");
	fseek(fp, 0, SEEK_END);
	length = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	unsigned char* v1 = (unsigned char*)malloc(sizeof(unsigned char)*length);
	unsigned char* v2 = (unsigned char*)malloc(sizeof(unsigned char)*length);

	fread(v1, 1, length, fp);
	fclose(fp);

	// decrypt old stub
	cryptoObj_->decryptWithKey(v1, length, old_key, v2);

	// encrypt new stub
	cryptoObj_->encryptWithKey(v2, length, new_key, v1);

	// write new stub
	fp = fopen(name, "w");
	fwrite(v1, length, 1, fp);
	fclose(fp);
//	split = timerSplit(&timer);
//	printf("stub update timer: %lf\n", split);

	delete(sock);
	free(v1);
	free(v2);
	free(new_cipher);
}

void KeyEx::new_file(int user, char* filepath, int pathSize){
	BIGNUM *s = BN_new();
	BN_pseudo_rand(s, 256, -1, 0);

	//send indicator
	int indicator = 1;

	Socket *sock = new Socket("192.168.0.30", 1101, user);

	sock->genericSend((char*)&indicator, sizeof(int));

	// send file name

	char* filename = (char*)malloc(sizeof(char)*pathSize+sizeof(int));

	memcpy(filename, &user, sizeof(int));
	memcpy(filename+sizeof(int), filepath, pathSize);

	char namebuffer[HASH_SIZE+sizeof(int)];
	int hash_length = HASH_SIZE;

	// hash file name
	memcpy(namebuffer, &hash_length, sizeof(int));
	cryptoObj_->generateHash((unsigned char*)filename, pathSize+sizeof(int), (unsigned char*)namebuffer+sizeof(int));

	// send hashed file name to server
	sock->genericSend(namebuffer, HASH_SIZE+sizeof(int));

	// compute key cipher
	unsigned char buffer[HASH_SIZE];
	memset(buffer, 0, HASH_SIZE);

	BN_bn2bin(s, buffer+(HASH_SIZE-BN_num_bytes(s)));

	// compute key
	unsigned char key[HASH_SIZE];
	cryptoObj_->generateHash(buffer, HASH_SIZE, key);

	memcpy(current_key, key, HASH_SIZE);

	// cpabe encryption
	FILE *fp = fopen("temp_cpabe","w");
	fwrite(buffer, 1, HASH_SIZE, fp);
	fclose(fp);
	char cmd[256];

	snprintf(cmd, sizeof(cmd), "cpabe-enc keys/pub_key temp_cpabe 'id = 0'");

	system(cmd);

	// read cipher
	fp = fopen("temp_cpabe.cpabe","r");
	fseek(fp, 0, SEEK_END);
	int length = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char* cipher = (char*)malloc(sizeof(char)*length+sizeof(int));

	memcpy(cipher, &length, sizeof(int));
	fread(cipher+sizeof(int), 1, length, fp);
	fclose(fp);

	// send key cipher
	sock->genericSend(cipher, length+sizeof(int));

	// record file meta for key regression
	int meta_size = sizeof(int)*2+COMPUTE_SIZE*2;
	char* meta = (char*)malloc(sizeof(char)*meta_size+sizeof(int));

	memset(meta,0,meta_size+sizeof(int));
	memcpy(meta, &meta_size, sizeof(int));

	int ver = 0;
	memcpy(meta+sizeof(int), &user, sizeof(int));
	memcpy(meta+sizeof(int)*2, &ver, sizeof(int));

	BN_bn2bin(rsa_->e, (unsigned char*)meta+sizeof(int)*3+(COMPUTE_SIZE-BN_num_bytes(rsa_->e)));
	BN_bn2bin(rsa_->n, (unsigned char*)meta+sizeof(int)*3+COMPUTE_SIZE+(COMPUTE_SIZE-BN_num_bytes(rsa_->n)));

	// send meta
	sock->genericSend(meta, meta_size+sizeof(int));

	delete(sock);
}	
