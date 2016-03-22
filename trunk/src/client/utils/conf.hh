/*
 * conf.hh
 */

#ifndef __CONF_HH__
#define __CONF_HH__

#include <stdio.h>
#include <stdlib.h>

#define MAX_IP_SIZE 20

using namespace std;

/*
 * configuration class
 */

class Configuration{
	private:
		/* total number for cloud */
		int numOfStore_;

		/* list for data store IPs */
		char** datastoreIP_;

		/* list for data store ports */
		int* datastorePort_;

		/* only single key manager is allowed for current version */
		char keymanagerIP_[MAX_IP_SIZE];

		int keymanagerPort_;

		/* only single key store is allowed for current version */
		char keystoreIP_[MAX_IP_SIZE];
		
		int keystorePort_;
	public:
		/* constructor */
		Configuration(){

			/* SET HERE! total number of data stores */
			numOfStore_ = 1;

			/* initialization based on numOfStore_ */
			datastoreIP_ = (char**)malloc(sizeof(char*)*numOfStore_);

			for(int i = 0; i < numOfStore_; i++){
				datastoreIP_[i] = (char*)malloc(sizeof(char)*MAX_IP_SIZE);
			}

			datastorePort_ = (int*)malloc(sizeof(int)*numOfStore_);
			/* initialization done */

			/* SET HERE! data store IPs and Ports */
			strcpy(datastoreIP_[0], "192.168.0.30");
			datastorePort_[0] = 1101;

			/* If you have numOfStore_ > 1, please set each data store
			 * one by one as following examples 
			 *
			 * */

			// strcpy(datastoreIP_[1], "192.168.0.31");
			// datastorePort_[1] = 1101;
			
			// strcpy(datastoreIP_[2], "192.168.0.32");
			// datastorePort_[2] = 1101;
			
			// strcpy(datastoreIP_[3], "192.168.0.33");
			// datastorePort_[3] = 1101;
			

			/* SET HERE! key manager IP */
			strcpy(keymanagerIP_, "192.168.0.26");

			/* SET HERE! key manager Port */
			keymanagerPort_ = 1101;

			/* SET HERE! key store IP */
			strcpy(keystoreIP_, "192.168.0.30");

			/* SET HERE! key store Port */
			keystorePort_ = 1101;
		}

		~Configuration(){
			for(int i = 0; i < numOfStore_; i++){
				free(datastoreIP_[i]);
			}
			free(datastoreIP_);
			free(datastorePort_);
		}

		inline int getN() { return numOfStore_; }

		inline char* getkmIP() { return keymanagerIP_; }

		inline int getkmPort() { return keymanagerPort_; }

		inline char* getksIP() { return keystoreIP_; }

		inline int getksPort() { return keystorePort_; }

		inline char* getdsIP(int index) { return datastoreIP_[index]; }
		
		inline int getdsPort(int index) { return datastorePort_[index]; }

};

#endif
