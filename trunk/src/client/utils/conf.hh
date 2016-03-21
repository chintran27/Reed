/*
 * conf.hh
 */

#ifndef __CONF_HH__
#define __CONF_HH__

#include <stdio.h>
#include <stdlib.h>

using namespace std;

/*
 * configuration class
 */

class Configuration{
	private:
		/* total number for cloud */
		int numOfStore_;

		/* only single key manager is allowed for current version */
		char keymanagerIP_[20];

		int keymanagerPort_;

		/* only single key store is allowed for current version */
		char keystoreIP_[20];
		
		int keystorePort_;
	public:
		/* constructor */
		Configuration(){
			numOfStore_ = 1;

			strcpy(keymanagerIP_, "192.168.0.26");

			keymanagerPort_ = 1101;

			strcpy(keystoreIP_, "192.168.0.30");

			keystorePort_ = 1104;
		}

		inline int getN() { return numOfStore_; }

		inline char* getkmIP() { return keymanagerIP_; }

		inline int getkmPort() { return keymanagerPort_; }

		inline char* getksIP() { return keystoreIP_; }

		inline int getksPort() { return keystorePort_; }

};

#endif
