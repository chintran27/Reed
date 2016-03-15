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
      int n_;

      /* fault tolerance degree */
      int m_;

      /* k = n - m */
      int k_;

      /* security degree */
      int r_;

      /* secret buffer size */
      int secretBufferSize_;

      /* share buffer size */
      int shareBufferSize_;

      /* buffer size */
      int bufferSize_;

      /* chunk end list size */
      int chunkEndIndexListSize_;

	  char* keymanagerIP_;

	  int keymanagerPort_;

	  char* keystoreIP_;

	  int keystorePort_;
  public:
      /* constructor */
      Configuration(){
        n_ = 1;
        m_ = 1;
        k_ = n_ - m_;
        r_ = k_ - 1;
        secretBufferSize_ = 16*1024;
        shareBufferSize_ = 16*1024*n_;
        bufferSize_ = 1024*1024*1024;
        chunkEndIndexListSize_ = 1024*1024;

		keymanagerIP_ = "192.168.0.26";
		keymanagerPort_ = 1101;

		keystoreIP_ = "192.168.0.30";
		keystorePort_ = 1104;
      }

      inline int getN() { return n_; }

      inline int getM() { return m_; }

      inline int getK() { return k_; }

      inline int getR() { return r_; }

      inline int getSecretBufferSize() { return secretBufferSize_; }

      inline int getShareBufferSize() { return shareBufferSize_; }

      inline int getBufferSize() { return bufferSize_; }

      inline int getListSize() { return chunkEndIndexListSize_; }

	  inline char* getkmIP() { return keymanagerIP_; }
	  inline int getkmPort() { return keymanagerPort_; }
	  inline char* getksIP() { return keystoreIP_; }
	  inline int getksPort() { return keystorePort_; }

};

#endif
