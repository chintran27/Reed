

# REED

 * Introduction
 * Requirements
 * Installation
 * Configuration
 * Make
 * Example
 * Maintainers

# INTRODUCTION

REED builds on a deterministic version of all-or-nothing transform (AONT), such that it enables secure and lightweight rekeying, while preserving the deduplication capability. We propose two REED encryption schemes that trade between performance and security, and extend REED for dynamic access control. We implement a REED prototype with various performance optimization techniques. Our trace-driven testbed evaluation shows that our REED prototype maintains high performance and storage efficiency.

# REQUIREMENTS

REED is built on Ubuntu 12.04.3 LTS with g++ version 4.8.1.

This software requires the following libraries:

 * OpenSSL (https://www.openssl.org/source/openssl-1.0.2a.tar.gz)
 * boost C++ library (http://sourceforge.net/projects/boost/files/boost/1.58.0/boost_1_58_0.tar.gz)
 * GMP library (https://gmplib.org/)
 * LevelDB (https://github.com/google/leveldb/archive/master.zip)
 * CP-ABE toolkit and libbswabe library (http://acsc.cs.utexas.edu/cpabe/) 
 * PBC library (https://crypto.stanford.edu/pbc/)

The LevelDB is packed in /server/lib/.


# INSTALLATION


For linux user you can install the LevelDB dependency, OpenSSL and Boost by the following:

 * sudo apt-get install libssl-dev libboost-all-dev libsnappy-dev 

REED client also needs following packages to support CP-ABE toolkit:

 * sudo apt-get install flex bison libgmp3-dev libglib2.0-dev

Dependency:

 * Install pbc-0.5.14
 * Install libbswabe-0.9
 * Install cpabe-0.11

# CONFIGURATION


 * Configure the storage server (can be specified as keystore or datastore or both in conf.hh)

	For data store:
	- Make sure there are three directories under /server/
	- "DedupDB" for levelDB logs
	- "RecipeFiles" for temp recipe files
	- "ShareContainers" for share local cache
	- Start a server by "./SERVER [port]"

	For key store:
	- Make sure there is a directory under /server
	- "keystore" for key states
	- Start a server by "./SERVER [port]"

 * Configure the key manager

  - Start a key manager by "./KEYMANAGER [port]"

 * Configure the client
  
  - Specify the key manager and key store IPs, ports in /client/util/conf.hh

  - Specify the number of storage nodes in /client/util/conf.hh, modifying the "numOfStore_" value

  - Specify the data stores IPs and Ports according to your "numOfStore_" in /client/util/conf.hh
	
  	Example: you have run 2 servers with "./SERVER [port]" on machines:
  
    	- 192.168.0.30 with port 11030
    	- 192.168.0.31 with port 11031
	
	And you have run 1 key manager with "./KEYMANAGER [port]" on machine:

    	- 192.168.0.32 with port 11032
    
    If you want one server act as datastore, the other one to be keystore, you need modify the /client/util/conf.hh as following:
    
    	- numOfStore_ = 1;
    
    	- strcpy(datastoreIP_[0], "192.168.0.30"); 
    	
    	- datastorePort_[0] = 11030;
    
    	- strcpy(keymanagerIP_, "192.168.0.32"); 
    	
    	- keymanagerPort_ = 11032;
    
    	- strcpy(keystoreIP_, "192.168.0.31"); 
    	
    	- keystorePort_ = 11031;


# MAKE


 * To make a client, on the client machine:
  - Go to /client/lib/, type "make" to make gf_complete
  - Back to /client/, type "make" to get the executable CLIENT program
  
 * To make a server, on each storage node:
  - Go to /server/lib/leveldb/, type "make" to make levelDB
  - Back to /server/, type "make" to get the executable SERVER program

 * To make a key manager, on the key manager machine:
  - Go to /keymanager/, type "make" to get the executable KEYMANAGER program

# EXAMPLE

 * After successful make

	usage: ./CLIENT [filename] [userID] [action] [secutiyType]

	- [filename]: full path of the file;
	- [userID]: user ID of current client;
	- [action]: [-u] upload; [-d] download;
	- [securityType]: [HIGH] AES-256 & SHA-256; [LOW] AES-128 & SHA-1


 * To upload a file "test", assuming from user "0" using enhanced scheme

	./CLIENT test 0 -u HIGH

 * To download a file "test", assuming from user "1" using baseline scheme

	./CLIENT test 1 -d LOW

 * To rekey a file "test", assuming from user "2" using baseline scheme

  ./CLIENT test 2 -r LOW

# MAINTAINER

 * Current maintainer

	- Chuan QIN, the Chinese University of Hong Kong, chintran27@gmail.com




