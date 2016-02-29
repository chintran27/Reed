

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

CDStore is built on Ubuntu 12.04.3 LTS with gcc version 4.6.3.

This software requires the following libraries:

 * OpenSSL (https://www.openssl.org/source/openssl-1.0.2a.tar.gz)
 * GF-Complete (https://github.com/ceph/gf-complete/archive/master.zip)
 * boost C++ library (http://sourceforge.net/projects/boost/files/boost/1.58.0/boost_1_58_0.tar.gz)
 * LevelDB (https://github.com/google/leveldb/archive/master.zip)
 * CP-ABE toolkit (http://acsc.cs.utexas.edu/cpabe/)

The GF-Complete and LevelDB are packed in /client/lib/ and /server/lib/ respectively.


# INSTALLATION


For linux user you can install the LevelDB dependency, OpenSSL and Boost by the following:

 * sudo apt-get install libssl-dev libboost-all-dev libsnappy-dev


# CONFIGURATION


 * Configure the storage server (REED requires at least 4 storage server)

	- Make sure there are three directories under /server/meta
	- "DedupDB" for levelDB logs
	- "RecipeFiles" for temp recipe files
	- "ShareContainers" for share local cache
	- Start a server by "./SERVER [port]"

 * Configure the key server

  - Start a key server by "./KEYSERVER [port]"

 * Configure the client

	- In the configure file /client/config, specify the storage nodes line by line with [IP]:[port]

	Example: you have run 4 servers with "./SERVER [port]" on machines:
		- 192.168.0.30 with port 11030
		- 192.168.0.31 with port 11031
		- 192.168.0.32 with port 11032
		- 192.168.0.33 with port 11033
		
		you need to specify the ip and port in config with following format: 

			192.168.0.30:11030
			192.168.0.31:11031
			192.168.0.32:11032
			192.168.0.33:11033

		(the actual order doesn't matter)

  - Specify the key server IP and port in file /client/keyClient/exchange.cc line 200

  Example: you have run key server with "./KEYSERVER 1101" on machine with IP 192.168.0.26:
    - Change the line into: sock_[0] = new Ssl("192.168.0.26",1101,0);
	
	- (Optional) In the configure class of client, /client/util/conf.hh

		- set chunk and secure parameters following the comments
		- set the number of storage nodes according to your running servers

# MAKE


	To make a client, on the client machine:

	 * Go to /client/lib/, type "make" to make gf_complete
	 * Back to /client/, type "make" to get the executable CLIENT program

	To make a server, on each storage node:

	 * Go to /server/lib/leveldb/, type "make" to make levelDB
	 * Back to /server/, type "make" to get the executable SERVER program

  To make a keyserver, on the key server machine:

   * Go to /keyServer/, type "make" to get the executable KEYSERVER program

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




