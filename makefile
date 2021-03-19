all: alice.exe bob.exe

alice.exe:
	g++ -o alice Alice.cpp -lzmq -ltomcrypt

bob.exe:
	g++ -o bob Bob.cpp -lzmq -ltomcrypt
