#include <zmq.h>
#include "Helper.hpp"
#include <vector>
#include <string>
using namespace std;

int main(void){
    int length = 1024;
    unsigned char key[33] = "secretsecretsecr";
    //Getting information from Alice
    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    int rc = zmq_bind (responder, "tcp://*:5555");
    assert (rc == 0);
    char prevHmac[33];
    prevHmac[0] = '\0';
    prevHmac[32] = '\0';
    char authHmac[33];
    authHmac[0] = '\0';
    authHmac[32] = '\0';
    vector<string> messages;

    for(int i = 1; i <= 100; i++){
        //container for recieved ciphertext
        char buffer[length + 1] = "";
        //getting message from alice
        zmq_recv(responder, buffer, length, 0);
        cout << "Received Cipher " << i << endl;
        sleep (1);          //  Do some 'work'
        //letting alice know i got the message
        zmq_send (responder, "Got it.", 8, 0);

        //generating hmac
        char hmac[21];
        unsigned char hashedHmac[33];
        compute_hmac(buffer,hmac,key);
        hmac[20] = '\0';
        //hash current hmac H(prevHmac - 1 || prevHmac)
        //H(H(prevHmac - 1 || preHmac) || currentHmac)
        
        if(i == 1){
            //hash original hmac as there is only one
            generateHash((unsigned char*)hmac,hashedHmac,20);
            memcpy(prevHmac,hashedHmac,33);
        }
        else{
            //hashing current hmac and previous hmac
            char hmacCat[65];
            zeromem(hmacCat,65);
            strcat(hmacCat,prevHmac);
            strcat(hmacCat,hmac);
            generateHash((unsigned char*)hmacCat,(unsigned char*)prevHmac,64);
            // memcpy(prevHmac,hashedHmac,32);
        }

        //Decrypting ciphertext
        unsigned char* plain;
        plain = ctr_decrypt((unsigned char*)buffer,key,length);
        string plainString(reinterpret_cast<char*>(plain));
        messages.push_back(plainString);

        //hashing key to generate next key in chain
        generateHash(key,key,strlen((char*)key));
    }

    zmq_recv (responder, authHmac, 32, 0);
    //check for validity
    if(strcmp(prevHmac,authHmac) == 0){
        cout << endl << "Hmacs the same, writing contents to file!" << endl;
        writeToFile("messageDecrypt.txt",messages);
    }

    return EXIT_SUCCESS;
}