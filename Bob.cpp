#include <zmq.h>
#include "Helper.hpp"

using namespace std;

int main(void){
    int length = 1024;
    unsigned char key[33] = "secretsecretsecr";
    //Getting information from Alice
    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    int rc = zmq_bind (responder, "tcp://*:5555");
    assert (rc == 0);
    for(int i = 1; i < 6; i++){
        //container for recieved ciphertext
        char buffer[length + 1] = "";
        //getting message from alice
        zmq_recv (responder, buffer, length, 0);
        cout << "Received Cipher " << i << endl;
        sleep (1);          //  Do some 'work'
        //letting alice know i got the message
        zmq_send (responder, "Got it.", 8, 0);
        //Uncomment to print cipher
        // for(int i = 0; i < length; i++){
        //     cout << buffer[i];
        // }
        // cout << endl;
        //Decrypting ciphertext
        unsigned char* plain;
        plain = ctr_decrypt((unsigned char*)buffer,key,length);
        cout << "Plaintext " << i << endl;
        cout << plain << endl;
        //hashing key to generate next key in change, deleting old key in the overwrite.
        generateHash(key,key,strlen((char*)key));
    }

    return EXIT_SUCCESS;
}