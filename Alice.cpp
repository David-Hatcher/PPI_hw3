#include <zmq.h>
#include "Helper.hpp"

using namespace std;

int main(void){
    unsigned char buffer[MAXBLOCKSIZE];

    unsigned char key[33] = "secretsecretsecr";
    unsigned char message[1025] = "hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellovhellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohel";


    void *context = zmq_ctx_new ();
    void *requester = zmq_socket (context, ZMQ_REQ);
    zmq_connect (requester, "tcp://localhost:5555");
    
    //need to change loop to for each message
    for(int i = 1; i < 6; i++){
        int length = strlen((char*)message);
        //copying message, this will need to be replaced whenever we figure out how the message will be input
        unsigned char msg[1025];
        strcpy((char*)msg,(char*)message);
        //generating ciphertext
        unsigned char* cipher;
        cipher = ctr_encrypt(msg,key,length);
        //printing ciphertext
        cout << endl << "Printing Ciphertext " << i << endl << endl;
        for(int i = 0; i < length; i++){
            cout << cipher[i];
        }
        cout << endl;
        //Generating new key for next round of encryption, old key deleted during overwrite
        generateHash(key,key,strlen((char*)key));

        //Hmac aggretation still needs to be complete
        // char hmac[32];
        // compute_hmac((char*)cipher,hmac,key);
        // cout << hmac << endl;

        //sending ciphertext to bob
        cout << "Sending Ciphertext " << i << endl;
        zmq_send(requester, cipher, length, 0);
        sleep(1);          //  Do some 'work'
        zmq_recv(requester, buffer, length, 0);
        cout << "Recieved Response" << endl << endl;
    }

    return EXIT_SUCCESS;
}

