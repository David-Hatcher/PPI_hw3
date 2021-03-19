#include <zmq.h>
#include <vector>
#include <iomanip>
#include <sstream>
#include "Helper.hpp"

using namespace std;

int main(void){
    unsigned char buffer[MAXBLOCKSIZE];

    unsigned char key[33] = "secretsecretsecr";
    cout << "Reading Contents from file" << endl;
    vector<string> messages = getFileConts("message.txt");

    void *context = zmq_ctx_new ();
    void *requester = zmq_socket (context, ZMQ_REQ);
    zmq_connect (requester, "tcp://localhost:5555");
    char prevHmac[33];
    prevHmac[0] = '\0';
    prevHmac[32] = '\0';

    for(int i = 1; i <= 100; i++){
        unsigned char message[1025];
        strcpy((char *)message,messages.front().c_str());
        messages.erase(messages.begin());
        int length = strlen((char*)message);
        //copying message, this will need to be replaced whenever we figure out how the message will be input
        unsigned char msg[1025];
        strcpy((char*)msg,(char*)message);
        //generating ciphertext
        unsigned char* cipher;
        cipher = ctr_encrypt(msg,key,length);

        //printing ciphertext to console
        cout << endl << "Printing Ciphertext " << i << endl;
        for(int i = 0; i < 1025; i++){
            cout << cipher[i];
        }
        cout << endl;

        //make hmac for current cipher text
        char hmac[21];
        unsigned char hashedHmac[33];
        compute_hmac((char*)cipher,hmac,key);
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
            char hmacCat[65] = "";
            zeromem(hmacCat,65);
            strcat(hmacCat,prevHmac);
            strcat(hmacCat,hmac);
            //deleting previous HMAC and current hash
            generateHash((unsigned char*)hmacCat,(unsigned char*)prevHmac,64);
        }

        //printing agg mac to console
        cout << endl << "Agg MAC " << i << ":" <<  endl;
        for(int i = 0; i < 32; i++){
            cout << prevHmac[i];
        }
        cout << endl;
        //hashing key to generate next key in chain, deleting previous in overwrite
        generateHash(key,key,strlen((char*)key));

        //sending ciphertext to bob
        // cout << "Sending Ciphertext " << i << endl;
        zmq_send(requester, cipher, length, 0);
        sleep(1);          //  Do some 'work'
        zmq_recv(requester, buffer, length, 0);
        // cout << "Recieved Response" << endl << endl;
    }

    //sending hmac for authentication
    sleep(1);
    zmq_send(requester,prevHmac,32,0);

    //Closing connection to bob
    zmq_close (requester);
    zmq_ctx_destroy (context);
    return EXIT_SUCCESS;
}

