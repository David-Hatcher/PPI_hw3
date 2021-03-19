#include <string>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <tomcrypt.h>

using namespace std;

/*read a single line from a file*/
vector<string> getFileConts(string fileName){
    vector<string> messages;
    ifstream file;
    file.open(fileName);
    if(file.is_open()){
        string s;
        while(getline(file,s)){
            messages.push_back(s);
        }
    }
    file.close();
    return messages;
}

/*write a single string to a text file*/
void writeToFile(string fileName, vector<string> msg){
    ofstream file;
    file.open(fileName);
    for(string m : msg){
        file << m << endl;
    }
}

unsigned char* ctr_encrypt(unsigned char *buffer, unsigned char *key,int len)
{
    int keylength = 16;
    unsigned char IV[16] = "bbcdefhij12345";
    if(strlen((const char*)key) > 17){
        keylength = 32;
    }
    
    symmetric_CTR ctr;
    int err/*,x*/;
    /* register twofish first */
    if (register_cipher(&twofish_desc) == -1)
    {
        printf("Error registering cipher.\n");
        return buffer;
    }
    if ((err = ctr_start(
             find_cipher("twofish"),    /* index of desired cipher */
             IV,                        /* the initial vector */
             key,                       /* the secret key */
             keylength,                        /* length of secret key (16 bytes) */
             0,                         /* 0 == default # of rounds */
             CTR_COUNTER_LITTLE_ENDIAN, /* Little endian counter */
             &ctr)                      /* where to store the CTR state */
         ) != CRYPT_OK)
    {
        printf("ctr_start error: %s\n", error_to_string(err));
        return buffer;
    }
    if ((err = ctr_encrypt(buffer,         /* plaintext */
                           buffer,         /* ciphertext */
                           len,            /* length of plaintext pt */
                           &ctr)           /* CTR state */
         ) != CRYPT_OK)
    {
        printf("ctr_encrypt error: %s\n", error_to_string(err));
        return buffer;
    }
    //zeromem(key, sizeof(key));
    zeromem(&ctr, sizeof(ctr));
    return buffer;
}



unsigned char* ctr_decrypt(unsigned char *buffer, unsigned char *key,int len)
{
    int keylength = 16;
    unsigned char IV[16] = "bbcdefhij12345";
    if(strlen((const char*)key) > 17){
        keylength = 32;
    }
    symmetric_CTR ctr;
    int x, err;
    

    /* register twofish first */
    if (register_cipher(&twofish_desc) == -1)
    {
        printf("Error registering cipher.\n");
        return buffer;
    }

    /* somehow fill out key and IV */
    /* start up CTR mode */
    if ((err = ctr_start(
             find_cipher("twofish"),    /* index of desired cipher */
             IV,                        /* the initial vector */
             key,                       /* the secret key */
             keylength,                        /* length of secret key (16 bytes) */
             0,                         /* 0 == default # of rounds */
             CTR_COUNTER_LITTLE_ENDIAN, /* Little endian counter */
             &ctr)                      /* where to store the CTR state */
         ) != CRYPT_OK)
    {
        printf("ctr_start error: %s\n", error_to_string(err));
        return buffer;
    }
    /* somehow fill buffer than encrypt it */
  
    /* make use of ciphertext... */
    /* now we want to decrypt so let’s use ctr_setiv */
    
    if ((err = ctr_setiv(IV,   
                         16,   
                         &ctr) 
         ) != CRYPT_OK)
    {
        printf("ctr_setiv error: %s\n", error_to_string(err));
        return buffer;
    }
    if ((err = ctr_decrypt(buffer,         
                           buffer,         
                           len, 
                           &ctr)           
         ) != CRYPT_OK)
    {
        printf("ctr_decrypt error: %s\n", error_to_string(err));
        return buffer;
    }

  
    if ((err = ctr_done(&ctr)) != CRYPT_OK)
    {
        printf("ctr_done error: %s\n", error_to_string(err));
        return buffer;
    }
    
    /* clear up and return */
    //zeromem(key, sizeof(key));
    zeromem(&ctr, sizeof(ctr));
    return buffer;
}

void compute_hmac(char *message, char *mac, unsigned char *key)
{
    int idx, err;
    hmac_state hmac;
    unsigned char dst[MAXBLOCKSIZE];
    unsigned long dstlen;

    /* register SHA-1 */
    register_hash(&sha1_desc);

    /* get index of SHA1 in hash descriptor table */
    idx = find_hash("sha1");

    /* we would make up our symmetric key in "key[]" here */
    /* start the HMAC */
    hmac_init(&hmac, idx, key, 16);

    /* process a few octets */
    hmac_process(&hmac, (const unsigned char*) message, sizeof(message));

    /* get result (presumably to use it somehow...) */
    dstlen = sizeof(dst);
    
    hmac_done(&hmac, dst, &dstlen);

    memcpy(mac, dst, dstlen);

} 

//Generate a single hash based on a seed and length, then place it in the destination
void generateHash(unsigned char seed[],unsigned char dest[],int seedLength){
    unsigned char buf[33];
    unsigned long len;
    len = sizeof(buf);
    /* register algos */
    register_hash(&sha256_desc);
    register_cipher(&aes_desc);
    hash_memory(find_hash("sha256"),seed,seedLength,buf,&len);
    //Setting final value in buf to null char to signify end of string
    buf[32] = '\0';
    strcpy((char *)dest,(char *)buf);
}


