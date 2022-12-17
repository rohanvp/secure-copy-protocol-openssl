#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>

#define MAX 5000


void handleErrors(void);
int AES_256_DECRYPTION(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

int main (int argc,char* argv[])
{   
    

    /* TAKING COMMAND LINE ARGUMENTS STARTS */
    char *inputFileName=argv[1];
    char *operationMode=argv[2];
    int portNumber;
    char *nw_address_temp=argv[3];
    char ip_address[20],port_number[10];
    int opMode=0;

    if(strcmp(operationMode,"-d")==0)
    { 
        int i=0;
        int j=0;

        while(nw_address_temp[i]!='\0')
        {
            port_number[j]=nw_address_temp[i];
            i++;
            j++;
        }
        opMode=0;

    }
    else if(strcmp(operationMode,"-l")==0)
    {
        opMode=1;
    }
    
    /* TAKING COMMAND LINE ENDS */
    

    /* READING DATA FROM UFSEND STARTS */
    char buffer[10000];
    if(opMode==0)
    {   
        // SOCKET STARTS
        int server_fd, new_socket, valread;
        struct sockaddr_in address;
        int opt = 1;
        int addrlen = sizeof(address);
        
        char* msg_to_ufsend = "Data Recived Successfully";

        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("socket failed");
            exit(EXIT_FAILURE);
        }

        if (setsockopt(server_fd, SOL_SOCKET,
                    SO_REUSEADDR | SO_REUSEPORT, &opt,
                    sizeof(opt))) {
            perror("setsockopt");
            exit(EXIT_FAILURE);
        }
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(atoi(port_number));

        if (bind(server_fd, (struct sockaddr*)&address,
                sizeof(address))
            < 0) {
            perror("bind failed");
            exit(EXIT_FAILURE);
        }
        if (listen(server_fd, 3) < 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        }
        if ((new_socket
            = accept(server_fd, (struct sockaddr*)&address,
                    (socklen_t*)&addrlen))
            < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        valread = read(new_socket, buffer, MAX);

        send(new_socket, msg_to_ufsend, strlen(msg_to_ufsend), 0);

        close(new_socket);
        
        shutdown(server_fd, SHUT_RDWR);

        // SOCKET ENDS
        printf("Inbound Data");
        printf("\n");
        printf("Data Recieved Successfully in Network Mode\n");
        
    }

    else
    {
        printf("Data Recieved Successfully in Local Mode\n");
        FILE *recvtext_fp = fopen(inputFileName, "rb");
        fseek(recvtext_fp, 0, SEEK_END);
        long recv_size = ftell(recvtext_fp);
        fseek(recvtext_fp, 0, SEEK_SET); 

        fread(buffer, recv_size, 1, recvtext_fp);
        
        fclose(recvtext_fp);

        buffer[recv_size] = 0;
    }
    /* READING DATA FROM UFSEND STARTS */

    
    /* CLEANING RECEIVED DATA STARTS */
        int i=0;
        unsigned char *out=buffer;
        char temp1[10],temp2[10],temp3[10],temp4[10];
        char iv_temp[MAX],tag_temp[MAX],cipher_temp[MAX];

        char *temp;
        while(out[i]!='/')
        {
            temp1[i]=out[i];
            i++;
        }
        i++;
        int j=0;
        while(out[i]!='/')
        {
            temp2[j]=out[i];
            i++;
            j++;
        }
        i++;
        j=0;
        while(out[i]!='/')
        {
            temp3[j]=out[i];
            i++;
            j++;
        }
        i++;
        j=0;
        while(out[i]!='/')
        {
            temp4[j]=out[i];
            i++;
            j++;
        }
        i++;
        j=0;
        
        int x=atoi(temp1);
        int y=atoi(temp2);
        int z=atoi(temp3);
        int m=atoi(temp4);

        
        for(int k=i;k<x+i-y;k++)
        {
            iv_temp[j]=out[k];
            j++;
        }
        
        i=i+x;
        j=0;
        for(int k=i;k<y+i;k++)
        {
            tag_temp[j]=out[k];
            j++;
        }
        i=i+y;
        j=0;
        int t=strlen(cipher_temp);
        for(int k=i;k<z+i;k++)
        {
            cipher_temp[j]=out[k];
            j++;
        }
    /* CLEANING RECEIVED DATA ENDS */


    /* PBKDF2 IMPLEMENTATION STARTS */
        unsigned char key[32];
        unsigned char myPass[50];
        printf("Please Provide A Password:");
        scanf("%s",myPass);
        
        int temp_key_length=0;
        while(temp_key_length!=32)
        {
            PKCS5_PBKDF2_HMAC(myPass,strlen(myPass),
                        "SodiumChloride", strlen("SodiumChloride"), 4096,
                        EVP_sha3_256(),
                        sizeof(key), key);
            temp_key_length=sizeof(key);
        }
        printf("Key:");
        for (size_t i=0; i<sizeof(key); ++i)
            printf("%02x ", key[i]);
        printf("\n");
        printf("\n");
    /* PBKDF2 IMPLEMENTATION ENDS */
   



    /* EXTRACTING REQUIRED PARTS FROM RECEIVED DATA FOR DECRYPTION STARTS */
    unsigned char *iv = (unsigned char *)iv_temp;
    size_t iv_len = 16;


    unsigned char ciphertext[5000];

    strcpy(ciphertext,(unsigned char *)cipher_temp);

    unsigned char decryptedtext[2000];

    unsigned char *tag=tag_temp;

    int decryptedtext_len, ciphertext_len=m;

    /* EXTRACTING REQUIRED PARTS FROM RECEIVED DATA FOR DECRYPTION STARTS */


    /* PRINTING RECEIVED PARAMETERS STARTS */

        printf("IV is:\n");
        BIO_dump_fp (stdout, iv, strlen(iv));

        printf("Tag is:\n");
        BIO_dump_fp (stdout, tag, strlen(tag));

        printf("Ciphertext is:\n");
        BIO_dump_fp (stdout, ciphertext, strlen(ciphertext));

    /* PRINTING RECEIVED PARAMETERS ENDS */


    /* DECTYPTING RECEIVED DATA STARTS */


    
    decryptedtext_len = AES_256_DECRYPTION(ciphertext, ciphertext_len,
                                tag,
                                key, iv, iv_len,
                                decryptedtext);
    

    if (decryptedtext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);

        FILE *dec_fptr;
        char tempFileName[50];
        strncpy(tempFileName,inputFileName,strlen(inputFileName)-6);
        dec_fptr = fopen(tempFileName, "w+");
        if (dec_fptr == NULL) {
            printf("Error!");
            exit(1);
        }
        fprintf(dec_fptr, "%s", decryptedtext);
        fclose(dec_fptr);





    } else {
        printf("Decryption failed\n");
    }   
    /* DECTYPTING RECEIVED DATA ENDS */

    return 0;
}


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}



int AES_256_DECRYPTION(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* INITIALIZING THE CONTEXT*/
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* INITIALIZING DECRYPTION OPERATION */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* SETTING IV LENGTH. THIS LENGTH IS LENGTH OF IV OBTAINED FROM THE SENDER VIA OUR METHOD OF CREATING DATA FOR TRANSMISSION. */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* SETTING KEY(GENERATED BY PBKDF2) AND IV(OBTAINED FROM SENDER) */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();


    /* SETTING CIPHERTEXT LENGTH AND PROVIDING AND EMPTY STORAGE FOR PLAINTEXT */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* SETTING TAG VALUE. THIS VALUE IS OBTAINED FROM THE SENDER */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /* FINAL DECRYPTION OPERATION*/
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* FREEING EVP_CIPHER STRUCTURED INITIALIZED AT FIRST STEP */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}
