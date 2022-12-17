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
int AES_256_GCM_ENCRYPT(unsigned char *plaintext, int plaintext_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);

int main(int argc,char* argv[])
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

        while(nw_address_temp[i]!=':')
        {
            ip_address[j]=nw_address_temp[i];
            i++;
            j++;
        }
        j=0;
        i++;
        while(nw_address_temp[i]!='\0')
        {
            port_number[j]=nw_address_temp[i];
            i++;
            j++;
        }
        opMode=0;
        
        

    }
    else
    {
        
        opMode=1;
    }

    /* TAKING COMMAND LINE ENDS */

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
   


    /*IV GENERATION STARTS*/
    unsigned char temp_iv[16];
    unsigned char iv[16];
    int len_iv=0;
    while(len_iv!=16)
    {  
        RAND_priv_bytes(temp_iv,16);
        len_iv=strlen(temp_iv);

    }
    size_t iv_len = 16;
    strcpy(iv,temp_iv);
    /*IV GENERATION ENDS*/


    /* AES 256 STARTS */
        

        /* Reading plaintext from the file starts*/
        FILE *plaintext_fp = fopen(inputFileName, "rb");
        fseek(plaintext_fp, 0, SEEK_END);
        long plaintext_size = ftell(plaintext_fp);
        fseek(plaintext_fp, 0, SEEK_SET); 
        
        unsigned char plaintext[5000];

        fread(plaintext, plaintext_size, 1, plaintext_fp);
        
        fclose(plaintext_fp);
        plaintext[plaintext_size] = 0;
        /* Reading plaintext from the file ends*/
        
       

        // unsigned char *additional =(unsigned char *)"abcde";
        unsigned char ciphertext[2000];
        unsigned char tag[16];
        int ciphertext_len;

        

        ciphertext_len = AES_256_GCM_ENCRYPT(plaintext, strlen ((char *)plaintext),                                 
                                 key,
                                 temp_iv, iv_len,
                                 ciphertext, tag);

        char dis_msg[30];
        strcpy(dis_msg,"Successfully encrypted ");
        strcat(dis_msg,inputFileName);
        strcat(dis_msg," to ");
        strcat(dis_msg,inputFileName);
        strcat(dis_msg,".uf");
        printf("%s\n",dis_msg);
        printf("\n");
    

        
        printf("IV is:\n");
        BIO_dump_fp (stdout, iv, 16);
        printf("\n");

        printf("Tag is:\n");
        BIO_dump_fp (stdout, tag, strlen(tag));
        printf("\n");

        printf("Ciphertext is:\n");
        BIO_dump_fp (stdout, ciphertext, strlen(ciphertext));
        printf("\n");
       
    /* AES 256 ENDS */
    /* PREPARING DATA FOR TRANSMISSION STARTS */


        unsigned char *final_text;
        char iv_size_f[10],tag_size_f[10],ciphertext_size_f[10],ciphertext_fsize_f[10];
        int iv_l,tag_l,cipher_l,cipher_ml;
        cipher_ml=ciphertext_len;
        iv_l=strlen(iv);
        tag_l=strlen(tag);
        cipher_l=strlen(ciphertext);
        sprintf(iv_size_f, "%d", iv_l);
        sprintf(tag_size_f, "%d", tag_l);
        sprintf(ciphertext_size_f, "%d", cipher_l);
        sprintf(ciphertext_fsize_f, "%d", cipher_ml);
        

        if((final_text = (char *)malloc(100 + strlen(iv) + strlen(tag)+strlen(ciphertext)+ 1)) != NULL)
        {
            strcpy(final_text, iv_size_f);
            strcat(final_text, "/");
            strcat(final_text, tag_size_f);
            strcat(final_text, "/");
            strcat(final_text, ciphertext_size_f);
            strcat(final_text, "/");
            strcat(final_text, ciphertext_fsize_f);
            strcat(final_text, "/");
            strcat(final_text, iv);
            strcat(final_text, tag);
            strcat(final_text, ciphertext);
        }


    /* PREPARING DATA FOR TRANSMISSION ENDS */


    if(opMode==0)
    {
        // SOCKET STARTS
            strcpy(dis_msg,"Transmitting data to ");
            strcat(dis_msg,ip_address);
            printf("%s",dis_msg);
            printf("\n");



            int sock = 0, valread, client_fd;
            struct sockaddr_in serv_addr;
            char buffer[MAX] = { 0 };
            if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                printf("\n Socket creation error \n");
            }

            serv_addr.sin_family = AF_INET;
            serv_addr.sin_port = htons(atoi(port_number));


            if (inet_pton(AF_INET, ip_address , &serv_addr.sin_addr)
                <= 0) {
                printf(
                    "\nInvalid address/ Address not supported \n");
                
            }

            if ((client_fd
                = connect(sock, (struct sockaddr*)&serv_addr,
                        sizeof(serv_addr)))
                < 0) {
                printf("\nConnection Failed \n");
                
            }
            send(sock, final_text, strlen(final_text), 0);
            
            valread = read(sock, buffer, 1000);
            printf("%s\n", buffer);

            
            close(client_fd);
        // SOCKET ENDS
    }
    else
    {   
        strcpy(dis_msg,"File Encrypted to ");
        strcat(dis_msg,inputFileName);
        strcat(dis_msg,".ufsec");
        printf("%s\n",dis_msg);
        printf("\n");
        FILE *fptr;
        char tempFileName[50];
        strcpy(tempFileName,inputFileName);
        strcat(tempFileName,".ufsec");
        fptr = fopen(tempFileName, "w+");
        if (fptr == NULL) {
            printf("Error!");
            exit(1);
        }
        fprintf(fptr, "%s", final_text);
        fclose(fptr);
    }


    return 0;

}
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int AES_256_GCM_ENCRYPT(unsigned char *plaintext, int plaintext_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* INITIALIZING THE CONTEXT*/
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* INITIALIZING ENCRYPTION OPERATION */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* SETTING LENGTH OF IV */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* SETTING THE KEY(FROM PBKDF2) AND RANDOMLY GENERATED IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /* SETTING PLAINTEXT AND PLAINTEXT LENGTH FOR ENCRYPTION*/
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* FINALIZING THE ENCRYPTION */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* STORING THE TAG IN VARIABLE. THIS WILL BE SENT TO THE DECRYPTION SIDE FOR DECRYPTING THIS MESSAGE */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* FREEING EVP_CIPHER STRUCTURED INITIALIZED AT FIRST STEP*/
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
