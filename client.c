#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

#define BUFFLEN 1024
#define PAYLOAD_TYPE "application/json"
#define URL_REGISTER "/api/v1/tema/auth/register"
#define URL_LOGIN "/api/v1/tema/auth/login"
#define URL_ENTER_LIBRARY "/api/v1/tema/library/access"
#define URL_GET_BOOKS "/api/v1/tema/library/books"
#define URL_LOGOUT "/api/v1/tema/auth/logout"

//returns a serialized JSON string containing 
//the username and password read from stdin
char *get_user() {
    //fetch username
    char username[BUFFLEN] = {0};
    printf("username=");
    fgets(username, BUFFLEN, stdin);
    //check for spaces in username
    if (strstr(username, " ") != NULL) {
        printf("Username cannot contain spaces!\n\n");
        return NULL;
    }
    username[strlen(username) - 1] = '\0';

    //fetch password
    char password[BUFFLEN] = {0};
    printf("password=");
    fgets(password, BUFFLEN, stdin);
    //check for spaces in password
    if (strstr(password, " ") != NULL) {
        printf("Password cannot contain spaces!\n\n");
        return NULL;
    }
    password[strlen(password) - 1] = '\0';

    //init the JSON object
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    
    return json_serialize_to_string(root_value);
}

int main(int argc, char *argv[]) {

    int host_port = 8080;
    char host_ipaddr[16] = "34.254.242.81";

    int login_status = 0; //0 - not logged in, 1 - logged in
    int library_access = 0; //0 - NO access to library, 1 - access to library
    char session_cookie[BUFFLEN] = {0};
    char jwt_token[BUFFLEN] = {0};

    while (1) {

        //get user input from stdin
        char buff[BUFFLEN] = {0};
        fgets(buff, BUFFLEN, stdin);

        //open connection to server after each user command
        int sockfd = open_connection(host_ipaddr, host_port, AF_INET, SOCK_STREAM, 0);

        //close connection and exit
        if (strcmp(buff, "exit\n") == 0) {
            close_connection(sockfd);
            break;
        }

        else if (strcmp(buff, "register\n") == 0) //REGISTER command
        { 
            //get JSON object with username and password
            char *serialized_string = get_user();
            if (serialized_string == NULL) {
                close_connection(sockfd);
                continue;
            }

            //compute POST request, send it to server and receive response
            char *message = compute_post_request(host_ipaddr, URL_REGISTER, PAYLOAD_TYPE, serialized_string, NULL, 0);
            send_to_server(sockfd, message);
            char *response = receive_from_server(sockfd);

            //check if registration was succesful
            if (strstr(response, "HTTP/1.1 400 Bad Request") != NULL && strstr(response, "{\"error\":\"The username ") != NULL) {
                printf("Registration failed! Username is taken!\n");
            }
            else if (strstr(response, "HTTP/1.1 201 Created") != NULL){
                printf("Registration succesful!\n");
            }
            else printf("ERROR\n");
        }

        else if (strcmp(buff, "login\n") == 0) //LOGIN command
        {
            //check if user is already logged in
            if (login_status == 1) {
                printf("You are already logged in!\n\n");
                close_connection(sockfd);
                continue;
            }

            //get JSON object with username and password
            char *serialized_string = get_user();
            if (serialized_string == NULL) {
                close_connection(sockfd);
                continue;
            }

            //compute POST request, send it to server and receive response
            char *message = compute_post_request(host_ipaddr, URL_LOGIN, PAYLOAD_TYPE, serialized_string, NULL, 0);
            send_to_server(sockfd, message);
            char *response = receive_from_server(sockfd);

            //username not found or wrong password
            if (strstr(response, "HTTP/1.1 400 Bad Request") != NULL) {
                printf("Login failed! Wrong credentials!\n");
            }
            else if (strstr(response, "Set-Cookie: ") != NULL) {
                
                //extract cookie from response
                char *cookie = strstr(response, "Set-Cookie: ");
                cookie += strlen("Set-Cookie: ");
                strcpy(session_cookie, cookie);
                
                //remove the rest of the response
                int i = 0;
                while (session_cookie[i] != ';' && session_cookie[i] != '\0')
                    i++;
                session_cookie[i] = '\0';

                //set login status to 1 and print success message
                if (session_cookie != NULL) {
                    login_status = 1;
                    printf("Login succesful!\n");
                }
            }
            else printf("ERROR\n");
        }

        else if (strcmp(buff, "enter_library\n") == 0) //ENTER_LIBRARY command
        {
            //check if user is logged in
            if (login_status == 0) {
                printf("You are not logged in!\n\n");
                close_connection(sockfd);
                continue;
            }

            //check if user already has access to library
            if (library_access == 1) {
                printf("You already have access to library!\n\n");
                close_connection(sockfd);
                continue;
            }

            //compute GET request, send it to server and receive response
            char *message = compute_get_request(host_ipaddr, URL_ENTER_LIBRARY, NULL, session_cookie, NULL);
            send_to_server(sockfd, message);
            char *response = receive_from_server(sockfd);

            if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
                
                //extract JWT token from response
                char *token = strstr(response, "{\"token\":\"");
                token += strlen("{\"token\":\"");
                strcpy(jwt_token, token);

                //remove the rest of the response
                int i = 0;
                while (jwt_token[i] != '\"' && jwt_token[i] != '\0')
                    i++;
                jwt_token[i] = '\0';
                
                //set library access to 1 and print success message
                if(jwt_token != NULL) {
                    library_access = 1;
                    printf("Access granted!\n");
                }
            }
            else printf("ERROR\n");
        }

        else if (strcmp(buff, "get_books\n") == 0) //GET_BOOKS command
        {
            //check if user has access to library
            if (library_access == 0) {
                printf("You don't have access to library!\n\n");
                close_connection(sockfd);
                continue;
            }

            //compute GET request, send it to server and receive response
            char *message = compute_get_request(host_ipaddr, URL_GET_BOOKS, NULL, session_cookie, jwt_token);
            send_to_server(sockfd, message);
            char *response = receive_from_server(sockfd);

            //print books
            if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
                char *books = strstr(response, "\n[{\"id\":");

                if (books != NULL) {
                    // JSON_Value *root_value;
                    // JSON_Array *books_array;
                    // JSON_Object *book_object;
                    // root_value = json_parse_string(books);
                    // books_array = json_value_get_array(root_value);

                    // for (int i = 0; i < json_array_get_count(books_array); i++) {
                    //     book_object = json_array_get_object(books_array, i);
                    //     printf("id: %d\n", (int)json_object_get_number(book_object, "id"));
                    //     printf("title: %s\n", json_object_get_string(book_object, "title"));
                    //     printf("\n");
                    //}
                    printf("%s\n", books);
                }
                else printf("No books in library!\n");
            }
            else printf("ERROR\n");
        }

        else if (strcmp(buff, "logout\n") == 0) //LOGOUT command
        {
            //check if user is logged in
            if (login_status == 0) {
                printf("You are not logged in!\n\n");
                close_connection(sockfd);
                continue;
            }

            //compute GET request, send it to server and receive response
            char *message = compute_get_request(host_ipaddr, URL_LOGOUT, NULL, session_cookie, NULL);
            send_to_server(sockfd, message);
            char *response = receive_from_server(sockfd);

            //check if logout was succesful
            if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
                //reset login status and library access
                login_status = 0;
                library_access = 0;

                //reset session cookie and JWT token
                session_cookie[0] = '\0';
                jwt_token[0] = '\0';

                //print success message
                printf("Logout succesful!\n");
            }
            else printf("ERROR\n");
        }

        else if (strcmp(buff, "exit\n") == 0) //EXIT command
        {
            close_connection(sockfd);
            break;
        }

        else {
            printf("Invalid command!\n");
        }

        printf("\n");
        close_connection(sockfd);
    }
    
    return 0;
}
