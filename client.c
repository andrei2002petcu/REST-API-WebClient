#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include <ctype.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

#define BUFFLEN 1024
#define PAYLOAD_TYPE "application/json"
#define URL_REGISTER "/api/v1/tema/auth/register"
#define URL_LOGIN "/api/v1/tema/auth/login"
#define URL_ENTER_LIBRARY "/api/v1/tema/library/access"
#define URL_GET_BOOKS "/api/v1/tema/library/books"
#define URL_GET_BOOK "/api/v1/tema/library/books/"
#define URL_ADD_BOOK "/api/v1/tema/library/books"
#define URL_LOGOUT "/api/v1/tema/auth/logout"

//returns -1 if the string is empty
//if space_allowed is 0, also returns -1 if the string contains spaces
int check_format(char *buff, int space_allowed) {
    //check if empty string
    if (strlen(buff) == 0 || buff[0] == '\n' || buff[0] == ' ') {
        printf("Fields cannot be empty\n\n");
        return -1;
    }

    //check for spaces
    if (space_allowed == 0 && strstr(buff, " ") != NULL) {
        printf("Fields cannot contain spaces!\n\n");
        return -1;
    }

    return 0;
}

//returns -1 if the string contains non-digit characters
int is_number(char *buff) {
    for (int i = 0; i < strlen(buff); i++) {
        if (isdigit(buff[i]) == 0) {
            return -1;
        }
    }
    return 0;
}

//returns a serialized JSON string containing 
//the username and password read from stdin
char *get_user() {
    //fetch username
    char username[BUFFLEN] = {0};
    printf("username=");
    fgets(username, BUFFLEN, stdin);
    username[strlen(username) - 1] = '\0';

    //fetch password
    char password[BUFFLEN] = {0};
    printf("password=");
    fgets(password, BUFFLEN, stdin);
    password[strlen(password) - 1] = '\0';

    //check if the username and password are valid
    if (check_format(username, 0) == -1) {
        return NULL;
    }
    if (check_format(password, 1) == -1) {
        return NULL;
    }

    //init the JSON object
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    
    return json_serialize_to_string(root_value);
}

//returns a serialized JSON string containing
//info about the book read from stdin
char *get_book() {
    //fetch title
    char title[BUFFLEN] = {0};
    printf("title=");
    fgets(title, BUFFLEN, stdin);
    title[strlen(title) - 1] = '\0';

    //fetch author
    char author[BUFFLEN] = {0};
    printf("author=");
    fgets(author, BUFFLEN, stdin);
    author[strlen(author) - 1] = '\0';

    //fetch genre
    char genre[BUFFLEN] = {0};
    printf("genre=");
    fgets(genre, BUFFLEN, stdin);
    genre[strlen(genre) - 1] = '\0';

    //fetch publisher
    char publisher[BUFFLEN] = {0};
    printf("publisher=");
    fgets(publisher, BUFFLEN, stdin);
    publisher[strlen(publisher) - 1] = '\0';

    //fetch page_count
    char page_count[BUFFLEN] = {0};
    printf("page_count=");
    fgets(page_count, BUFFLEN, stdin);
    page_count[strlen(page_count) - 1] = '\0';

    //check if the book info is valid
    if (check_format(title, 1) == -1) {
        return NULL;
    }
    if (check_format(author, 1) == -1) {
        return NULL;
    }
    if (check_format(genre, 1) == -1) {
        return NULL;
    }
    if (check_format(publisher, 1) == -1) {
        return NULL;
    }
    if (is_number(page_count) == -1) {
        printf("Page count must be a number!\n\n");
        return NULL;
    }

    //init the JSON object
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "title", title);
    json_object_set_string(root_object, "author", author);
    json_object_set_string(root_object, "genre", genre);
    json_object_set_string(root_object, "publisher", publisher);
    json_object_set_string(root_object, "page_count", page_count);

    return json_serialize_to_string(root_value);
}

//returns URL with book_id appended
char *get_book_id() {
    //fetch book_id
    char id[BUFFLEN] = {0};
    printf("id=");
    fgets(id, BUFFLEN, stdin);
    id[strlen(id) - 1] = '\0';
    if (is_number(id) == -1) {
        printf("Book id must be a number!\n\n");
        return NULL;
    }

    char url[BUFFLEN] = {0};
    strcpy(url, URL_GET_BOOK);
    strcat(url, id);

    return strdup(url);
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

        //open connection to server for each user command
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
            char *message = compute_post_request(host_ipaddr, URL_REGISTER, PAYLOAD_TYPE, serialized_string, NULL, NULL);
            send_to_server(sockfd, message);
            char *response = receive_from_server(sockfd);

            //check if registration was succesful
            if (strstr(response, "HTTP/1.1 400 Bad Request") != NULL && strstr(response, "{\"error\":\"The username ") != NULL) {
                //extract error message from response
                char *error_msg = strstr(response, "The username ");
                
                //remove the rest of the response
                int i = 0;
                while (error_msg[i] != '\"' && error_msg[i] != '\0')
                    i++;
                error_msg[i] = '\0';
                printf("%s\n", error_msg);
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
            char *message = compute_post_request(host_ipaddr, URL_LOGIN, PAYLOAD_TYPE, serialized_string, NULL, NULL);
            send_to_server(sockfd, message);
            char *response = receive_from_server(sockfd);

            //username not found or wrong password
            if (strstr(response, "HTTP/1.1 400 Bad Request") != NULL) {
                //extract error message from response
                char *error_msg = strstr(response, "{\"error\":\"");
                error_msg += strlen("{\"error\":\"");
                
                //remove the rest of the response
                int i = 0;
                while (error_msg[i] != '\"' && error_msg[i] != '\0')
                    i++;
                error_msg[i] = '\0';
                printf("Login failed! %s\n", error_msg);
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
                    JSON_Value *root_value;
                    JSON_Array *books_array;
                    JSON_Object *book_object;
                    root_value = json_parse_string(books);
                    books_array = json_value_get_array(root_value);

                    for (int i = 0; i < json_array_get_count(books_array); i++) {
                        book_object = json_array_get_object(books_array, i);
                        printf("\nid= %d\n", (int)json_object_get_number(book_object, "id"));
                        printf("title= %s\n", json_object_get_string(book_object, "title"));
                    }
                }
                else 
                    printf("No books in library!\n");
            }
            else printf("ERROR\n");
        }

        else if (strcmp(buff, "get_book\n") == 0) //GET_BOOK command
        {
            //check if user has access to library
            if (library_access == 0) {
                printf("You don't have access to library!\n\n");
                close_connection(sockfd);
                continue;
            }

            //get URL for GET_BOOK request with book id
            char *url = get_book_id();
            if (url == NULL) {
                close_connection(sockfd);
                continue;
            }

            //compute GET request, send it to server and receive response
            char *message = compute_get_request(host_ipaddr, url, NULL, session_cookie, jwt_token);
            send_to_server(sockfd, message);
            char *response = receive_from_server(sockfd);

            if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
                char *book = strstr(response, "{\"id\":");

                if (book != NULL) {
                    JSON_Value *root_value;
                    JSON_Object *book_object;
                    root_value = json_parse_string(book);
                    book_object = json_value_get_object(root_value);

                    printf("title= %s\n", json_object_get_string(book_object, "title"));
                    printf("author= %s\n", json_object_get_string(book_object, "author"));
                    printf("publisher= %s\n", json_object_get_string(book_object, "publisher"));
                    printf("genre= %s\n", json_object_get_string(book_object, "genre"));
                    printf("page_count= %d\n", (int)json_object_get_number(book_object, "page_count"));
                }
                else 
                    printf("No book was found with this id!\n");
            }
            else if (strstr(response, "HTTP/1.1 404 Not Found") != NULL)
                printf("No book was found with this id!\n");
            else 
                printf("ERROR\n");
        }

        else if (strcmp(buff, "add_book\n") == 0) //ADD_BOOK command
        {
            //check if user has access to library
            if (library_access == 0) {
                printf("You don't have access to library!\n\n");
                close_connection(sockfd);
                continue;
            }

            //get JSON object with book info
            char *serialized_string = get_book();
            if (serialized_string == NULL) {
                close_connection(sockfd);
                continue;
            }

            //compute POST request, send it to server and receive response
            char *message = compute_post_request(host_ipaddr, URL_ADD_BOOK, PAYLOAD_TYPE, serialized_string, session_cookie, jwt_token);
            send_to_server(sockfd, message);
            char *response = receive_from_server(sockfd);

            //printf("%s\n", response);
            if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
                printf("Book added succesfully!\n");
            }
            else printf("ERROR\n");
        }

        else if (strcmp(buff, "delete_book\n") == 0) //DELETE_BOOK command
        {
            //check if user has access to library
            if (library_access == 0) {
                printf("You don't have access to library!\n\n");
                close_connection(sockfd);
                continue;
            }

            //get URL for DELETE_BOOK request with book id
            char *url = get_book_id();
            if (url == NULL) {
                close_connection(sockfd);
                continue;
            }

            //compute DELETE request, send it to server and receive response
            char *message = compute_delete_request(host_ipaddr, url, session_cookie, jwt_token);
            send_to_server(sockfd, message);
            char *response = receive_from_server(sockfd);

            //print appropriate message
            if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
                printf("Book deleted succesfully!\n");
            }
            else if (strstr(response, "HTTP/1.1 404 Not Found") != NULL)
                printf("No book was found with this id!\n");
            else 
                printf("ERROR\n");
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

        else {
            printf("Invalid command!\n");
        }

        printf("\n");
        close_connection(sockfd);
    }
    
    return 0;
}
