#include "kvdb.h"

extern uint32 client_fd;

uint32 get_socket_state(int sock){
  struct tcp_info info; 
  uint32 len = sizeof(info); 
  getsockopt(sock, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&len); 
  return info.tcpi_state;
}

void close_socket(int sock){
    sockaddr_storage storage;
    socklen_t sock_len = sizeof(storage);
    char ip_str[INET_ADDRSTRLEN+1] = {0}; 
    char ip6_str[INET6_ADDRSTRLEN+1] = {0}; 
    uint16 port;

    int ret = getpeername(sock, (sockaddr*)&storage, &sock_len);  
    shutdown(sock, SHUT_RDWR);
 
    if(!(ret < 0)){
        if (storage.ss_family == AF_INET){
            sockaddr_in* addr = (sockaddr_in* )&storage;
            inet_ntop(AF_INET, &addr->sin_addr.s_addr, ip_str, sizeof(ip_str));
            port = ntohs(addr->sin_port);
            printf("[%d] Connection Closed - %s:%d\n", getpid(), ip_str, port);
        }
        /* This code is not used, but must be written... */
        if(storage.ss_family == AF_INET6){
            sockaddr_in6* addr = (sockaddr_in6* )&storage;
            inet_ntop(AF_INET6, &addr->sin6_addr, ip6_str, sizeof(ip6_str));
            port = ntohs(addr->sin6_port);
            printf("[%d] Connection Closed - %s:%d\n", getpid(), ip6_str, port);
        }
    } else{
        printf("[%d] Connection Closed.\n", getpid());
    }
}

/**
 * Read N bytes to target stream
 * @param (stream) int stream
 * @param (buffer) char* buffer,
 * @param (maxlen) int maxlen
 * @return read count
 */
uint32 readn(int stream, char* buffer, uint32 maxlen) {
    uint32 total = 0;
    int rn = 0;
    while (total < maxlen) {
        rn = read(stream, buffer + total, maxlen - total);
        if (rn <= 0) {
            if(stream == client_fd && get_socket_state(stream) != TCP_ESTABLISHED){
                fprintf(stderr, "[%d] \x1B[33mData stream [READ] interrupted!\x1B[0m\n", getpid());
                close_socket(stream);
                exit(-1);
            }
            return total;
        } else {
            total += rn;
        }
    }
    return total;
}

/**
 * Write N bytes to target stream
 * @param (stream) int stream
 * @param (buffer) char* buffer,
 * @param (maxlen) int maxlen
 * @return write count
 */
unsigned int writen(int stream, char* buffer, uint32 maxlen) {
    uint32 total = 0;
    int wn = 0;
    while (total < maxlen) {
        wn = write(stream, buffer + total, maxlen - total);
        if (wn <= 0) {
            if(stream == client_fd && get_socket_state(stream) != TCP_ESTABLISHED){
                fprintf(stderr, "[%d] \x1B[33mData stream [WRITE] interrupted!\x1B[0m\n", getpid());
                close_socket(stream);
                exit(-1);
            }
            return total;
        } else {
            total += wn;
        }
    }
    return total;
}

/**
 * Returns a serialized data_t object
 * @brief Returns a serialized data_t object
 * @param (sock) client sock
 * @param (str) Pointer to the data_t object to be returned
 * @return non-return
 */
void do_resp(int sock, data_t* resp_data){
    internal_do_resp(sock, resp_data, 0);
}

void internal_do_resp(int sock, data_t* resp_data, int level) {
    uint16 type_be = 0;
    uint64 integer_be = 0;
    data_float_t float_be = 0;
    uint32 str_len_be = 0;
    char* str_ptr = NULL;
    uint32 count_be = 0;

    if (!resp_data){
        // write empty obj for null
        writen(sock, (char*)MAGIC, MAGIC_SIZE);
        type_be = BigLittleSwap16(DATA_TYPE_EMPTY);
        writen(sock, (char*)&type_be, sizeof(uint16));
        return;
    }
    // finishe this!
    type_be = BigLittleSwap16(resp_data->type);
    /* check level */
    if(!level){
        writen(sock, (char*)MAGIC, MAGIC_SIZE);
    }
    /* switch case */
    switch (resp_data->type) {
        case DATA_TYPE_INTEGER:
            integer_be = BigLittleSwap64(resp_data->integer);
            writen(sock, (char*)&type_be, sizeof(uint16));
            writen(sock, (char*)&integer_be, sizeof(data_integer_t));
            return;
        case DATA_TYPE_FLOAT:
            *(uint64*)&float_be = BigLittleSwap64(*(uint64*)&resp_data->_float);
            writen(sock, (char*)&type_be, sizeof(uint16));
            writen(sock, (char*)&float_be, sizeof(data_float_t));
            return;
        case DATA_TYPE_STRING:
            str_len_be = BigLittleSwap32(resp_data->str.len);
            str_ptr = resp_data->str.ptr;
            writen(sock, (char*)&type_be, sizeof(uint16));
            writen(sock, (char*)&str_len_be, sizeof(uint32));
            writen(sock, str_ptr, resp_data->str.len);
            return;
        case DATA_TYPE_ARRAY:
            count_be = BigLittleSwap32(resp_data->array.count);
            writen(sock, (char*)&type_be, sizeof(uint16));
            writen(sock, (char*)&count_be, sizeof(uint32));
            for (uint32 i = 0; i < resp_data->array.count; i++) {
                internal_do_resp(sock, resp_data->array.items[i], level+1);
            }
            return;
        case DATA_TYPE_EMPTY:
            writen(sock, (char*)&type_be, sizeof(uint16));
            return;
        default:
            resp_str(sock, "Unknown error!");
            return;
    }
}

/**
 * Returns a string
 * @brief Returns a string
 * @param (sock) client sock
 * @param (str) Pointer to the string to be returned
 * @return non-return
 */
void resp_str(int sock, const char* str) {
    data_t *str_obj = make_string(str);
    do_resp(sock, str_obj);
    release_data_t(str_obj);
}

/**
 * construct a data_t obj from stream
 * @brief construct a data_t obj from stream
 * @param (sock) client sock
 * @return data_t reference
 */
data_t* read_data_t(int sock) {
    return do_read_data_t(sock, 0);
}

data_t* do_read_data_t(int sock, int level) {
    uint16 type_be;
    uint16 type_le;

    /* new data_t obj */
    data_t* tmp = (data_t*)calloc(1, sizeof(data_t));
    if (!tmp)
        return NULL;

    // integer
    data_integer_t integer_be = 0;
    // float
    data_float_t float_be = 0;
    // string
    uint32 str_len_be = 0;
    uint32 str_len_le = 0;
    // array
    uint32 count_be = 0;
    uint32 count_le = 0;
    data_t* item = NULL;

    readn(sock, (char*)&type_be, sizeof(uint16));
    type_le = BigLittleSwap16(type_be);

    int l;

    switch (type_le) {
        case DATA_TYPE_INTEGER:
            tmp->type = DATA_TYPE_INTEGER;
            if (readn(sock, (char*)&integer_be, sizeof(data_integer_t)) !=
                sizeof(data_integer_t)) {
                goto INVALID;
            }
            tmp->integer = BigLittleSwap64(integer_be);
#ifdef DEBUG
            fprintf(stderr, "[%d] ", getpid());
            for (int l = 0; l < level; l++) {
                printf("- ");
            }
            fprintf(stderr, "Integer: \x1B[36m0x%llx\x1B[0m\n", tmp->integer);
#endif
            return tmp;
        case DATA_TYPE_FLOAT:
            tmp->type = DATA_TYPE_FLOAT;
            if (readn(sock, (char*)&float_be, sizeof(data_float_t)) !=
                sizeof(data_float_t)) {
                goto INVALID;
            }
            *(uint64*)&tmp->_float = BigLittleSwap64(*(uint64*)&float_be);
#ifdef DEBUG
            fprintf(stderr, "[%d] ", getpid());
            for (int l = 0; l < level; l++) {
                printf("- ");
            }
            fprintf(stderr, "Float: \x1B[35m%lf\x1B[0m\n", tmp->_float);
#endif
            return tmp;
        case DATA_TYPE_STRING:
            tmp->type = DATA_TYPE_STRING;
            if (readn(sock, (char*)&str_len_be, sizeof(uint32)) !=
                sizeof(uint32)) {
                goto INVALID;
            }
            str_len_le = BigLittleSwap32(str_len_be);
            tmp->str.len = str_len_le;
            tmp->str.ptr = (char*)calloc(str_len_le, 1);
            if (!tmp->str.ptr)
                goto INVALID;
            readn(sock, tmp->str.ptr, str_len_le);
#ifdef DEBUG
            fprintf(stderr, "[%d] ", getpid());
            for (int l = 0; l < level; l++) {
                printf("- ");
            }
            fprintf(stderr, "String(%d): \x1B[32m%s\x1B[0m\n", tmp->str.len, tmp->str.ptr);
#endif
            return tmp;
        case DATA_TYPE_ARRAY:
            tmp->type = DATA_TYPE_ARRAY;
            if (readn(sock, (char*)&count_be, sizeof(uint32)) !=
                sizeof(uint32)) {
                goto INVALID;
            }
            count_le = BigLittleSwap32(count_be);
            tmp->array.count = count_le;
            tmp->array.items = (data_t**)calloc(count_le, sizeof(data_t*));
#ifdef DEBUG
            fprintf(stderr, "[%d] ", getpid());
            for (int l = 0; l < level; l++) {
                printf("- ");
            }
            fprintf(stderr, "\x1B[107mArray[%d]\x1B[0m:\n", tmp->array.count);
#endif
            for (uint32 i = 0; i < count_le; i++) {
                item = do_read_data_t(sock, level + 1);
                if (item == NULL) {
                    /* release all received items when error occur */
                    for (uint32 j = 0; j < i; j++) {
                        release_data_t(tmp->array.items[j]);
                        free(tmp->array.items);
                        goto INVALID;
                    }
                }
                tmp->array.items[i] = item;
            }
            return tmp;
        case DATA_TYPE_EMPTY:
#ifdef DEBUG
            fprintf(stderr, "[%d] ", getpid());
            for (int l = 0; l < level; l++) {
                printf("- ");
            }
            fprintf(stderr, "Empty data_t\n");
#endif
            tmp->type = DATA_TYPE_EMPTY;
            return tmp;
        default:
            goto INVALID;
            break;
    }
INVALID:
    free(tmp);
    return NULL;
}