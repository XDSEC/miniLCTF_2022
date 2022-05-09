#ifndef _KVDB_H
#define _KVDB_H

#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <utility>
#include <list>

typedef char int8;
typedef short int int16;
typedef int int32;
typedef long long int64;
typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;
typedef unsigned long long uint64;

#define BigLittleSwap16(A) \
    ((((uint16)(A)&0xff00) >> 8) | (((uint16)(A)&0x00ff) << 8))
#define BigLittleSwap32(A)                                                \
    ((((uint32)(A)&0xff000000) >> 24) | (((uint32)(A)&0x00ff0000) >> 8) | \
     (((uint32)(A)&0x0000ff00) << 8) | (((uint32)(A)&0x000000ff) << 24))
#define BigLittleSwap64(x)   (((uint64)x & 0x00000000000000ff) << 7*8)|\
							 (((uint64)x & 0x000000000000ff00) << 5*8)|\
							 (((uint64)x & 0x0000000000ff0000) << 3*8)|\
							 (((uint64)x & 0x00000000ff000000) << 1*8)|\
							 (((uint64)x & 0x000000ff00000000) >> 1*8)|\
							 (((uint64)x & 0x0000ff0000000000) >> 3*8)|\
							 (((uint64)x & 0x00ff000000000000) >> 5*8)|\
							 (((uint64)x & 0xff00000000000000) >> 7*8)

#define DATA_TYPE_EMPTY 0x0
#define DATA_TYPE_INTEGER 0x1
#define DATA_TYPE_FLOAT 0x2
#define DATA_TYPE_STRING 0x3
#define DATA_TYPE_ARRAY 0x4
#define DATA_TYPE_TERM 0xff

#define MAGIC_SIZE 4
#define MAX_OP_SIZE 15
#define MAGIC "KVDB"
#define OPCODE_ADD "ADD"
#define OPCODE_DELETE "DEL"
#define OPCODE_MODIFY "MDF"
#define OPCODE_RENAME "RNM"
#define OPCODE_COPY "CPY"
#define OPCODE_GET "GET"
#define OPCODE_DUMP "DUMP"
#define OPCODE_CLEAR "CLR"
#define OPCODE_SHUTDOWN "SHUT"
#define OPCODE_TREM "\0"

typedef uint64 data_integer_t;
typedef double data_float_t;
typedef struct data_string_t {
    uint32 len;
    char* ptr;
} data_string_t;
typedef struct data_t data_t;
typedef struct data_array_t {
    uint32 count;
    data_t** items;
} data_array_t;
typedef struct data_t {
    uint16 type;
    union {
        data_integer_t integer;
        data_float_t _float;
        data_string_t str;
        data_array_t array;
    };
} data_t;

/* methods of database layer */

extern uint32 add_data_item(data_t* key, data_t* value, uint32 overwrite);
extern uint32 delete_data_item(data_t* key);
extern uint32 modify_data_item(data_t* key, data_t *new_value);
extern uint32 rename_data_item(data_t* old_key, data_t *new_key);
extern uint32 copy_data_item(data_t* src_key, data_t *dst_key);
extern data_t *get_data_item(data_t* key);
extern data_t *dump_data_item();
extern uint32 clear_data_item();

/* methods of data_t obj*/

extern uint32 release_data_t(data_t* data);
extern data_t* copy_data_t(data_t* data);
extern uint32 compare_data_t(data_t* dst, data_t* src);
extern data_t* make_string(const char* str);

/* Network opcode handlers */

extern uint32 op_handler_ADD(int sock);
extern uint32 op_handler_DEL(int sock);
extern uint32 op_handler_MDF(int sock);
extern uint32 op_handler_RNM(int sock);
extern uint32 op_handler_CPY(int sock);
extern uint32 op_handler_GET(int sock);
extern uint32 op_handler_DUMP(int sock);
extern uint32 op_handler_CLR(int sock);
extern uint32 op_handler_SHUT(int sock);

/* signal handlers */

typedef void (*__sighandler_t)(int);
extern void signal_handler(int);

/* IO */

uint32 get_socket_state(int sock);
void close_socket(int sock);
extern uint32 readn(int stream, char* buffer, uint32 maxlen);
extern unsigned int writen(int stream, char* buffer, uint32 maxlen);
extern data_t* read_data_t(int sock);
extern data_t* do_read_data_t(int sock, int level);
extern void resp_str(int sock, const char* str);
extern void do_resp(int sock, data_t* resp_data);
extern void internal_do_resp(int sock, data_t* resp_data, int level);

class Data {
   public:
    Data(void);
    Data(data_t* value);
    Data(const Data& obj);
    ~Data(void);
    Data& operator=(const Data& x) {
        data = copy_data_t(x.get_data_t());
        return *this;
    }
    bool operator==(Data& x) {
        data_t* src = data;
        data_t* dst = x.get_data_t();
        return compare_data_t(dst, src) ? false : true;
    }
    uint32 update_data_t(data_t* a);
    uint32 update_data_t(Data& a);
    data_t* get_data_t() const;

   private:
    data_t* data;
};

typedef std::pair<Data, Data> kvpair;
extern std::list<kvpair> database;

#endif