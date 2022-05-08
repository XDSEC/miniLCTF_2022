#include "kvdb.h"

/* Network opcode handlers */

extern uint32 client_fd;

uint32 op_handler_ADD(int sock) {
    data_t* key = read_data_t(sock);
    if (!key) {
        resp_str(sock, "Key Error");
        return 1;
    }
    data_t* value = read_data_t(sock);
    if (!value) {
        resp_str(sock, "Value Error");
        release_data_t(key);
        return 1;
    }
    if (add_data_item(key, value, 1) != 0) {
        resp_str(sock, "Add Failed");
        release_data_t(key);
        release_data_t(value);
        return 1;
    }
    /* success */
    resp_str(sock, "Done");
    release_data_t(key);
    release_data_t(value);
    return 0;
}

uint32 op_handler_DEL(int sock) {
    data_t* key = read_data_t(sock);
    if (!key) {
        resp_str(sock, "Key Error");
        return 1;
    }
    if (delete_data_item(key) != 0) {
        resp_str(sock, "Delete Failed");
        release_data_t(key);
        return 1;
    }
    /* success */
    resp_str(sock, "Done");
    release_data_t(key);
    return 0;
}

uint32 op_handler_MDF(int sock) {
    data_t* key = read_data_t(sock);
    if (!key) {
        resp_str(sock, "Key Error");
        return 1;
    }
    data_t* new_value = read_data_t(sock);
    if (!new_value) {
        resp_str(sock, "Value Error");
        release_data_t(key);
        return 1;
    }
    if (modify_data_item(key, new_value) != 0) {
        resp_str(sock, "Modify Failed");
        release_data_t(key);
        release_data_t(new_value);
        return 1;
    }
    /* success */
    resp_str(sock, "Done");
    release_data_t(key);
    release_data_t(new_value);
    return 0;
}

uint32 op_handler_RNM(int sock) {
    data_t* key = read_data_t(sock);
    if (!key) {
        resp_str(sock, "Old Key Error");
        return 1;
    }
    data_t* new_key = read_data_t(sock);
    if (!new_key) {
        resp_str(sock, "New Key Error");
        release_data_t(key);
        return 1;
    }
    /* check dup */
    if (get_data_item(new_key) != NULL) {
        resp_str(sock, "Duplicate Key");
        release_data_t(key);
        release_data_t(new_key);
        return 1;
    }
    if (rename_data_item(key, new_key) != 0) {
        resp_str(sock, "Rename Failed");
        release_data_t(key);
        release_data_t(new_key);
        return 1;
    }
    /* success */
    resp_str(sock, "Done");
    release_data_t(key);
    release_data_t(new_key);
    return 0;
}

uint32 op_handler_CPY(int sock) {
    data_t* src_key = read_data_t(sock);
    if (!src_key) {
        resp_str(sock, "Src Key Error");
        return 1;
    }
    data_t* dst_key = read_data_t(sock);
    if (!dst_key) {
        resp_str(sock, "Dst Key Error");
        release_data_t(dst_key);
        return 1;
    }
    /* check dup */
    if (get_data_item(dst_key) != NULL) {
        resp_str(sock, "Duplicate Key");
        release_data_t(src_key);
        release_data_t(dst_key);
        return 1;
    }
    if (copy_data_item(src_key, dst_key) != 0) {
        resp_str(sock, "Copy Failed");
        release_data_t(src_key);
        release_data_t(dst_key);
        return 1;
    }
    /* success */
    resp_str(sock, "Done");
    release_data_t(src_key);
    release_data_t(dst_key);
    return 0;
}

uint32 op_handler_GET(int sock) {
    data_t* key = read_data_t(sock);
    if (!key) {
        resp_str(sock, "Key Error");
        return 1;
    }
    data_t* res = get_data_item(key);
    if (res == NULL) {
        /* return an empty type data_t */
        data_t* empty = (data_t*)calloc(sizeof(data_t), 1);
        if (empty) {
            empty->type = DATA_TYPE_EMPTY;
            do_resp(sock, empty);
            release_data_t(empty);
        } else {
            resp_str(sock, "Get Failed");
        }
        release_data_t(key);
        return 1;
    }
    /* success */
    do_resp(sock, res);
    release_data_t(key);
    return 0;
}

uint32 op_handler_DUMP(int sock){
    data_t *dump_array = dump_data_item();
    if(!dump_array){
        resp_str(sock, "Dump Failed");
        return 1;
    };
    do_resp(sock, dump_array);
    release_data_t(dump_array);
    return 0;
}

uint32 op_handler_CLR(int sock){
    if(clear_data_item()){
        resp_str(sock, "Clear Failed");
        return 1;
    }
    resp_str(sock, "Done");
    return 0;
}

uint32 op_handler_SHUT(int sock) {
    resp_str(sock, "Shutdown Received");
    close_socket(client_fd);
    exit(0);
}