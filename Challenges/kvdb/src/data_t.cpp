#include "kvdb.h"

/**
 * Release a data_t obj.
 * @param (data) data_t* data
 * @return 0-success other-error
 */
uint32 release_data_t(data_t* data) {
    switch (data->type) {
        case DATA_TYPE_EMPTY:
        case DATA_TYPE_INTEGER:
        case DATA_TYPE_FLOAT:
            free(data);
            return 0;
        case DATA_TYPE_STRING:
            free(data->str.ptr);
            free(data);
            return 0;
        case DATA_TYPE_ARRAY:
            for (uint32 i = 0; i < data->array.count; i++) {
                if (release_data_t(data->array.items[i])) {
                    free(data->array.items);
                    free(data);
                    return ~0;
                }
            }
            free(data->array.items);
            free(data);
            return 0;
        default:
            return ~0;
    }
};

/**
 * Return a new data_t obj by deepcopy
 * @param (data) data_t* data
 * @return pointer to new data_t obj
 */
data_t* copy_data_t(data_t* data) {
    data_t* tmp = (data_t*)calloc(1, sizeof(data_t));
    if (!tmp)
        return NULL;
    tmp->type = data->type;
    switch (data->type) {
        case DATA_TYPE_EMPTY:
            return tmp;
        case DATA_TYPE_INTEGER:
            tmp->integer = data->integer;
            return tmp;
        case DATA_TYPE_FLOAT:
            tmp->_float = data->_float;
            return tmp;
        case DATA_TYPE_STRING:
            tmp->str.len = data->str.len;
            tmp->str.ptr = (char*)calloc(tmp->str.len + 2, 1);
            if (!tmp->str.ptr) {
                free(tmp);
                return NULL;
            }
            memcpy(tmp->str.ptr, data->str.ptr, tmp->str.len);
            return tmp;
        case DATA_TYPE_ARRAY:
            data_t* new_item;
            tmp->array.count = data->array.count;
            tmp->array.items =
                (data_t**)calloc(data->array.count, sizeof(data_t*));
            for (uint32 i = 0; i < tmp->array.count; i++) {
                new_item = copy_data_t(data->array.items[i]);
                if (!new_item) {
                    /* Release all array elements that have been created and
                     * return NULL */
                    for (uint32 j = 0; j < i; j++) {
                        release_data_t(tmp->array.items[j]);
                    }
                    free(tmp->array.items);
                    free(tmp);
                    return NULL;
                }
                tmp->array.items[i] = new_item;
            }
            return tmp;
        default:
            return NULL;
    }
}

/**
 * Compare two data_t obj
 * @param (dst) data_t* dst
 * @param (src) data_t* src
 * @return 0-success other-error
 */
uint32 compare_data_t(data_t* dst, data_t* src) {
    uint32 i = 0;
    if (dst == NULL || src == NULL) {
        return 1;
    }
    /* check type */
    if (dst->type != src->type) {
        return 1;
    }
    switch (dst->type) {
        case DATA_TYPE_INTEGER:
            return dst->integer == src->integer ? 0 : 1;
        case DATA_TYPE_FLOAT:
            return dst->_float == src->_float ? 0 : 1;
        case DATA_TYPE_STRING:
            if (dst->str.len != src->str.len) {
                return 1;
            }
            return memcmp(dst->str.ptr, src->str.ptr, dst->str.len) == 0 ? 0
                                                                         : 1;
        case DATA_TYPE_ARRAY:
            if (dst->array.count != src->array.count) {
                return 1;
            }
            for (i = 0; i < dst->array.count; i++) {
                if (compare_data_t(dst->array.items[i], src->array.items[i])) {
                    return 1;
                }
            }
            return 0;
        case DATA_TYPE_EMPTY:
            return 0;
        default:
            return 1;
    }
}

/**
 * Construct a string type data_t obj by const char *
 * @param (str) data_t* str
 * @return pointer to string type data_t obj
 */
data_t* make_string(const char* str) {
    data_t* tmp = (data_t*)calloc(1, sizeof(data_t));
    if (!tmp)
        return NULL;
    tmp->type = DATA_TYPE_STRING;
    tmp->str.ptr = strdup(str);
    tmp->str.len = strlen(tmp->str.ptr);
    return tmp;
}

/**
 * Add a new pair<Data, Data> to database
 * @param (key) data_t* key
 * @param (value) data_t* value
 * @param (overwrite) 1-overwrite other-not overwrite
 * @return 0-success 1-failed
 */
uint32 add_data_item(data_t* key, data_t* value, uint32 overwrite) {
    if (!key || !value) {
        return 1;
    }
    if (overwrite) {
        delete_data_item(key);
    }
    Data key_obj(key);
    Data value_obj(value);
    database.push_back(kvpair(key_obj, value_obj));
    return 0;
}

/**
 * Delete kvpair<Data, Data> in database by specified key value
 * @param (key) data_t* key
 * @return 0-success 1-failed
 */
uint32 delete_data_item(data_t* key) {
    if (!key)
        return 1;
    Data vuln(key);
    std::list<kvpair>::iterator iter;
    for (iter = database.begin(); iter != database.end(); iter++) {
        if (iter->first == vuln) {
            /*delete old kvpair*/
            database.erase(iter);
            return 0;
        }
    }
    return 1;
}

/**
 * Modify the value corresponding to the specified key in the database
 * @param (key) data_t* key
 * @param (value) data_t* new_value
 * @return 0-success 1-failed
 */
uint32 modify_data_item(data_t* key, data_t* new_value) {
    if (!key || !new_value) {
        return 1;
    }
    Data vuln(key);
    std::list<kvpair>::iterator iter;
    for (iter = database.begin(); iter != database.end(); iter++) {
        if (iter->first == vuln) {
            iter->second.update_data_t(new_value);
            return 0;
        }
    }
    return 1;
}

/**
 * Rename the value corresponding to the specified key in the database
 * @param (old_key) data_t* old_key
 * @param (new_key) data_t* new_key
 * @return 0-success 1-failed
 */
uint32 rename_data_item(data_t* old_key, data_t* new_key) {
    if (!old_key || !new_key) {
        return 1;
    }
    Data vuln(old_key);
    std::list<kvpair>::iterator iter;
    for (iter = database.begin(); iter != database.end(); iter++) {
        if (iter->first == vuln) {
            iter->first.update_data_t(new_key);
            return 0;
        }
    }
    return 1;
}

/**
 * Copy the data item corresponding to SRC
 * to the data item corresponding to DST
 * @param (src_key) data_t* src_key
 * @param (dst_key) data_t* dst_key
 * @return 0-success 1-failed
 */
uint32 copy_data_item(data_t* src_key, data_t* dst_key) {
    if (!src_key || !dst_key) {
        return 1;
    }
    Data vuln(src_key);
    std::list<kvpair>::iterator iter;
    for (iter = database.begin(); iter != database.end(); iter++) {
        if (iter->first == vuln) {
            return add_data_item(dst_key, iter->second.get_data_t(), 0);
        }
    }
    return 1;
}

/**
 * Dump all key-value pairs in database.
 * @return pointer to array type data_t obj
 */
data_t *dump_data_item(){
    data_t *dump_array = (data_t *)calloc(1, sizeof(data_t));
    if(!dump_array) return NULL;
    dump_array->type = DATA_TYPE_ARRAY;
    dump_array->array.count = database.size();
    dump_array->array.items = (data_t **)calloc(dump_array->array.count, sizeof(data_t *));
    std::list<kvpair>::iterator iter;
    int i;
    for (iter = database.begin(), i = 0; iter != database.end(); iter++, i++) {
        /* item_array[2] = {key, value} */
        data_t *item_array = (data_t *)calloc(1, sizeof(data_t));
        item_array->type = DATA_TYPE_ARRAY;
        item_array->array.count = 2;
        item_array->array.items = (data_t **)calloc(2, sizeof(data_t *));
        item_array->array.items[0] = iter->first.get_data_t();
        item_array->array.items[1] = iter->second.get_data_t();
        dump_array->array.items[i] = item_array;
    }
    return dump_array;
}

/**
 * Delete all key-value pairs in database.
 * @return 0-success 1-failed
 */
uint32 clear_data_item(){
    std::list<kvpair>::iterator iter;
    if(database.size() == 0){
        return 1;
    }
    database.clear();
    return 0;
}

/**
 * Get the datat member of the data item corresponding
 * to the key from the database
 * @param (key) data_t* key
 * @return NOT_NULL-success NULL-failed
 */
data_t* get_data_item(data_t* key) {
    if (!key)
        return NULL;
    Data vuln(key);
    std::list<kvpair>::iterator iter;
    for (iter = database.begin(); iter != database.end(); iter++) {
        if (iter->first == vuln) {
            return iter->second.get_data_t();
        }
    }
    return NULL;
}