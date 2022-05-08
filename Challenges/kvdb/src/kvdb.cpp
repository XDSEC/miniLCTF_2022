/************************************************
 * File name: kvdb.c
 * Description: A simple key-value database.
 * Author: Eqqie
 * Version: 0.0.1
 ************************************************/
#include "kvdb.h"

uint32 socks_server_port = 9999;
uint32 max_requests = 32;
uint32 timeout = 64;
uint32 run_daemon = 0;
static char dev_null[] = "/dev/null";
static char *log_file = dev_null;

uint32 client_fd;

static uint16 accepted_types[] = {DATA_TYPE_EMPTY, DATA_TYPE_INTEGER,
                                  DATA_TYPE_FLOAT, DATA_TYPE_STRING,
                                  DATA_TYPE_ARRAY, DATA_TYPE_TERM};

static struct op_handler {
    char opcode[MAX_OP_SIZE + 1];
    uint32 (*handler)(int);
} accepted_ops[] = {
    {OPCODE_ADD, op_handler_ADD},       {OPCODE_DELETE, op_handler_DEL},
    {OPCODE_MODIFY, op_handler_MDF},    {OPCODE_RENAME, op_handler_RNM},
    {OPCODE_COPY, op_handler_CPY},      {OPCODE_GET, op_handler_GET},
    {OPCODE_SHUTDOWN, op_handler_SHUT}, {OPCODE_DUMP, op_handler_DUMP},
    {OPCODE_CLEAR, op_handler_CLR},     {OPCODE_TREM, NULL}};

std::list<kvpair> database;

Data::Data(void) {
    memset(data, 0, sizeof(data_t));
    data->type = DATA_TYPE_EMPTY;
}

Data::Data(data_t* value) {
    data = copy_data_t(value);
}

Data::Data(const Data& obj) {
    data = copy_data_t(obj.get_data_t());
}

Data::~Data() {
    release_data_t(data);
}

uint32 Data::update_data_t(data_t* a) {
    if (!a)
        return 1;
    data_t * target = a;
    if(data->type == target->type){
        switch (target->type)
        {
        case DATA_TYPE_INTEGER:
            data->integer = target->integer;
            return 0;
        case DATA_TYPE_FLOAT:
            data->_float = target->_float;
            return 0;
        case DATA_TYPE_STRING:
            if(target->str.len <= data->str.len){
                memcpy(data->str.ptr, target->str.ptr, target->str.len);
                data->str.len = target->str.len;
                return 0;
            } else{
                break;
            }
        default:
            break;
        }
    }
    data_t* old_data_t = data;
    data = copy_data_t(a);
    release_data_t(old_data_t);
    return 0;
}

uint32 Data::update_data_t(Data& a) {
    if (!a.get_data_t())
        return 1;
    data_t * target = a.get_data_t();
    if(data->type == target->type){
        switch (target->type)
        {
        case DATA_TYPE_INTEGER:
            data->integer = target->integer;
            return 0;
        case DATA_TYPE_FLOAT:
            data->_float = target->_float;
            return 0;
        case DATA_TYPE_STRING:
            if(target->str.len <= data->str.len){
                memcpy(data->str.ptr, target->str.ptr, target->str.len);
                data->str.len = target->str.len;
                return 0;
            } else{
                break;
            }
        default:
            break;
        }
    }
    data_t* old_data_t = data;
    data = copy_data_t(target);
    release_data_t(old_data_t);
    return 0;
}

data_t* Data::get_data_t() const{
    return data;
}

/**
 * Handle a new socket connection by passing a sock fd.
 * @param (sock) sock fd
 * @return 0-success other-error
 */
uint32 handle_request(int sock) {
    char magic_buf[4] = {0};
    char op_buf[MAX_OP_SIZE + 1] = {0};
    uint16 op_len_be = 0;
    uint16 op_len_le = 0;

    while (1) {
    FETCH_COMMAND:
        /* check MAGIC */
        memset(magic_buf, '\0', sizeof(magic_buf));
        memset(op_buf, '\0', sizeof(op_buf));
        if (readn(sock, magic_buf, MAGIC_SIZE) != MAGIC_SIZE) {
            resp_str(sock, "Bad Magic");
            return ~0;
        }
        if (memcmp(magic_buf, MAGIC, MAGIC_SIZE)) {
            resp_str(sock, "Bad Magic");
            return ~0;
        }

        /* read op */
        if (readn(sock, (char*)&op_len_be, sizeof(uint16)) != sizeof(uint16)) {
            resp_str(sock, "Bad Op Length");
            return ~0;
        }
        op_len_le = BigLittleSwap16(op_len_be);
        if (op_len_le > MAX_OP_SIZE) {
            resp_str(sock, "Bad Op Length");
            return ~0;
        }
        memset(op_buf, '\0', sizeof(op_buf));
        readn(sock, op_buf, op_len_le);

        /* find handler */
        op_handler* h = NULL;
        for (h = &accepted_ops[0]; h->opcode[0] && h->handler; h++) {
            if (!memcmp(op_buf, h->opcode, op_len_le)) {
                /* call handler */
                int res = h->handler(sock);
#ifdef DEBUG
                fprintf(stderr, "[%d] op_handler_%s() return %d\n", getpid(),
                        h->opcode, res);
#endif
                goto FETCH_COMMAND;
            }
        }
        /* unknown opcode return */
        resp_str(sock, "Op Not Found");
        return ~0;
    }
}

uint32 server_loop() {
    int sock_fd;
    struct sockaddr_in local_addr, client_addr;
    memset(&local_addr, 0, sizeof(local_addr));

    /* new socket (only IPv4 is supported now) */
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "server_loop(): Can not create sock_fd!" << std::endl;
        return 1;
    }
    /* reuse addr */
    int new_optval = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &new_optval,
                   sizeof(new_optval)) < 0) {
        std::cerr << "server_loop(): setsockopt()!" << std::endl;
        return 1;
    }
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // listen addr
    local_addr.sin_port = htons(socks_server_port);  // listen port
    socklen_t local_addr_len = sizeof(local_addr);

    if (bind(sock_fd, (struct sockaddr*)&local_addr, local_addr_len) < 0) {
        std::cerr << "server_loop(): bind()" << std::endl;
        return 1;
    }

    if (listen(sock_fd, max_requests) < 0) {
        std::cerr << "server_loop(): listen()" << std::endl;
        return 1;
    } else {
        printf("[%d] Listen on port %d.\n", getpid(), socks_server_port);
    }

    socklen_t client_addr_len = sizeof(client_addr);
    memset(&client_addr, 0, sizeof(client_addr));

    while (1) {
        /* loop */
        if ((client_fd = accept(sock_fd, (struct sockaddr*)&client_addr,
                                &client_addr_len)) < 0) {
            std::cerr << "server_loop(): accept()" << std::endl;
            return 1;
        } else {
            /* get address info */
            char ip_str[INET_ADDRSTRLEN+1] = {0}; 
            uint16 port;
            inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ip_str, sizeof(ip_str));
            port = ntohs(client_addr.sin_port);

            /* set TCP_NODELAY */
            new_optval = 1;
            if (setsockopt(client_fd, SOL_TCP, TCP_NODELAY, &new_optval,
                           sizeof(new_optval)) < 0) {
                fprintf(stderr,
                        "Warnning: Can not setsockopt() for client_fd %d",
                        client_fd);
            }

            /* fork process */
            int pid = fork();
            if (pid < 0) {
                continue;
            } else {
                if (pid == 0) { // subprocess
                    close(sock_fd);
                    /* set timeout */
                    if (timeout) {
                        alarm(timeout);
                        signal(SIGALRM, signal_handler);
                    }
                    
                    printf("[%d] Connection Established - %s:%d\n", getpid(), ip_str, port);

                    /* handle */
                    int res = handle_request(client_fd);

                    /* normal exit */
                    close_socket(client_fd);
                    exit(res);
                } else { // main process 
                    close(client_fd);
                    continue;
                }
            }
        }
        /* end loop */
    }
}

void signal_handler(int sig_num) {
    switch (sig_num) {
        case SIGALRM:
            fprintf(stderr, "[%d] \x1B[31mTimeout!\x1B[0m\n", getpid());
            close_socket(client_fd);
            exit(0);
        default:
            exit(-1);
    }
}

void prepare() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

int init_daemon(){
        // ignore I/O signal and STOP signal
        signal(SIGTTOU,SIG_IGN);
        signal(SIGTTIN,SIG_IGN);
        signal(SIGTSTP,SIG_IGN);
        signal(SIGHUP,SIG_IGN);

        // quit parent process
        int pid = fork();
        if (pid < 0) {
            return -1;
        }
        if (pid > 0) {
            exit(0); 
        }

        // new process group
        setsid(); 

        // ensure the process is not the process group leader
        pid = fork();
        if (pid < 0) {
            return -1;
        }
        if (pid > 0) {
            exit(0);
        }

        fprintf(stderr, "[%d] KVDB service started.\n", getpid());

        // redirect log message
        int fd1 = open(log_file, O_WRONLY);
        if(fd1 > 0){
            dup2(fd1, stdout->_fileno);
            dup2(fd1, stderr->_fileno);
            close(fd1);
        } else{
            fprintf(stderr, "[%d] \x1B[31mExit: Can not open file '%s'.\x1B[0m\n", getpid(), log_file);
            exit(-1);
        }
        // no stdin !!!
        int fd2 = open("/dev/null", O_WRONLY);
        if(fd2 > 0){
            dup2(fd2, stdin->_fileno);
            close(fd2);
        } else{
            close(stdin->_fileno);
        }
        
        umask(0);
        signal(SIGCHLD,SIG_IGN);

        return server_loop();
}

int main(int argc, char* argv[]) {
    prepare();
    int c;
    while ((c = getopt(argc, argv, "p:m:t:l:hd")) != -1) {
        switch (c) {
            case 'p':
                socks_server_port = atoi(optarg);
                break;
            case 'm':
                max_requests = atoi(optarg);
                break;
            case 't':
                timeout = atoi(optarg);
                break;
            case 'l':
                log_file = (char *)optarg;
            case 'd':
                run_daemon = 1;
                break;
            case 'h':
                std::cerr
                    << "kvdb [-p <port>] [-m <max_clients>] [-t <timeout sec>] [-l <log file>] [-d]"
                    << std::endl;
                exit(0);
            case '?':
                std::cerr << ("HELP: -h") << std::endl;
                exit(0);
        }
    }
    std::cout << "Loading key-value database..." << std::endl;

    if(run_daemon){
        init_daemon();
    } else{
        fprintf(stderr,
                "[%d] \x1B[33mNotice: Service is running in terminal mode - It "
                "should only be used for debugging!\x1B[0m\n",
                getpid());
        fprintf(stderr,
                "[%d] \x1B[33mYou can Run with '-d' for daemon mode.\x1B[0m\n",
                getpid());
    }

    return server_loop();
}
