#include <vector>
#include <functional>
#include <cstdint>
#include <cassert>
#include <string>
#include <cstring>
#include <iostream>
#include <ctime>
#include <pthread.h>

#include <sys/types.h>        
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

 #include <sys/epoll.h>

#define INF 0
#define DBG 1
#define ERR 2
#define LOG_LEVEL DBG

#define LOG(level, format, ...) do{\
        if (level < LOG_LEVEL) break;\
        time_t t = time(NULL);\
        struct tm *ltm = localtime(&t);\
        char tmp[32] = {0};\
        strftime(tmp, 31, "%H:%M:%S", ltm);\
        fprintf(stdout, "[%p %s %s:%d] " format "\n", (void*)pthread_self(), tmp, __FILE__, __LINE__, ##__VA_ARGS__);\
    }while(0)

#define INF_LOG(format, ...) LOG(INF, format, ##__VA_ARGS__)
#define DBG_LOG(format, ...) LOG(DBG, format, ##__VA_ARGS__)
#define ERR_LOG(format, ...) LOG(ERR, format, ##__VA_ARGS__)


#define BUFFER_DEFAULT_SIZE 1024

class Buffer {
private:
    std::vector<char> _buffer;
    uint64_t _r_idx;
    uint64_t _w_idx;
public:
    Buffer() : _r_idx(0), _w_idx(0), _buffer(BUFFER_DEFAULT_SIZE) {}
    inline char* begin() { return &*_buffer.begin(); }
    inline char* writePosion() {return begin() + _w_idx; }
    inline char* readPosition() { return begin() + _r_idx; }
    //缓冲区末尾空间大小
    inline uint64_t tailIdleSize() { return _buffer.size() - _w_idx; }
    //缓冲区起始空间大小
    inline uint64_t headIdleSize() { return _r_idx; }
    inline uint64_t readAbleSize() { return _w_idx - _r_idx; }
    //将读向后便宜
    inline void moveReadOffset(uint64_t len) {
        assert(len <= readAbleSize());
        _r_idx += len;
    }
    inline void moveWriteOffset(uint64_t len) {
        assert(len <= tailIdleSize());
        _w_idx += len;   
    }
    void ensureWSpace(uint64_t len) {
        if (tailIdleSize() >= len) { return; }
        if (len <= tailIdleSize() + headIdleSize()) {
            uint64_t rsz = readAbleSize();
            std::copy(readPosition(), readPosition() + rsz, _buffer.begin());
            _r_idx = 0;
            _w_idx = rsz;
        } else {
            _buffer.resize(_w_idx + len);
        }
    }
    void write(const void* data, uint64_t w_len) {
        ensureWSpace(w_len);
        const char* d = (const char*)data;
        std::copy(d, d + w_len, writePosion());
    }
    void writeString(const std::string& data) {
        return write(data.c_str(), data.size());
    }
    void writeStringAndMove(const std::string &data) {
            writeString(data);
            moveWriteOffset(data.size());
    }
    void writeBuffer(Buffer& data) {
        return write(data.readPosition(), data.readAbleSize());
    }
    void writeBufferAndMove(Buffer &data) { 
            writeBuffer(data);
            moveWriteOffset(data.readAbleSize());
    }
    void read(void* buf, uint64_t r_len) {
        assert(r_len <= readAbleSize());
        std::copy(readPosition(), readPosition() + r_len, (char*)buf);
    }
    void ReadAndMove(void *buf, uint64_t len) {
            read(buf, len);
            moveReadOffset(len);
    }
    std::string readAsString(uint64_t len) {
        //要求要获取的数据大小必须小于可读数据大小
        assert(len <= readAbleSize());
        std::string str;
        str.resize(len);
        read(&str[0], len);
        return str;
    }
    std::string readAsStringAndMove(uint64_t len) {
        assert(len <= readAbleSize());
        std::string str = readAsString(len);
        moveReadOffset(len);
        return str;
    }
    // 查找'/n'
    char *findCRLF() {
        char *res = (char*)memchr(readPosition(), '\n', readAbleSize());
        return res;
    }
    std::string getLine() {
        char *pos = findCRLF();
        if (pos == nullptr) {
            return "";
        }
        return readAsString(pos - readPosition() + 1);   //+1取出换行字符
    }
    std::string getLineAndMove() {
        std::string str = getLine();
        moveReadOffset(str.size());
        return str;
    }

    //清空缓冲区
    void clear() {
        _r_idx = 0;
        _w_idx = 0;
    }
};

#define MAX_LISTEN 1024
class Socket {
    private:
        int _sockfd;
    public:
        Socket():_sockfd(-1) {}
        Socket(int fd): _sockfd(fd) {}
        ~Socket() { _close(); }
        int fd() { return _sockfd; }
        bool _create() {
            _sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (_sockfd < 0) {
                ERR_LOG("CREATE SOCKET FAILED!!");
                return false;
            }
            return true;
        }
        bool _bind(const std::string &ip, uint16_t port) {
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = inet_addr(ip.c_str());
            socklen_t len = sizeof(struct sockaddr_in);
            int ret = bind(_sockfd, (struct sockaddr*)&addr, len);
            if (ret < 0) {
                ERR_LOG("BIND ADDRESS FAILED!");
                return false;
            }
            return true;
        }
        bool _listen(int backlog = MAX_LISTEN) {
            int ret = listen(_sockfd, backlog);
            if (ret < 0) {
                ERR_LOG("SOCKET LISTEN FAILED!");
                return false;
            }
            return true;
        }
        bool _connect(const std::string &ip, uint16_t port) {
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = inet_addr(ip.c_str());
            socklen_t len = sizeof(struct sockaddr_in);
            int ret = connect(_sockfd, (struct sockaddr*)&addr, len);
            if (ret < 0) {
                ERR_LOG("CONNECT SERVER FAILED!");
                return false;
            }
            return true;
        }
        int _accept() {
            int newfd = accept(_sockfd, nullptr, nullptr);
            if (newfd < 0) {
                ERR_LOG("SOCKET ACCEPT FAILED!");
                return -1;
            }
            return newfd;
        }
        ssize_t _recv(void *buf, size_t len, int flag = 0) {
            ssize_t ret = recv(_sockfd, buf, len, flag);
            if (ret <= 0) {
                //EAGAIN 当前socket的接收缓冲区中没有数据了，在非阻塞的情况下才会有这个错误
                //EINTR  表示当前socket的阻塞等待，被信号打断了
                if (errno == EAGAIN || errno == EINTR) {
                    return 0;//表示这次接收没有接收到数据
                }
                ERR_LOG("SOCKET RECV FAILED!!");
                return -1;
            }
            return ret; 
        }
        ssize_t nonBlockRecv(void *buf, size_t len) {
            return _recv(buf, len, MSG_DONTWAIT); // MSG_DONTWAIT 表示当前接收为非阻塞。
        }
        ssize_t _send(const void *buf, size_t len, int flag = 0) {
            ssize_t ret = send(_sockfd, buf, len, flag);
            if (ret < 0) {
                if (errno == EAGAIN || errno == EINTR) {
                    return 0;
                }
                ERR_LOG("SOCKET SEND FAILED!!");
                return -1;
            }
            return ret;
        }
        ssize_t nonBlockSend(void *buf, size_t len) {
            if (len == 0) return 0;
            
            return _send(buf, len, MSG_DONTWAIT); // MSG_DONTWAIT 表示当前发送为非阻塞。
        }
        void _close() {
            if (_sockfd != -1) {
                close(_sockfd);
                _sockfd = -1;
            }
        }
        // server
        bool createServer(uint16_t port, const std::string &ip = "0.0.0.0", bool is_block = false) {
            //1. 创建套接字，2. 绑定地址，3. 开始监听，4. 设置非阻塞， 5. 启动地址重用
            if (_create() == false) { return false; }
            if (is_block) { NonBlock(); }
            if (_bind(ip, port) == false) { return false; }
            if (_listen() == false) { return false; }
            reuseAddress();
            return true;
        }
        // client
        bool createClient(uint16_t port, const std::string &ip) {
            if (_create() == false) return false;
            if (_connect(ip, port) == false) return false;
            return true;
        }
        //设置套接字选项---开启地址端口重用
        void reuseAddress() {
            // int setsockopt(int fd, int leve, int optname, void *val, int vallen)
            int val = 1;
            setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR, (void*)&val, sizeof(int));
            val = 1;
            setsockopt(_sockfd, SOL_SOCKET, SO_REUSEPORT, (void*)&val, sizeof(int));
        }
        //设置套接字阻塞属性-- 设置为非阻塞
        void NonBlock() {
            int flag = fcntl(_sockfd, F_GETFL, 0);  //获取属性
            fcntl(_sockfd, F_SETFL, flag | O_NONBLOCK);     //设置非阻塞
        }
};


class Poller;
class EventLoop;
class Channel {
    private:
        int _fd;
        EventLoop *_loop;
        uint32_t _events;  // 当前需要监控的事件
        uint32_t _revents; // 当前连接触发的事件
        using eventCallback = std::function<void()>;
        eventCallback _read_callback;   
        eventCallback _write_callback;  
        eventCallback _error_callback; 
        eventCallback _close_callback;  
        eventCallback _event_callback; 
    public:
        Channel(EventLoop *loop, int fd):_fd(fd), _events(0), _revents(0), _loop(loop) {}
        inline int fd() { return _fd; }
        inline uint32_t events() { return _events; }
        inline void setREvents(uint32_t e) { _revents = e; }
        inline void setReadCallback(const eventCallback &cb) { _read_callback = cb; }
        inline void setWriteCallback(const eventCallback &cb) { _write_callback = cb; }
        inline void setErrorCallback(const eventCallback &cb) { _error_callback = cb; }
        inline void setCloseCallback(const eventCallback &cb) { _close_callback = cb; }
        inline void seteventCallback(const eventCallback &cb) { _event_callback = cb; }
        //当前是否监控了可读
        inline bool readAble() { return (_events & EPOLLIN); } 
        //当前是否监控了可写
        inline bool writeAble() { return (_events & EPOLLOUT); }
        //启动读事件监控
        void enableRead() { 
            _events |= EPOLLIN;
            update(); 
        }
        //启动写事件监控
        void enableWrite() { _events |= EPOLLOUT; update(); }
        //关闭读事件监控
        void disableRead() { _events &= ~EPOLLIN; update(); }
        //关闭写事件监控
        void disableWrite() { _events &= ~EPOLLOUT; update(); }
        //关闭所有事件监控
        void disableAll() { _events = 0; update(); }
        //移除监控
        void remove();
        //更新到eventloop事件监控中
        void update();
        //事件处理，一旦连接触发了事件，就调用这个函数，自己触发了什么事件如何处理自己决定
        void handleEvent() {
            //                             EPOLLRDHUP对方关闭链接          EPOLLPRI带外数据           
            if ((_revents & EPOLLIN) || (_revents & EPOLLRDHUP) || (_revents & EPOLLPRI)) {
                if (_read_callback) _read_callback();
                if (_event_callback) _event_callback();     //刷新活跃度

            }
            /*有可能会释放连接的操作事件，一次只处理一个*/
            if (_revents & EPOLLOUT) {
                if (_write_callback) _write_callback();
                if (_event_callback) _event_callback(); 
            }else if (_revents & EPOLLERR) {
                if (_event_callback) _event_callback(); 
                if (_error_callback) _error_callback();
            }else if (_revents & EPOLLHUP) {
                if (_event_callback) _event_callback(); 
                if (_close_callback) _close_callback();
            }
        }
};

#define MAX_EPOLLEVENTS 1024
class Poller {
    private:
        int _epfd;
        struct epoll_event _events[MAX_EPOLLEVENTS];
        std::unordered_map<int, Channel *> _channels;
    private:
        void update(Channel *channel, int op) {
            int fd = channel->fd();
            struct epoll_event ev;
            ev.data.fd = fd;
            ev.events = channel->events();
            // int epoll_ctl(int epfd, int op,  int fd,  struct epoll_event *ev);
            int ret = epoll_ctl(_epfd, op, fd, &ev);
            if (ret < 0) {
                ERR_LOG("EPOLLCTL FAILED!");
            }
            return;
        }
        //判断一个Channel是否已经添加了事件监控
        inline bool hasChannel(Channel *channel) { return _channels.contains(channel->fd()); }
    public:
        Poller() {
            _epfd = epoll_create(MAX_EPOLLEVENTS);
            if (_epfd < 0) {
                ERR_LOG("EPOLL CREATE FAILED!!");
                abort();
            }
        }
        //添加或修改监控事件
        void updateEvent(Channel *channel) {
            if (!hasChannel(channel)) {
                _channels.emplace(channel->fd(), channel);
                return update(channel, EPOLL_CTL_ADD);
            }
            return update(channel, EPOLL_CTL_MOD);
        }
        //移除监控
        void removeEvent(Channel *channel) {
            _channels.erase(channel->fd());        //返回0表示没有添加channel事件监控
            update(channel, EPOLL_CTL_DEL);
        }
        //开始监控，返回活跃连接
        void _poll(std::vector<Channel*> *active) {
            // int epoll_wait(int epfd, struct epoll_event *evs, int maxevents, int timeout)
            int nready = epoll_wait(_epfd, _events, MAX_EPOLLEVENTS, -1);
            if (nready < 0) {
                // 阻塞被信号打断了
                if (errno == EINTR) {
                    return;
                }
                ERR_LOG("EPOLL WAIT ERROR:%s\n", strerror(errno));
                abort();
            }
            for (int i = 0; i < nready; i++) {
                auto it = _channels.find(_events[i].data.fd);
                assert(it != _channels.end());
                it->second->setREvents(_events[i].events);//设置实际就绪的事件
                active->push_back(it->second);
            }
            return; 
        }
};