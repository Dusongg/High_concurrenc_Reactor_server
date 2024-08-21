#ifndef __SERVER_HPP_
#define __SERVER_HPP_
#include <unordered_map>
#include <utility>
#include <vector>
#include <functional>
#include <cstdint>
#include <cassert>
#include <string>
#include <cstring>
#include <iostream>
#include <ctime>
#include <cstdlib>
#include <pthread.h>

#include "glog/logging.h"

//Channel
#include <sys/types.h>        
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

//Poller
#include <sys/epoll.h>

//EventLoop
#include <thread>
#include <memory>
#include <sys/eventfd.h>
#include <mutex>

//timmer
#include <sys/timerfd.h>

#include "component/any.hpp"

// LoopThread
#include <condition_variable>

#include <csignal>

//LOG
#define INF 0
#define DBG 1
#define ERR 2
#define LOG_LEVEL DBG

//#define LOG(level, format, ...) do{\
//        if (level < LOG_LEVEL) break;\
//        time_t t = time(NULL);\
//        struct tm *ltm = localtime(&t);\
//        char tmp[32] = {0};\
//        strftime(tmp, 31, "%H:%M:%S", ltm);\
//        fprintf(stdout, "[%p %s %s:%d] " format "\n", (void*)pthread_self(), tmp, __FILE__, __LINE__, ##__VA_ARGS__);\
//    }while(0)
//
//#define INF_LOG(format, ...) LOG(INF, format, ##__VA_ARGS__)
//#define DBG_LOG(format, ...) LOG(DBG, format, ##__VA_ARGS__)
//#define ERR_LOG(format, ...) LOG(ERR, format, ##__VA_ARGS__)


#define BUFFER_DEFAULT_SIZE 1024

class Buffer {
private:
    std::vector<char> _buffer;
    uint64_t _r_idx;
    uint64_t _w_idx;
public:
    Buffer() : _r_idx(0), _w_idx(0), _buffer(BUFFER_DEFAULT_SIZE) {}
    inline char* begin() { return &*_buffer.begin(); }
    inline char* writePosition() {return begin() + _w_idx; }
    inline char* readPosition() { return begin() + _r_idx; }
    //缓冲区末尾空间大小
    inline uint64_t tailIdleSize() { return _buffer.size() - _w_idx; }
    //缓冲区起始空间大小
    [[nodiscard]] inline uint64_t headIdleSize() const { return _r_idx; }
    [[nodiscard]] inline uint64_t readAbleSize() const { return _w_idx - _r_idx; }
    //将读向后便宜
    inline void moveReadOffset(uint64_t len) {
        if(len == 0) return;
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
            std::copy(readPosition(), readPosition() + rsz, begin());
            _r_idx = 0;
            _w_idx = rsz;
        } else {
//            DBG_LOG("resize %ld", _w_idx + len);
            _buffer.resize(_w_idx + len);
        }
    }
    void write(const void* data, uint64_t w_len) {
        if (w_len == 0) return;
        ensureWSpace(w_len);
        const char* d = (const char*)data;
        std::copy(d, d + w_len, writePosition());
    }
    void writeAndMove(const void* data, uint64_t w_len) {
        write(data, w_len);
        moveWriteOffset(w_len);
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
    explicit Socket(int fd): _sockfd(fd) {}
    ~Socket() { Close(); }
    [[nodiscard]] int fd() const { return _sockfd; }
    bool Create() {
        _sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (_sockfd < 0) {
            LOG(ERROR) << "CREATE SOCKET FAILED!!";
            return false;
        }
        return true;
    }
    [[nodiscard]] bool Bind(const std::string &ip, uint16_t port) const {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        socklen_t len = sizeof(struct sockaddr_in);
        int ret = bind(_sockfd, (struct sockaddr*)&addr, len);
        if (ret < 0) {
            LOG(ERROR) << "BIND ADDRESS FAILED!";
            return false;
        }
        return true;
    }
    [[nodiscard]] bool Listen(int backlog = MAX_LISTEN) const {
        int ret = listen(_sockfd, backlog);
        if (ret < 0) {
            LOG(ERROR) << "SOCKET LISTEN FAILED!";
            return false;
        }
        return true;
    }
    [[nodiscard]] bool Connect(const std::string &ip, uint16_t port) const {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        socklen_t len = sizeof(struct sockaddr_in);
        int ret = connect(_sockfd, (struct sockaddr*)&addr, len);
        if (ret < 0) {
            LOG(ERROR) <<"CONNECT SERVER FAILED!";

            return false;
        }
        return true;
    }
    [[nodiscard]] int Accept() const {
        int newfd = accept(_sockfd, nullptr, nullptr);
        if (newfd < 0) {
            LOG(ERROR) << "SOCKET ACCEPT FAILED!";
            return -1;
        }
        return newfd;
    }
    [[nodiscard]]ssize_t Recv(void *buf, size_t len, int flag = 0) const {
        ssize_t ret = recv(_sockfd, buf, len, flag);
        if (ret <= 0) {
            //EAGAIN 当前socket的接收缓冲区中没有数据了，在非阻塞的情况下才会有这个错误
            //EINTR  表示当前socket的阻塞等待，被信号打断了
            if (errno == EAGAIN || errno == EINTR) {
                return 0;//表示这次接收没有接收到数据
            }
            LOG(ERROR) << "SOCKET RECV FAILED!!";
            return -1;
        }
        return ret; 
    }
    [[nodiscard]] ssize_t nonBlockRecv(void *buf, size_t len) const {
        return Recv(buf, len, MSG_DONTWAIT); // MSG_DONTWAIT 表示当前接收为非阻塞。
    }
    [[nodiscard]] ssize_t Send(const void *buf, size_t len, int flag = 0) const {
        ssize_t ret = send(_sockfd, buf, len, flag);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                return 0;
            }
            LOG(ERROR) << "SOCKET SEND FAILED!!";
            return -1;
        }
        return ret;
    }
    [[nodiscard]] ssize_t nonBlockSend(void *buf, size_t len) const {
        if (len == 0) return 0;
        
        return Send(buf, len, MSG_DONTWAIT); // MSG_DONTWAIT 表示当前发送为非阻塞。
    }
    void Close() {
        if (_sockfd != -1) {
            close(_sockfd);
            _sockfd = -1;
        }
    }
    // server
    bool createServer(uint16_t port, const std::string &ip = "0.0.0.0", bool is_block = false) {
        //1. 创建套接字，2. 绑定地址，3. 开始监听，4. 设置非阻塞， 5. 启动地址重用
        if (!Create()) { return false; }
        if (is_block) { NonBlock(); }
        if (!Bind(ip, port)) { return false; }
        if (!Listen()) { return false; }
        reUseAddress();
        return true;
    }
    // client
    bool createClient(uint16_t port, const std::string &ip) {
        if (!Create()) return false;
        if (!Connect(ip, port)) return false;
        return true;
    }
    //设置套接字选项---开启地址端口重用
    void reUseAddress() const {
        // int setsockopt(int fd, int leve, int optname, void *val, int vallen)
        int val = 1;
        setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, (void*)&val, sizeof(int));
    }
    //设置套接字阻塞属性-- 设置为非阻塞
    void NonBlock() const {
        int flag = fcntl(_sockfd, F_GETFL, 0);          //获取属性
        fcntl(_sockfd, F_SETFL, flag | O_NONBLOCK);     //设置非阻塞
    }
};


class Poller;
class EventLoop;
//描述一个fd的事件和回调
class Channel {
private:
    int _fd;
    EventLoop *_loop;
    uint32_t _events;  // 当前需要监控的事件
    uint32_t _revents; // 当前连接触发的事件(next)
    using eventCallback = std::function<void()>;
    eventCallback _read_callback;   
    eventCallback _write_callback;  
    eventCallback _error_callback; 
    eventCallback _close_callback;  
    eventCallback _event_callback; 
public:
    Channel(EventLoop *loop, int fd):_fd(fd), _events(0), _revents(0), _loop(loop) {}
    [[nodiscard]] inline int fd() const { return _fd; }
    [[nodiscard]] inline uint32_t events() const { return _events; }
    inline void setREvents(uint32_t ev) { _revents = ev; }
    inline void setReadCallback(const eventCallback &cb) { _read_callback = cb; }
    inline void setWriteCallback(const eventCallback &cb) { _write_callback = cb; }
    inline void setErrorCallback(const eventCallback &cb) { _error_callback = cb; }
    inline void setCloseCallback(const eventCallback &cb) { _close_callback = cb; }
    inline void setEventCallback(const eventCallback &cb) { _event_callback = cb; }
    //当前是否监控了可读
    [[nodiscard]] inline bool readAble() const { return (_events & EPOLLIN); }
    //当前是否监控了可写
    [[nodiscard]] inline bool writeAble() const { return (_events & EPOLLOUT); }
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
        }
        if (_revents & EPOLLOUT) {
            if (_write_callback) _write_callback();
        }else if (_revents & EPOLLERR) {
            if (_error_callback) _error_callback();//一旦出错，就会释放连接，因此要放到前边调用任意回调
        }else if (_revents & EPOLLHUP) {
            if (_close_callback) _close_callback();
        }

        if (_event_callback) _event_callback();    //定时任务

    }
};

#define MAX_EPOLLEVENTS 1024
class Poller {
private:
    int _epfd;
    struct epoll_event _events[MAX_EPOLLEVENTS]{};
    std::unordered_map<int, Channel *> _channels;
private:
    void update(Channel *channel, int op) const {
        int fd = channel->fd();
        struct epoll_event ev{};
        ev.data.fd = fd;
        ev.events = channel->events();
        // int epoll_ctl(int epfd, int op,  int fd,  struct epoll_event *ev);
        int ret = epoll_ctl(_epfd, op, fd, &ev);
        if (ret < 0) {
            LOG(ERROR) << "EPOLLCTL FAILED!";
        }
    }
    //判断一个Channel是否已经添加了事件监控
    inline bool hasChannel(Channel *channel) {
        return _channels.contains(channel->fd());
//        return  _channels.find(channel->fd()) != _channels.end();
    }
public:
    Poller() {
        _epfd = epoll_create(MAX_EPOLLEVENTS);
        if (_epfd < 0) {
            LOG(ERROR) << "EPOLL CREATE FAILED!!";
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
            LOG(ERROR) << "EPOLL WAIT ERROR: " << strerror(errno);
            abort();
        }
        for (int i = 0; i < nready; i++) {
            auto it = _channels.find(_events[i].data.fd);
            assert(it != _channels.end());

            it->second->setREvents(_events[i].events);//设置实际就绪的事件

            //TODO: 考虑异步执行该操作
            active->push_back(it->second);
        }
    }
};

using taskFunc = std::function<void()>;
using releaseFunc = std::function<void()>;
class TimerTask{
private:
    uint64_t _id;       // 定时器任务对象ID
    uint32_t _timeout;  //定时任务的超时时间
    bool _canceled;     // true:定时器表示被取消
    taskFunc _task_cb;  //定时器对象要执行的定时任务
    releaseFunc _release; //用于删除TimerWheel中保存的定时器对象信息
public:
    TimerTask(uint64_t id, uint32_t delay, taskFunc cb):
        _id(id), _timeout(delay), _task_cb(std::move(cb)), _canceled(false) {}
    ~TimerTask() { 
        if (!_canceled) _task_cb();
        _release(); 
    }
    void cancel() { _canceled = true; }
    void setRelease(const releaseFunc &cb) { _release = cb; }
    [[nodiscard]] uint32_t delayTime() const { return _timeout; }
};

class TimerWheel {
private:
    using weakTask = std::weak_ptr<TimerTask>;
    using sPtrTask = std::shared_ptr<TimerTask>;
    uint32_t _tick;      //当前的秒针，走到哪里释放哪里，释放哪里，就相当于执行哪里的任务
    int _capacity;  //表盘最大数量---其实就是最大延迟时间
    std::vector<std::vector<sPtrTask>> _wheel;
    std::unordered_map<uint64_t, weakTask> _timers;

    EventLoop *_loop;
    int _timer_fd;//定时器描述符--可读事件回调就是读取计数器，执行定时任务
    std::unique_ptr<Channel> _timer_channel;
private:
    void removeTimer(uint64_t id) {
        auto it = _timers.find(id);
        if (it != _timers.end()) {
            _timers.erase(it);
        }
    }
    static int createTimerfd() {
        int timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (timer_fd < 0) {
            LOG(ERROR) << "TIMERFD CREATE FAILED!";
            abort();
        }
        //int timerfd_settime(int fd, int flags, struct itimerspec *new, struct itimerspec *old);
        struct itimerspec itime{};
        itime.it_value.tv_sec = 1;
        itime.it_value.tv_nsec = 0;//第一次超时时间为1s后
        itime.it_interval.tv_sec = 1; 
        itime.it_interval.tv_nsec = 0; //第一次超时后，每次超时的间隔时
        timerfd_settime(timer_fd, 0, &itime, nullptr);
        return timer_fd;
    }
    uint64_t readTimeFd() const {
        uint64_t times;
        //有可能因为其他描述符的事件处理花费事件比较长，然后在处理定时器描述符事件的时候，有可能就已经超时了很多次
        //read读取到的数据times就是从上一次read之后超时的次数
        ssize_t ret = read(_timer_fd, &times, 8);
        if (ret < 0) {
            LOG(ERROR) << "READ TIMEFD FAILED!";
            abort();
        }
        return times;
    }
    //这个函数应该每秒钟被执行一次，相当于秒针向后走了一步
    void runTimerTask() {
        _tick = (_tick + 1) % _capacity;
        _wheel[_tick].clear();//清空指定位置的数组，就会把数组中保存的所有管理定时器对象的shared_ptr释放掉
    }
    void onTime() {
        //根据实际超时的次数，执行对应的超时任务
        auto times = readTimeFd();
        for (int i = 0; i < times; i++) {
            runTimerTask();
        }
    }
    void timerAddInLoop(uint64_t id, uint32_t delay, const taskFunc &cb) {
        sPtrTask sptr(new TimerTask(id, delay, cb));
        sptr->setRelease([this, id] { removeTimer(id); });
        uint32_t pos = (_tick + delay) % _capacity;
        _wheel[pos].push_back(sptr);
        _timers[id] = weakTask(sptr);
    }
    void timerRefreshInLoop(uint64_t id) {
        //通过保存的定时器对象的weak_ptr构造一个shared_ptr出来，添加到轮子中
        auto it = _timers.find(id);
        if (it == _timers.end()) {
            return;//没找着定时任务，没法刷新，没法延迟
        }
        sPtrTask sptr = it->second.lock();//lock获取weak_ptr管理的对象对应的shared_ptr
        uint32_t delay = sptr->delayTime();
        uint32_t pos = (_tick + delay) % _capacity;
        _wheel[pos].push_back(sptr);
    }
    void timerCancelInLoop(uint64_t id) {
        auto it = _timers.find(id);
        if (it == _timers.end()) {
            return;//没找着定时任务，没法刷新，没法延迟
        }
        sPtrTask sptr = it->second.lock();
        if (sptr) sptr->cancel();
    }
public:
    explicit TimerWheel(EventLoop *loop):_capacity(60), _tick(0), _wheel(_capacity), _loop(loop),
        _timer_fd(createTimerfd()), _timer_channel(new Channel(_loop, _timer_fd)) {
        _timer_channel->setReadCallback([this] { onTime(); });      //每秒钟触发
        _timer_channel->enableRead();//启动读事件监控
    }
    
    //在任务队列中执行添加、刷新、删除
    void timerAdd(uint64_t id, uint32_t delay, const taskFunc &cb);
    void timerRefresh(uint64_t id);
    void timerCancel(uint64_t id);
    /*这个接口存在线程安全问题--这个接口实际上不能被外界使用者调用，只能在模块内，在对应的EventLoop线程内执行*/
    bool hasTimer(uint64_t id) {
        // return _timers.contains(id);
        return _timers.find(id) != _timers.end();
    }
};

class EventLoop {
private:
    using functor = std::function<void()>;
    std::thread::id _thread_id;//线程ID
    int _event_fd;//eventfd唤醒IO事件监控有可能导致的阻塞
    std::unique_ptr<Channel> _event_channel;
    Poller _poller;//进行所有描述符的事件监控
    std::vector<functor> _tasks;//任务队列
    std::mutex _mutex;//实现任务池操作的线程安全
    TimerWheel _timer_wheel;//定时器模块
private:
    //执行任务池中的所有任务
    void runAllTask() {
        std::vector<functor> functors;
        {
            std::unique_lock<std::mutex> _lock(_mutex);
            _tasks.swap(functors);
        }
        for (auto &f : functors) {
            //TODO: 实现异步运行
            f();
        }
    }
    static int createEventFd() {
        int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (efd < 0) {
            LOG(ERROR) << "CREATE EVENTFD FAILED!!";
            abort();
        }
        return efd;
    }
    void raedEventFd() const {
        uint64_t res = 0;
        ssize_t ret = read(_event_fd, &res, sizeof(res));
        if (ret < 0) {
            //EINTR:被信号打断   EAGAIN:表示无数据可读
            if (errno == EINTR || errno == EAGAIN) {
                return;
            }
            LOG(ERROR) << "READ EVENTFD FAILED!";
            abort();
        }
    }
    void weakUpEventFd() const {
        uint64_t val = 1;
        ssize_t ret = write(_event_fd, &val, sizeof(val));
        if (ret < 0) {
            if (errno == EINTR) {
                return;
            }
            LOG(ERROR) << "READ EVENTFD FAILED!";
            abort();
        }
    }
public:
    EventLoop():_thread_id(std::this_thread::get_id()), 
                _event_fd(createEventFd()), 
                _event_channel(new Channel(this, _event_fd)),
                _timer_wheel(this) {
        //给eventfd添加可读事件回调函数，读取eventfd事件通知次数
        _event_channel->setReadCallback([this] { raedEventFd(); });
        //启动eventfd的读事件监控
        _event_channel->enableRead();
    }
    //事件监控->就绪事件处理->执行任务
    [[noreturn]] void run() {
        while(true) {
            //1. 事件监控
            std::vector<Channel *> actives;
            _poller._poll(&actives);
            //2. 事件处理
            for (auto &channel : actives) {
                channel->handleEvent();
            }
            //3. 执行任务
            runAllTask();
        }
    }
    //判断当前线程是否是EventLoop对应的线程；
    bool isInLoop() {
        return (_thread_id == std::this_thread::get_id());
    }
    void assertInLoop() {
        assert(_thread_id == std::this_thread::get_id());
    }
    //判断将要执行的任务是否处于当前线程中，如果是则执行，不是则压入队列。
    void runInLoop(const functor &cb) {
        if (isInLoop()) {
            return cb();
        }
        return queueInLoop(cb);
    }
    //将操作压入任务池
    void queueInLoop(const functor &cb) {
        {
            std::unique_lock<std::mutex> _lock(_mutex);
            _tasks.push_back(cb);
        }
        //唤醒有可能因为没有事件就绪，而导致的epoll阻塞；
        //其实就是给eventfd写入一个数据，eventfd就会触发可读事件
        weakUpEventFd();
    }
    //添加/修改描述符的事件监控
    void updateEvent(Channel *channel) { return _poller.updateEvent(channel); }
    //移除描述符的监控
    void removeEvent(Channel *channel) { return _poller.removeEvent(channel); }
    void timerAdd(uint64_t id, uint32_t delay, const taskFunc &cb) { return _timer_wheel.timerAdd(id, delay, cb); }
    void timerRefresh(uint64_t id) { return _timer_wheel.timerRefresh(id); }
    void timerCancel(uint64_t id) { return _timer_wheel.timerCancel(id); }
    bool hasTimer(uint64_t id) { return _timer_wheel.hasTimer(id); }
};

class LoopThread {
    private:
        std::mutex _mutex;          
        std::condition_variable _cond;  
        EventLoop *_loop;       // 线程内实例化
        std::thread _thread;    // EventLoop对应的线程
    void threadEntry() {
        auto* loop = new(EventLoop);
        {
            std::unique_lock<std::mutex> lock(_mutex);
            _loop = loop;
            _cond.notify_all();
        }
        loop->run();     //循环监控/执行
    }
    public:
        /*创建线程，设定线程入口函数*/
        LoopThread():_loop(nullptr), _thread(&LoopThread::threadEntry, this) {}
        EventLoop *getLoop() {
            EventLoop *loop = nullptr;
            {
                std::unique_lock<std::mutex> lock(_mutex);
                _cond.wait(lock, [&](){ return _loop != nullptr; });
                loop = _loop;
            }
            return loop;
        }
};

class LoopThreadPool {
private:
    int _thread_count;
    int _next_idx;
    EventLoop *_baseloop;
    std::vector<LoopThread*> _threads;
    std::vector<EventLoop *> _loops;
public:
    explicit LoopThreadPool(EventLoop *baseloop):_thread_count(0), _next_idx(0), _baseloop(baseloop) {}
    void setThreadCount(int count) { _thread_count = count; }
    void create() {
        if (_thread_count > 0) {
            _threads.resize(_thread_count);
            _loops.resize(_thread_count);
            for (int i = 0; i < _thread_count; i++) {
                _threads[i] = new LoopThread();
                _loops[i] = _threads[i]->getLoop();
            }
        }
    }
    EventLoop *nextLoop() {
        if (_thread_count == 0) {
            return _baseloop;
        }
        _next_idx = (_next_idx + 1) % _thread_count;
        return _loops[_next_idx];
    }
};

class Connection;
//DISCONECTED -- 连接关闭状态；   CONNECTING -- 连接建立成功-待处理状态
//CONNECTED -- 连接建立完成，各种设置已完成，可以通信的状态；  DISCONNECTING -- 待关闭状态
typedef enum { 
    DISCONNECTED, 
    CONNECTING, 
    CONNECTED, 
    DISCONNECTING
}ConnStatu;
using sPtrConnection = std::shared_ptr<Connection>;
class Connection : public std::enable_shared_from_this<Connection> {
private:
    uint64_t _conn_id;  // 连接的唯一ID，便于连接的管理和查找, 用_conn_id作为_timer_id
    int _sockfd;        // 连接关联的文件描述符
    bool _enable_inactive_release;  // true表示断开非活跃链接（默认false）
    EventLoop *_loop;   
    ConnStatu _statu;   // 连接状态
    Socket _socket;     
    Channel _channel;  
    Buffer _in_buffer; 
    Buffer _out_buffer; 
    any _context;       // 请求的接收处理上下文

    //对用户提供的函数调用接口
    using ConnectedCallback = std::function<void(const sPtrConnection&)>;
    using MessageCallback = std::function<void(const sPtrConnection&, Buffer *)>;
    using ClosedCallback = std::function<void(const sPtrConnection&)>;
    using AnyEventCallback = std::function<void(const sPtrConnection&)>;
    ConnectedCallback _connected_callback;
    MessageCallback _message_callback;
    ClosedCallback _closed_callback;
    AnyEventCallback _event_callback;
    ClosedCallback _server_closed_callback;
private:
    /*五个channel的事件回调函数*/
    //描述符可读事件触发后调用的函数，接收socket数据放到接收缓冲区中，然后调用_message_callback
    void handleRead() {
        //1. 接收socket的数据，放到缓冲区
        char buf[65536];
        ssize_t ret = _socket.nonBlockRecv(buf, 65535);
        if (ret < 0) {
            //出错了,不能直接关闭连接
            return shutdownInLoop();
        }
        //这里的等于0表示的是没有读取到数据，而并不是连接断开了，连接断开返回的是-1
        //将数据放入输入缓冲区,写入之后顺便将写偏移向后移动
        _in_buffer.writeAndMove(buf, ret);
        //2. 调用message_callback进行业务处理
        if (_in_buffer.readAbleSize() > 0) {
            //shared_from_this--从当前对象自身获取自身的shared_ptr管理对象
            return _message_callback(shared_from_this(), &_in_buffer);
        }
    }
    //描述符可写事件触发后调用的函数，将发送缓冲区中的数据进行发送
    void handleWrite() {
        //_out_buffer中保存的数据就是要发送的数据
        ssize_t ret = _socket.nonBlockSend(_out_buffer.readPosition(), _out_buffer.readAbleSize());
        if (ret < 0) {
            //发送错误,关闭连接
            if (_in_buffer.readAbleSize() > 0) {
                _message_callback(shared_from_this(), &_in_buffer);
            }
            return release();
        }
        _out_buffer.moveReadOffset(ret);//千万不要忘了，将读偏移向后移动
        if (_out_buffer.readAbleSize() == 0) {
            _channel.disableWrite();// 没有数据待发送了，关闭写事件监控
            //如果当前是连接待关闭状态，则有数据，发送完数据释放连接，没有数据则直接释放
            if (_statu == DISCONNECTING) {
                return release();
            }
        }
    }
    void handleClose() {
        if (_in_buffer.readAbleSize() > 0) {
            _message_callback(shared_from_this(), &_in_buffer);
        }
        return release();
    }
    void handleError() {
        return handleClose();
    }
    //描述符触发任意事件: 1. 刷新连接的活跃度--延迟定时销毁任务；  2. 调用组件使用者的任意事件回调
    void handleEvent() {
        if (_enable_inactive_release)  {  _loop->timerRefresh(_conn_id); }
        if (_event_callback)  {  _event_callback(shared_from_this()); }
    }
    //连接获取之后，所处的状态下要进行各种设置（启动读监控,调用回调函数）
    void establishedInLoop() {
        assert(_statu == CONNECTING);
        _statu = CONNECTED;
        // 一旦启动读事件监控就有可能会立即触发读事件，如果这时候启动了非活跃连接销毁
        _channel.enableRead();
        if (_connected_callback) _connected_callback(shared_from_this());
    }
    //释放接口
    void releaseInLoop() {
        _statu = DISCONNECTED;
        _channel.remove();
        _socket.Close();
        if (_loop->hasTimer(_conn_id)) cancelInactiveReleaseInLoop();
        if (_closed_callback) _closed_callback(shared_from_this());
        if (_server_closed_callback) _server_closed_callback(shared_from_this());
    }
    //这个关闭操作并非实际的连接释放操作，需要判断还有没有数据待处理，待发送
    void shutdownInLoop() {
        _statu = DISCONNECTING;// 设置连接为半关闭状态
        if (_in_buffer.readAbleSize() > 0) {
            if (_message_callback) _message_callback(shared_from_this(), &_in_buffer);
        }
        //要么就是写入数据的时候出错关闭，要么就是没有待发送数据，直接关闭
        if (_out_buffer.readAbleSize() > 0) {
            if (!_channel.writeAble()) {
                _channel.enableWrite();
            }
        }
        if (_out_buffer.readAbleSize() == 0) {
            release();      //将releaseInLoop添加到任务队列里
        }
    }
    //数据写入缓冲区，启动可事件
    void sendInLoop(Buffer buf) {
        if (_statu == DISCONNECTED) return ;
        _out_buffer.writeBufferAndMove(buf);
        if (!_channel.writeAble()) {
            _channel.enableWrite();
        }
    }
    //启动非活跃连接超时释放规则
    void enableInactiveReleaseInLoop(int sec) {
        //1. 将判断标志 _enable_inactive_release 置为true
        _enable_inactive_release = true;
        //2. 如果当前定时销毁任务已经存在，那就刷新延迟一下即可
        if (_loop->hasTimer(_conn_id)) {
            return _loop->timerRefresh(_conn_id);
        }
        //3. 如果不存在定时销毁任务，则新增
        _loop->timerAdd(_conn_id, sec, [this] { release(); });
    }
    void cancelInactiveReleaseInLoop() {
        _enable_inactive_release = false;
        if (_loop->hasTimer(_conn_id)) { 
            _loop->timerCancel(_conn_id); 
        }
    }
    void upgradeInLoop(const any &context, 
                const ConnectedCallback &conn, 
                const MessageCallback &msg, 
                const ClosedCallback &closed, 
                const AnyEventCallback &event)
    {
        _context = context;
        _connected_callback = conn;
        _message_callback = msg;
        _closed_callback = closed;
        _event_callback = event;
    }
public:
    Connection(EventLoop *loop, uint64_t conn_id, int sockfd):_conn_id(conn_id), _sockfd(sockfd),
        _enable_inactive_release(false), _loop(loop), _statu(CONNECTING), _socket(_sockfd),
        _channel(loop, _sockfd) {
        _channel.setCloseCallback([this] { handleClose(); });
        _channel.setEventCallback([this] { handleEvent(); });       //任意事件触发
        _channel.setReadCallback([this] { handleRead(); });
        _channel.setWriteCallback([this] { handleWrite(); });
        _channel.setErrorCallback([this] { handleError(); });
    }
//    ~Connection() { DBG_LOG("RELEASE CONNECTION:%p", this); }
    inline int fd() const { return _sockfd; }
    inline uint64_t id() const { return _conn_id; }
    inline bool connected() { return (_statu == CONNECTED); }
    inline void setContext(const any &context) { _context = context; }
    //获取上下文，返回的是指针
    inline any *getContext() { return &_context; }
    inline void setConnectedCallback(const ConnectedCallback&cb) { _connected_callback = cb; }
    inline void setMessageCallback(const MessageCallback&cb) { _message_callback = cb; }
    inline void setClosedCallback(const ClosedCallback&cb) { _closed_callback = cb; }
    inline void setAnyEventCallback(const AnyEventCallback&cb) { _event_callback = cb; }
    inline void setSrvClosedCallback(const ClosedCallback&cb) { _server_closed_callback = cb; }
    //连接建立就绪后，进行channel回调设置，启动读监控，调用_connected_callback
    void established() {
        _loop->runInLoop([this] { establishedInLoop(); });
    }
    //发送数据，将数据放到发送缓冲区，启动写事件监控
    void send(const char *data, size_t len) {
        //外界传入的data，可能是个临时的空间，我们现在只是把发送操作压入了任务池，有可能并没有被立即执行
        //因此有可能执行的时候，data指向的空间有可能已经被释放了。
        Buffer buf;
        buf.writeAndMove(data, len);
        _loop->runInLoop([this, capture0 = std::move(buf)] { sendInLoop(capture0); });
    }
    //关闭前判断是否有未处理的函数
    void shutdown() {
        _loop->runInLoop([this] { shutdownInLoop(); });
    } 
    void release() {
        _loop->queueInLoop([this] { releaseInLoop(); });
    }
    //启动非活跃销毁，并定义多长时间无通信就是非活跃，添加定时任务
    void enableInactiveRelease(int sec) {
        _loop->runInLoop([this, sec] { enableInactiveReleaseInLoop(sec); });
    }
    //取消非活跃销毁
    void cancelInactiveRelease() {
        _loop->runInLoop([this] { cancelInactiveReleaseInLoop(); });
    }
    //切换协议---重置上下文以及阶段性回调处理函数 -- 而是这个接口必须在EventLoop线程中立即执行
    //防备新的事件触发后，处理的时候，切换任务还没有被执行--会导致数据使用原协议处理了。
    void upgrade(const any &context, const ConnectedCallback &conn, const MessageCallback &msg, 
                    const ClosedCallback &closed, const AnyEventCallback &event) {
        _loop->assertInLoop();
        _loop->runInLoop([this, context, conn, msg, closed, event] { upgradeInLoop(context, conn, msg, closed, event); });
    }
};


//Acceptor管理监听链接accept
class Acceptor {
private:
    Socket _socket;  //启动server，获取listenfd, 
    EventLoop *_loop; //事件监控
    Channel _channel; //事件管理

    using AcceptCallback = std::function<void(int)>;
    AcceptCallback _accept_callback;
private:
    void handleRead() {
        int newfd = _socket.Accept();
        if (newfd < 0) {
            return ;
        }
        if (_accept_callback) _accept_callback(newfd);
    }
    int CreateServer(int port) {
        bool ret = _socket.createServer(port);
        assert(ret == true);
        return _socket.fd();
    }
public:
    //这里不能将启动读事件设置到构造函数中，因为可能事件触发会在设置回调函数之前进行
    Acceptor(EventLoop *loop, int port): _socket(CreateServer(port)), _loop(loop), 
        _channel(loop, _socket.fd()) {
        _channel.setReadCallback([this] { handleRead(); });
    }
    void setAcceptCallback(const AcceptCallback &cb) { _accept_callback = cb; }
    void listen() { _channel.enableRead(); }
};


class TcpServer {
private:
    uint64_t _next_id;      //这是一个自动增长的连接ID，
    int _port;
    int _timeout{};           //这是非活跃连接的统计时间---多长时间无通信就是非活跃连接
    bool _enable_inactive_release;//是否启动了非活跃连接超时销毁的判断标志
    EventLoop _baseloop;    //这是主线程的EventLoop对象，负责监听事件的处理
    Acceptor _acceptor;    //这是监听套接字的管理对象
    LoopThreadPool _pool;   //这是从属EventLoop线程池nextLoop
    std::unordered_map<uint64_t, sPtrConnection> _conns;//保存管理所有连接对应的shared_ptr对象

    using ConnectedCallback = std::function<void(const sPtrConnection&)>;
    using MessageCallback = std::function<void(const sPtrConnection&, Buffer *)>;
    using ClosedCallback = std::function<void(const sPtrConnection&)>;
    using AnyEventCallback = std::function<void(const sPtrConnection&)>;
    using Functor = std::function<void()>;
    ConnectedCallback _connected_callback;
    MessageCallback _message_callback;
    ClosedCallback _closed_callback;
    AnyEventCallback _event_callback;
private:
    void runAfterInLoop(const Functor &task, int delay) {
        _next_id++;
        _baseloop.timerAdd(_next_id, delay, task);
    }
    //为新连接构造一个Connection进行管理
    void newConnection(int fd) {
        _next_id++;
        sPtrConnection conn(new Connection(_pool.nextLoop(), _next_id, fd));
        //设置回调
        conn->setMessageCallback(_message_callback);
        conn->setClosedCallback(_closed_callback);
        conn->setConnectedCallback(_connected_callback);
        conn->setAnyEventCallback(_event_callback);
        conn->setSrvClosedCallback([this](auto && PH1) { removeConnection(std::forward<decltype(PH1)>(PH1)); });

        if (_enable_inactive_release) conn->enableInactiveRelease(_timeout);//启动非活跃超时销毁
        conn->established();//就绪初始化
        _conns.emplace(_next_id, conn);
    }
    void removeConnectionInLoop(const sPtrConnection &conn) {
        uint64_t id = conn->id();
        if (_conns.find(id) != _conns.end()) {
            _conns.erase(id);
        }
    }
    //从管理Connection的_conns中移除连接信息
    void removeConnection(const sPtrConnection &conn) {
        _baseloop.runInLoop([this, conn] { removeConnectionInLoop(conn); });
    }
public:
    explicit TcpServer(int port):
        _port(port),
        _next_id(0),
        _enable_inactive_release(false),
        _acceptor(&_baseloop, port),
        _pool(&_baseloop) {
        _acceptor.setAcceptCallback([this](auto && PH1) { newConnection(std::forward<decltype(PH1)>(PH1)); });
        _acceptor.listen();//将监听套接字挂到baseloop上
    }
    void setThreadCount(int count) { return _pool.setThreadCount(count); }
    void setConnectedCallback(const ConnectedCallback&cb) { _connected_callback = cb; }
    void setMessageCallback(const MessageCallback&cb) { _message_callback = cb; }
    void setClosedCallback(const ClosedCallback&cb) { _closed_callback = cb; }
    void setAnyEventCallback(const AnyEventCallback&cb) { _event_callback = cb; }
    void enableInactiveRelease(int timeout) { _timeout = timeout; _enable_inactive_release = true; }
    //用于添加一个定时任务
    void runAfter(const Functor &task, int delay) {
        _baseloop.runInLoop([this, task, delay] { runAfterInLoop(task, delay); });
    }
    void run() {
        _pool.create();  
        _baseloop.run();
    }
};


void Channel::remove() { return _loop->removeEvent(this); }
void Channel::update() { return _loop->updateEvent(this); }
void TimerWheel::timerAdd(uint64_t id, uint32_t delay, const taskFunc &cb) {
    _loop->runInLoop([this, id, delay, cb] { timerAddInLoop(id, delay, cb); });
}
//刷新/延迟定时任务
void TimerWheel::timerRefresh(uint64_t id) {
    _loop->runInLoop([this, id] { timerRefreshInLoop(id); });
}
void TimerWheel::timerCancel(uint64_t id) {
    _loop->runInLoop([this, id] { timerCancelInLoop(id); });
}

class NetWork {
    public:
        NetWork() {
//            DBG_LOG("SIGPIPE INIT");
            signal(SIGPIPE, SIG_IGN);
        }
};
static NetWork nw;

#endif