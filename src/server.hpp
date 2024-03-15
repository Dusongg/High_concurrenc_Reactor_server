#include <vector>
#include <functional>
#include <cstdint>
#include <cassert>
#include <string>
#include <cstring>
#include <iostream>
#include <ctime>
#include <pthread.h>

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

//LOG
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
                if (_event_callback) _event_callback();     //刷新活跃度
                if (_read_callback) _read_callback();

            }
            /*有可能会释放连接的操作事件，一次只处理一个*/
            if (_revents & EPOLLOUT) {
                if (_event_callback) _event_callback(); 
                if (_write_callback) _write_callback();
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

using taskFunc = std::function<void()>;
using releaseFunc = std::function<void()>;
class TimerTask{
    private:
        uint64_t _id;       // 定时器任务对象ID
        uint32_t _timeout;  //定时任务的超时时间
        bool _canceled;     // false-表示没有被取消， true-表示被取消
        taskFunc _task_cb;  //定时器对象要执行的定时任务
        releaseFunc _release; //用于删除TimerWheel中保存的定时器对象信息
    public:
        TimerTask(uint64_t id, uint32_t delay, const taskFunc &cb): 
            _id(id), _timeout(delay), _task_cb(cb), _canceled(false) {}
        ~TimerTask() { 
            if (_canceled == false) _task_cb(); 
            _release(); 
        }
        void cancel() { _canceled = true; }
        void setRelease(const releaseFunc &cb) { _release = cb; }
        uint32_t delayTime() { return _timeout; }
};

class TimerWheel {
    private:
        using weakTask = std::weak_ptr<TimerTask>;
        using sPtrTask = std::shared_ptr<TimerTask>;
        int _tick;      //当前的秒针，走到哪里释放哪里，释放哪里，就相当于执行哪里的任务
        int _capacity;  //表盘最大数量---其实就是最大延迟时间
        std::vector<std::vector<sPtrTask>> _wheel;
        std::unordered_map<uint64_t, weakTask> _timers;

        EventLoop *_loop;
        int _timerfd;//定时器描述符--可读事件回调就是读取计数器，执行定时任务
        std::unique_ptr<Channel> _timer_channel;
    private:
        void removeTimer(uint64_t id) {
            auto it = _timers.find(id);
            if (it != _timers.end()) {
                _timers.erase(it);
            }
        }
        static int createTimerfd() {
            int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
            if (timerfd < 0) {
                ERR_LOG("TIMERFD CREATE FAILED!");
                abort();
            }
            //int timerfd_settime(int fd, int flags, struct itimerspec *new, struct itimerspec *old);
            struct itimerspec itime;
            itime.it_value.tv_sec = 1;
            itime.it_value.tv_nsec = 0;//第一次超时时间为1s后
            itime.it_interval.tv_sec = 1; 
            itime.it_interval.tv_nsec = 0; //第一次超时后，每次超时的间隔时
            timerfd_settime(timerfd, 0, &itime, NULL);
            return timerfd;
        }
        int readTimefd() {
            uint64_t times;
            //有可能因为其他描述符的事件处理花费事件比较长，然后在处理定时器描述符事件的时候，有可能就已经超时了很多次
            //read读取到的数据times就是从上一次read之后超时的次数
            int ret = read(_timerfd, &times, 8);
            if (ret < 0) {
                ERR_LOG("READ TIMEFD FAILED!");
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
            int times = readTimefd();
            for (int i = 0; i < times; i++) {
                runTimerTask();
            }
        }
        void timerAddInLoop(uint64_t id, uint32_t delay, const taskFunc &cb) {
            sPtrTask pt(new TimerTask(id, delay, cb));
            pt->setRelease(std::bind(&TimerWheel::removeTimer, this, id));
            int pos = (_tick + delay) % _capacity;
            _wheel[pos].push_back(pt);
            _timers[id] = weakTask(pt);
        }
        void timerRefreshInLoop(uint64_t id) {
            //通过保存的定时器对象的weak_ptr构造一个shared_ptr出来，添加到轮子中
            auto it = _timers.find(id);
            if (it == _timers.end()) {
                return;//没找着定时任务，没法刷新，没法延迟
            }
            sPtrTask pt = it->second.lock();//lock获取weak_ptr管理的对象对应的shared_ptr
            int delay = pt->delayTime();
            int pos = (_tick + delay) % _capacity;
            _wheel[pos].push_back(pt);
        }
        void timerCancelInLoop(uint64_t id) {
            auto it = _timers.find(id);
            if (it == _timers.end()) {
                return;//没找着定时任务，没法刷新，没法延迟
            }
            sPtrTask pt = it->second.lock();
            if (pt) pt->cancel();
        }
    public:
        TimerWheel(EventLoop *loop):_capacity(60), _tick(0), _wheel(_capacity), _loop(loop), 
            _timerfd(createTimerfd()), _timer_channel(new Channel(_loop, _timerfd)) {
            _timer_channel->setReadCallback(std::bind(&TimerWheel::onTime, this));
            _timer_channel->enableRead();//启动读事件监控
        }
        /*定时器中有个_timers成员，定时器信息的操作有可能在多线程中进行，因此需要考虑线程安全问题*/
        /*如果不想加锁，那就把对定期的所有操作，都放到一个线程中进行*/
        void timerAdd(uint64_t id, uint32_t delay, const taskFunc &cb);
        //刷新/延迟定时任务
        void timerRefresh(uint64_t id);
        void timerCancel(uint64_t id);
        /*这个接口存在线程安全问题--这个接口实际上不能被外界使用者调用，只能在模块内，在对应的EventLoop线程内执行*/
        bool hasTimer(uint64_t id) {
            auto it = _timers.find(id);
            if (it == _timers.end()) {
                return false;
            }
            return true;
        }
};

 class EventLoop {
    private:
        using Functor = std::function<void()>;
        std::thread::id _thread_id;//线程ID
        int _event_fd;//eventfd唤醒IO事件监控有可能导致的阻塞
        std::unique_ptr<Channel> _event_channel;
        Poller _poller;//进行所有描述符的事件监控
        std::vector<Functor> _tasks;//任务池
        std::mutex _mutex;//实现任务池操作的线程安全
        TimerWheel _timer_wheel;//定时器模块
    private:
        //执行任务池中的所有任务
        void runAllTask() {
            std::vector<Functor> functor;
            {
                std::unique_lock<std::mutex> _lock(_mutex);
                _tasks.swap(functor);
            }
            for (auto &f : functor) {
                f();
            }
            return ;
        }
        static int createEventFd() {
            int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
            if (efd < 0) {
                ERR_LOG("CREATE EVENTFD FAILED!!");
                abort();
            }
            return efd;
        }
        void readEventfd() {
            uint64_t res = 0;
            int ret = read(_event_fd, &res, sizeof(res));
            if (ret < 0) {
                //EINTR:被信号打断   EAGAIN:表示无数据可读
                if (errno == EINTR || errno == EAGAIN) {
                    return;
                }
                ERR_LOG("READ EVENTFD FAILED!");
                abort();
            }
            return;
        }
        void weakUpEventFd() {
            uint64_t val = 1;
            int ret = write(_event_fd, &val, sizeof(val));
            if (ret < 0) {
                if (errno == EINTR) {
                    return;
                }
                ERR_LOG("READ EVENTFD FAILED!");
                abort();
            }
            return ;
        }
    public:
        EventLoop():_thread_id(std::this_thread::get_id()), 
                    _event_fd(createEventFd()), 
                    _event_channel(new Channel(this, _event_fd)),
                    _timer_wheel(this) {
            //给eventfd添加可读事件回调函数，读取eventfd事件通知次数
            _event_channel->setReadCallback(std::bind(&EventLoop::readEventfd, this));
            //启动eventfd的读事件监控
            _event_channel->enableRead();
        }
        //三步走--事件监控-》就绪事件处理-》执行任务
        void run() {
            while(1) {
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
        void runInLoop(const Functor &cb) {
            if (isInLoop()) {
                return cb();
            }
            return queueInLoop(cb);
        }
        //将操作压入任务池
        void queueInLoop(const Functor &cb) {
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




void Channel::remove() { return _loop->removeEvent(this); }
void Channel::update() { return _loop->updateEvent(this); }
void TimerWheel::timerAdd(uint64_t id, uint32_t delay, const taskFunc &cb) {
    _loop->runInLoop(std::bind(&TimerWheel::timerAddInLoop, this, id, delay, cb));
}
//刷新/延迟定时任务
void TimerWheel::timerRefresh(uint64_t id) {
    _loop->runInLoop(std::bind(&TimerWheel::timerRefreshInLoop, this, id));
}
void TimerWheel::timerCancel(uint64_t id) {
    _loop->runInLoop(std::bind(&TimerWheel::timerCancelInLoop, this, id));
}