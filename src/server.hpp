#include <vector>
#include <cstdint>
#include <cassert>
#include <string>
#include <cstring>
#include <iostream>
#include <ctime>
#include <pthread.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

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
