#include "../src/server.hpp"
#include <stdlib.h>
std::unordered_map<uint64_t, sPtrConnection> _conns;
uint64_t conn_id = 0;
EventLoop base_loop;
LoopThreadPool* loop_pool;
int next_loop = 0;

void connectionDestroy(const sPtrConnection& conn) {
    _conns.erase(conn->id());
}
void onConnected(const sPtrConnection& conn) {
    DBG_LOG("new connection:%p", conn.get());
}

void onMessage(const sPtrConnection& conn, Buffer* buf) {
    DBG_LOG("%s", buf->readPosition());
    buf->moveReadOffset(buf->readAbleSize());
    std::string str = "hello world!";
    conn->send(str.c_str(), str.size());
    // conn->shutdown();
}


int main() {
    TcpServer server(8888);
    server.setThreadCount(2);
    server.enableInactiveRelease(5);
    server.setClosedCallback(connectionDestroy);
    server.setConnectedCallback(onConnected);
    server.setMessageCallback(onMessage);
    server.run();
    return 0;
}