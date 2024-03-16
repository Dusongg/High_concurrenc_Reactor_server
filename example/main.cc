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

void newConnection(int fd) {
    conn_id++; 
    sPtrConnection conn(new Connection(loop_pool->nextLoop(), conn_id, fd));
    //
    conn->setMessageCallback(std::bind(onMessage, std::placeholders::_1, std::placeholders::_2));
    conn->setSrvClosedCallback(std::bind(connectionDestroy, std::placeholders::_1));
    conn->setConnectedCallback(std::bind(onConnected, std::placeholders::_1));
    conn->enableInactiveRelease(10);
    conn->Established();
    _conns.emplace(conn_id, conn);
}

int main() {
    loop_pool = new LoopThreadPool(&base_loop, 2);
    loop_pool->create();
    Acceptor acceptor(&base_loop, 8888);
    acceptor.setAcceptCallback(std::bind(newConnection, std::placeholders::_1));
    acceptor.listen();
    base_loop.run();
    return 0;
}