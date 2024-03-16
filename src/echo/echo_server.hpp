#include "../server.hpp"

class EchoServer {
    private:
        TcpServer _server;
    private:
        void onConnected(const sPtrConnection &conn) {
            DBG_LOG("NEW CONNECTION:%p", conn.get());
        }
        void OnClosed(const sPtrConnection &conn) {
            DBG_LOG("CLOSE CONNECTION:%p", conn.get());
        }
        void OnMessage(const sPtrConnection &conn, Buffer *buf) {
            conn->send(buf->readPosition(), buf->readAbleSize());
            buf->moveReadOffset(buf->readAbleSize());
            conn->shutdown();
        }
    public:
        EchoServer(int port):_server(port) {
            _server.setThreadCount(2);
            _server.enableInactiveRelease(10);
            _server.setClosedCallback(std::bind(&EchoServer::OnClosed, this, std::placeholders::_1));
            _server.setConnectedCallback(std::bind(&EchoServer::onConnected, this, std::placeholders::_1));
            _server.setMessageCallback(std::bind(&EchoServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
        }
        void run() { _server.run(); }
};