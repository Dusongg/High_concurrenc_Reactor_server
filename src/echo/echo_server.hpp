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

            // conn->send(buf->readPosition(), buf->readAbleSize());
            std::string rep = "HTTP/1.1 200 OK\r\n"
							"Accept-Ranges: bytes\r\n" 
							"Content-Length: 77\r\n"
							"Content-Type: text/html\r\n\r\n"
							"<html><head><title>TEST</title></head><body><h1>Dusong</h1></body></html>\r\n\r\n";
            conn->send(rep.c_str(), rep.size());
            
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