#include <glog/logging.h>

//int main(int argc, char* argv[]) {
//    google::InitGoogleLogging(argv[0]);
//    LOG(INFO) << "Found " << 1 << " cookies";
//}


//#include "./server.hpp"


#include "http.hpp"

#define WWWROOT "./wwwroot/"

std::string RequestStr(const HttpRequest &req) {
    std::stringstream ss;
    ss << req._method << " " << req._path << " " << req._version << "\r\n";
    for (auto &it : req._params) {
        ss << it.first << ": " << it.second << "\r\n";
    }
    for (auto &it : req._headers) {
        ss << it.first << ": " << it.second << "\r\n";
    }
    ss << "\r\n";
    ss << req._body;
    return ss.str();
}
void Hello(const HttpRequest &req, HttpResponse *rsp)
{
//    rsp->setContent(RequestStr(req), "text/plain");
    rsp->setContent("hello back", "text/plain");
}
void Login(const HttpRequest &req, HttpResponse *rsp)
{
    rsp->setContent(RequestStr(req), "text/plain");
}
void PutFile(const HttpRequest &req, HttpResponse *rsp)
{
    std::string pathname = WWWROOT + req._path;
    Util::writeFile(pathname, req._body);
}
void DelFile(const HttpRequest &req, HttpResponse *rsp)
{
    rsp->setContent(RequestStr(req), "text/plain");
}
int main()
{
    HttpServer server(8888);
    server.setThreadCount(10);
    server.setBaseDir(WWWROOT);//设置静态资源根目录，告诉服务器有静态资源请求到来，需要到哪里去找资源文件
    server.GET("/hello", Hello);
    server.POST("/login", Login);
    server.PUT("/1234.txt", PutFile);
    server.DELETE("/1234.txt", DelFile);
    server.listen();
    return 0;
}

//class EchoServer {
//private:
//    TcpServer _server;
//private:
//    static void onConnected(const sPtrConnection &conn) {
//        std::cout << "NEW CONNECTION: " << conn.get() << std::endl;
//    }
//    static void OnClosed(const sPtrConnection &conn) {
//        std::cout << "Close CONNECTION: " << conn.get() << std::endl;
//    }
//    static void OnMessage(const sPtrConnection &conn, Buffer *buf) {
//        char        sendBuffer[1024]{};
//        int ret = sprintf(sendBuffer,
//                          "HTTP/1.1 200 OK\r\n"
//                          "Accept-Ranges: bytes\r\n"
//                          "Content-Length: 75\r\n"
//                          "Content-Type: text/html\r\n"
//                          "Date: Sat, 06 Aug 2023 13:16:46 GMT\r\n\r\n"
//                          "<html><head><title>Dusong</title></head><body><h1>Dusong</h1></body></html>\r\n");
//        conn->send(sendBuffer, ret);
//        buf->moveReadOffset(buf->readAbleSize());
//        conn->shutdown();
//    }
//public:
//    explicit EchoServer(int port):_server(port) {
//        _server.setThreadCount(2);
//        _server.enableInactiveRelease(2);
//        _server.setClosedCallback([](auto && PH1) { OnClosed(std::forward<decltype(PH1)>(PH1)); });
//        _server.setConnectedCallback([](auto && PH1) { onConnected(std::forward<decltype(PH1)>(PH1)); });
//        _server.setMessageCallback([](auto && PH1, auto && PH2) { OnMessage(std::forward<decltype(PH1)>(PH1), std::forward<decltype(PH2)>(PH2)); });
//    }
//    void run() { _server.run(); }
//};
//
//int main() {
//    EchoServer server(8081);
//    server.run();
//}