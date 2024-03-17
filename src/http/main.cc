#include "http.hpp"

static const std::string wwwroot = "./wwwroot";

int main() {
    HttpServer server(8888);
    server.setThreadCount(3);
    server.setBaseDir(wwwroot);
    server.GET("/hello", [](const HttpRequest& req, HttpResponse* rsp) {
        rsp->setContent("xxx", "text/plain");
    });
    server.listen();
    return 0; 
}