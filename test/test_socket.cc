#include "../src/server.hpp"
#include <iostream>
int main() {
    Socket server;
    server._createServer(8888);
    char buffer[1024]{0};
    Socket conn(server._accept());
    std::cout << "action" << std::endl;
    while(1) {
        int ret = conn._recv(buffer, 1024, 0);
        if (ret < 0) {
            return 0;
        }
        std::cout << buffer << std::endl;

        conn._send(buffer, 1024, 0);
    }

}