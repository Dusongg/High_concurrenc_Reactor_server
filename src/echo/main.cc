#include "echo_server.hpp"

int main() {
    EchoServer server(8888);
    server.run();
}