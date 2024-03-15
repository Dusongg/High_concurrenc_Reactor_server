#include "server.hpp"
int main() {

    /*基本测试
    
    Buffer buffer;
    std::string str = "xxx";
    buffer.writeStringAndMove(str);

    std::string tmp = buffer.readAsStringAndMove(str.size());
    std::cout << buffer.readAbleSize() << std::endl;
    std::cout << tmp << std::endl;
    
    */

    Buffer buf;
    for (int i = 0; i < 200; i++) {
        std::string str = "Dusong!!!" + std::to_string(i) + '\n';
        buf.writeStringAndMove(str);
    }
    while(buf.readAbleSize() > 0) {
        std::string line = buf.getLineAndMove();
        DBG_LOG("xxx");
    } 

    return 0;
}