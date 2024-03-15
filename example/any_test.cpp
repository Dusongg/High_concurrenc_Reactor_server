#include "any.hpp"
#include <string>


int main() {
    any a;
    a = 10;
    std::cout << *a.get<int>() << std::endl;

    a = std::string("xxx");
    std::cout << *a.get<std::string>() << std::endl;
} 