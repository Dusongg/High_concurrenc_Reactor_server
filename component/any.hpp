#include <iostream>
#include <typeinfo>
#include <cassert>

class any {
private:
    class holder {
    public:
        virtual ~holder() = default;
        virtual const std::type_info& type() = 0;
        virtual holder* clone() = 0;
    };
    template<typename T>
    class placeholder: public holder {
    public:
        placeholder(const T& val) : _val(val) {}
        virtual const std::type_info& type() { return typeid(T); } 
        virtual holder* clone() { return new placeholder(_val); }
    public:
        T _val;
    };
    holder* _content; 
    
public:
    any() : _content(nullptr) {}
    ~any() { delete _content; }

    template <typename T>
    any(const T& val) : _content(new placeholder<T>(val)) {}
    any(const any& other) : _content(other._content ? other._content->clone() : nullptr) {}

    template<typename T>
    T* get() {
        assert(typeid(T) == _content->type());
        return &((placeholder<T>*)_content)->_val;
        
    }
    any& swap(any &other) {
        std::swap(_content, other._content);
        return *this;
    }
    template<typename T>
    any& operator=(const T& val) {
        any(val).swap(*this);
        return *this;
    }
    any& operator=(const any& other) {
        any(other).swap(*this);
        return *this;
    }
};

