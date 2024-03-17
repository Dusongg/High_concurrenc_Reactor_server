#include <string>
#include <iostream>
#include <vector>
#include <boost/algorithm/string.hpp>   //boost::split
#include <fstream>
#include "../server.hpp"
#include <ctype.h>      //isalnum()

//stat
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

//regex
#include <regex>


std::unordered_map<int, std::string> _statu_msg{
    {100,  "Continue"},
    {101,  "Switching Protocol"},
    {102,  "Processing"},
    {103,  "Early Hints"},
    {200,  "OK"},
    {201,  "Created"},
    {202,  "Accepted"},
    {203,  "Non-Authoritative Information"},
    {204,  "No Content"},
    {205,  "Reset Content"},
    {206,  "Partial Content"},
    {207,  "Multi-Status"},
    {208,  "Already Reported"},
    {226,  "IM Used"},
    {300,  "Multiple Choice"},
    {301,  "Moved Permanently"},
    {302,  "Found"},
    {303,  "See Other"},
    {304,  "Not Modified"},
    {305,  "Use Proxy"},
    {306,  "unused"},
    {307,  "Temporary Redirect"},
    {308,  "Permanent Redirect"},
    {400,  "Bad Request"},
    {401,  "Unauthorized"},
    {402,  "Payment Required"},
    {403,  "Forbidden"},
    {404,  "Not Found"},
    {405,  "Method Not Allowed"},
    {406,  "Not Acceptable"},
    {407,  "Proxy Authentication Required"},
    {408,  "Request Timeout"},
    {409,  "Conflict"},
    {410,  "Gone"},
    {411,  "Length Required"},
    {412,  "Precondition Failed"},
    {413,  "Payload Too Large"},
    {414,  "URI Too Long"},
    {415,  "Unsupported Media Type"},
    {416,  "Range Not Satisfiable"},
    {417,  "Expectation Failed"},
    {418,  "I'm a teapot"},
    {421,  "Misdirected Request"},
    {422,  "Unprocessable Entity"},
    {423,  "Locked"},
    {424,  "Failed Dependency"},
    {425,  "Too Early"},
    {426,  "Upgrade Required"},
    {428,  "Precondition Required"},
    {429,  "Too Many Requests"},
    {431,  "Request Header Headers Too Large"},
    {451,  "Unavailable For Legal Reasons"},
    {501,  "Not Implemented"},
    {502,  "Bad Gateway"},
    {503,  "Service Unavailable"},
    {504,  "Gateway Timeout"},
    {505,  "HTTP Version Not Supported"},
    {506,  "Variant Also Negotiates"},
    {507,  "Insufficient Storage"},
    {508,  "Loop Detected"},
    {510,  "Not Extended"},
    {511,  "Network Authentication Required"}
};

std::unordered_map<std::string, std::string> _mime_msg{
    {".aac",        "audio/aac"},
    {".abw",        "application/x-abiword"},
    {".arc",        "application/x-freearc"},
    {".avi",        "video/x-msvideo"},
    {".azw",        "application/vnd.amazon.ebook"},
    {".bin",        "application/octet-stream"},
    {".bmp",        "image/bmp"},
    {".bz",         "application/x-bzip"},
    {".bz2",        "application/x-bzip2"},
    {".csh",        "application/x-csh"},
    {".css",        "text/css"},
    {".csv",        "text/csv"},
    {".doc",        "application/msword"},
    {".docx",       "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".eot",        "application/vnd.ms-fontobject"},
    {".epub",       "application/epub+zip"},
    {".gif",        "image/gif"},
    {".htm",        "text/html"},
    {".html",       "text/html"},
    {".ico",        "image/vnd.microsoft.icon"},
    {".ics",        "text/calendar"},
    {".jar",        "application/java-archive"},
    {".jpeg",       "image/jpeg"},
    {".jpg",        "image/jpeg"},
    {".js",         "text/javascript"},
    {".json",       "application/json"},
    {".jsonld",     "application/ld+json"},
    {".mid",        "audio/midi"},
    {".midi",       "audio/x-midi"},
    {".mjs",        "text/javascript"},
    {".mp3",        "audio/mpeg"},
    {".mpeg",       "video/mpeg"},
    {".mpkg",       "application/vnd.apple.installer+xml"},
    {".odp",        "application/vnd.oasis.opendocument.presentation"},
    {".ods",        "application/vnd.oasis.opendocument.spreadsheet"},
    {".odt",        "application/vnd.oasis.opendocument.text"},
    {".oga",        "audio/ogg"},
    {".ogv",        "video/ogg"},
    {".ogx",        "application/ogg"},
    {".otf",        "font/otf"},
    {".png",        "image/png"},
    {".pdf",        "application/pdf"},
    {".ppt",        "application/vnd.ms-powerpoint"},
    {".pptx",       "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {".rar",        "application/x-rar-compressed"},
    {".rtf",        "application/rtf"},
    {".sh",         "application/x-sh"},
    {".svg",        "image/svg+xml"},
    {".swf",        "application/x-shockwave-flash"},
    {".tar",        "application/x-tar"},
    {".tif",        "image/tiff"},
    {".tiff",       "image/tiff"},
    {".ttf",        "font/ttf"},
    {".txt",        "text/plain"},
    {".vsd",        "application/vnd.visio"},
    {".wav",        "audio/wav"},
    {".weba",       "audio/webm"},
    {".webm",       "video/webm"},
    {".webp",       "image/webp"},
    {".woff",       "font/woff"},
    {".woff2",      "font/woff2"},
    {".xhtml",      "application/xhtml+xml"},
    {".xls",        "application/vnd.ms-excel"},
    {".xlsx",       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".xml",        "application/xml"},
    {".xul",        "application/vnd.mozilla.xul+xml"},
    {".zip",        "application/zip"},
    {".3gp",        "video/3gpp"},
    {".3g2",        "video/3gpp2"},
    {".7z",         "application/x-7z-compressed"}
};

class Util {
    public:
        static size_t split(const std::string &src, std::vector<std::string> *output, const std::string &sep) {
            boost::split(*output, src, boost::is_any_of(sep), boost::token_compress_on);
            return output->size();
        }

        //读取文件的所有内容，将读取的内容放到一个Buffer中
        static bool readFile(const std::string &filename, std::string *buf) {
            std::ifstream ifs(filename, std::ios::binary);
            if (ifs.is_open() == false) {
                printf("OPEN %s FILE FAILED!!", filename.c_str());
                return false;
            }
            //获取文件大小fsize
            size_t fsize = 0;
            ifs.seekg(0, ifs.end);
            fsize = ifs.tellg(); 
            ifs.seekg(0, ifs.beg);
            buf->resize(fsize); 
            ifs.read(&(*buf)[0], fsize);
            if (ifs.good() == false) {
                printf("READ %s FILE FAILED!!", filename.c_str());
                ifs.close();
                return false;
            }
            ifs.close();
            return true;
        }
        static bool writeFile(const std::string &filename, const std::string &buf) {
            std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
            if (ofs.is_open() == false) {
                printf("OPEN %s FILE FAILED!!", filename.c_str());
                return false;
            }
            ofs.write(buf.c_str(), buf.size());
            if (ofs.good() == false) {
                ERR_LOG("WRITE %s FILE FAILED!", filename.c_str());
                ofs.close();    
                return false;
            }
            ofs.close();
            return true;
        }

        //URL编码，避免URL中资源路径与查询字符串中的特殊字符与HTTP请求中特殊字符产生歧义
        //编码格式：将特殊字符的ascii值，转换为两个16进制字符，前缀%   C++ -> C%2B%2B
        //  不编码的特殊字符： RFC3986文档规定 . - _ ~ 字母，数字属于绝对不编码字符
        //RFC3986文档规定，编码格式 %HH 
        //W3C标准中规定，查询字符串中的空格，需要编码为+， 解码则是+转空格
        static std::string urlEncode(const std::string url, bool convert_space_to_plus) {
            std::string res;
            for (auto &c : url) {
                if (c == '.' || c == '-' || c == '_' || c == '~' || isalnum(c)) {
                    res += c;
                } else if (c == ' ' && convert_space_to_plus == true) {
                    res += '+';
                } else {
                    //剩下的字符都是需要编码成为 %HH 格式(两位十六进制)
                    char tmp[4]{0};
                    snprintf(tmp, 4, "%%%02X", c);
                    res += tmp;
                }
            }
            return res;
        }
        static int HEXTOI(char c) {
            if (isdigit(c)) { return c - '0'; }
            else if (islower(c)) { return c - 'a' + 10; }
            else if (isupper(c)) { return c - 'A' + 10; }
            return -1; 
        }
        static std::string urlDecode(const std::string url, bool convert_plus_to_space) {
            //遇到了%，则将紧随其后的2个字符，转换为数字，第一个数字左移4位，然后加上第二个数字  + -> 2b  %2b->2 << 4 + 11
            std::string res;
            for (int i = 0; i < url.size(); i++) {
                if (url[i] == '+' && convert_plus_to_space == true) {
                    res += ' ';
                }
                else if (url[i] == '%' && (i + 2) < url.size()) {
                    int v1 = HEXTOI(url[i + 1]), v2 = HEXTOI(url[i + 2]);
                    char v = v1 * 16 + v2;      //ascii
                    res += v;
                    i += 2;
                }
                else {
                    res += url[i];
                }
            }
            return res;
        }
        //状态码
        static std::string statuDesc(int statu) { return (_statu_msg.find(statu) != _statu_msg.end()) ? _statu_msg[statu] : "Unkonw"; }
        //Context-type
        static std::string extMime(const std::string &filename) {
            //E.G.  xxxx.txt 
            size_t pos = filename.find_last_of('.');
            if (pos == std::string::npos) {
                return "application/octet-stream";
            }
            std::string ext = filename.substr(pos);

            return (_mime_msg.find(ext) != _mime_msg.end()) ? _mime_msg[ext] : "application/octet-stream";
        }

        static bool isDirectory(const std::string &filename) {
            struct stat st;
            int ret = stat(filename.c_str(), &st);
            if (ret < 0) {
                return false;
            }
            return S_ISDIR(st.st_mode); //是否为目录
        }
        static bool isRegular(const std::string &filename) {
            struct stat st;
            int ret = stat(filename.c_str(), &st);
            if (ret < 0) {
                return false;
            }
            return S_ISREG(st.st_mode);  //是否为常规文件
        }

        //http请求的资源路径有效性判断
        static bool ValidPath(const std::string &path) {
            //思想：按照/进行路径分割，根据有多少子目录，计算目录深度，有多少层，深度不能小于0
            std::vector<std::string> subdir;
            split(path, &subdir, "/");
            int level = 0;
            for (auto &dir : subdir) {
                if (dir == "..") {
                    level--; //任意一层走出相对根目录，就认为有问题
                    if (level < 0) return false;
                    continue;
                }
                level++;
            }
            return true;
        }
};

class HttpRequest {
    public:
        std::string _method;      //请求方法
        std::string _path;        //资源路径
        std::string _version;     //协议版本
        std::string _body;        //请求正文
        std::smatch _matches;     //资源路径的正则提取数据
        std::unordered_map<std::string, std::string> _headers;  //头部字段
        std::unordered_map<std::string, std::string> _params;   //查询字符串
    public:
        HttpRequest():_version("HTTP/1.1") {}
        void ReSet() {
            _method.clear();
            _path.clear();
            _version = "HTTP/1.1";
            _body.clear();
            std::smatch match;
            _matches.swap(match);
            _headers.clear();
            _params.clear();
        }
        //插入头部字段  --->  key : 字段   val : 字段值
        inline void setHeader(const std::string &key, const std::string &val) { _headers.emplace(key, val); }
        inline bool hasHeader(const std::string &key) const { return _headers.find(key) != _headers.end(); }
        std::string getHeader(const std::string &key) const { return (_headers.find(key) != _headers.end()) ? _headers.at(key) : ""; }
        inline void setParam(const std::string &key, const std::string &val) { _params.emplace(key, val); }
        inline bool hasParam(const std::string &key) const { return _params.find(key) != _params.end(); }
        inline std::string getParam(const std::string &key) const { (_params.find(key) != _params.end()) ? _params.at(key) : ""; }
        //获取正文长度
        size_t contentLength() const {
            // Content-Length: 1234\r\n
            bool ret = hasHeader("Content-Length");
            if (ret == false) {
                return 0;
            }
            std::string clen = getHeader("Content-Length");
            return std::stol(clen);
        }
        //判断是否是短链接  : ture -> 短链接
        bool isclose() const {
            // 没有Connection字段，或者有Connection但是值是close，则都是短链接，否则就是长连接
            if (hasHeader("Connection") == true && getHeader("Connection") == "keep-alive") {
                return false;
            }
            return true;
        }
};

class HttpResponse {
    public:
        int _statu;
        bool _redirect_flag;
        std::string _body;
        std::string _redirect_url;
        std::unordered_map<std::string, std::string> _headers;
    public:
        HttpResponse():_redirect_flag(false), _statu(200) {}
        HttpResponse(int statu):_redirect_flag(false), _statu(statu) {} 
        void reSet() {
            _statu = 200;
            _redirect_flag = false;
            _body.clear();
            _redirect_url.clear();
            _headers.clear();
        }
        inline void setHeader(const std::string &key, const std::string &val) { _headers.emplace(key, val); }
        inline bool hasHeader(const std::string &key) { return _headers.find(key) != _headers.end(); }
        inline std::string getHeader(const std::string &key) { (_headers.find(key) != _headers.end()) ? _headers.at(key) : ""; }
        void SetContent(const std::string &body,  const std::string &type = "text/html") {
            _body = body;
            setHeader("Content-Type", type);
        }
        void setRedirect(const std::string &url, int statu = 302) {
            _statu = statu;
            _redirect_flag = true;
            _redirect_url = url;
        }
        bool isClose() {
            if (hasHeader("Connection") == true && getHeader("Connection") == "keep-alive") {
                return false;
            }
            return true;
        }
};