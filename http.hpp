#include <string>
#include <iostream>
#include <vector>
//#include <boost/algorithm/string.hpp>   //boost::split
#include <fstream>
#include "server.hpp"
#include <cctype>      //isalnum()

//stat
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

//regex
#include <regex>

#define DEFAULT_TIMEOUT 30

std::unordered_map<int, std::string> status_msg{
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

std::unordered_map<std::string, std::string> mime_msg{
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
        // boost::split(*output, src, boost::is_any_of(sep), boost::token_compress_on);
        // return output->size();
        size_t offset = 0;
        while(offset < src.size()) {
            size_t pos = src.find(sep, offset);
            if (pos == std::string::npos) {
                if(pos == src.size()) break;
                output->push_back(src.substr(offset));
                return output->size();
            }
            if (pos == offset) {
                offset = pos + sep.size();
                continue;
            }
            output->push_back(src.substr(offset, pos - offset));
            offset = pos + sep.size();
        }
        return output->size();
    }

    //读取文件的所有内容，将读取的内容放到一个Buffer中
    static bool readFile(const std::string &filename, std::string *buf) {
        std::ifstream ifs(filename, std::ios::binary);
        if (!ifs.is_open()) {
            printf("OPEN %s FILE FAILED!!", filename.c_str());
            return false;
        }
        //获取文件大小fsize
        size_t fsize = 0;
        ifs.seekg(0, std::ifstream::end);
        fsize = ifs.tellg();
        ifs.seekg(0, std::ifstream::beg);
        buf->resize(fsize);
        ifs.read(&(*buf)[0], fsize);
        if (!ifs.good()) {
            printf("READ %s FILE FAILED!!", filename.c_str());
            ifs.close();
            return false;
        }
        ifs.close();
        return true;
    }
    static bool writeFile(const std::string &filename, const std::string &buf) {
        std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) {
            LOG(ERROR) << "OPEN %s FILE FAILED!!" << filename.c_str();
            return false;
        }
        ofs.write(buf.c_str(), buf.size());
        if (!ofs.good()) {
            LOG(ERROR) << "WRITE %s FILE FAILED! "<<  filename.c_str();
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
    static std::string urlEncode(const std::string& url, bool convert_space_to_plus) {
        std::string res;
        for (auto &c : url) {
            if (c == '.' || c == '-' || c == '_' || c == '~' || isalnum(c)) {
                res += c;
            } else if (c == ' ' && convert_space_to_plus) {
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
            if (url[i] == '+' && convert_plus_to_space) {
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
    static std::string statusDesc(int status) { return (status_msg.find(status) != status_msg.end()) ? status_msg[status] : "Unkonw"; }
    //Context-type
    static std::string extMime(const std::string &filename) {
        //E.G.  xxxx.txt
        size_t pos = filename.find_last_of('.');
        if (pos == std::string::npos) {
            return "application/octet-stream";
        }
        std::string ext = filename.substr(pos);

        return (mime_msg.find(ext) != mime_msg.end()) ? mime_msg[ext] : "application/octet-stream";
    }

    static bool isDirectory(const std::string &filename) {
        struct stat st{};
        int ret = stat(filename.c_str(), &st);
        if (ret < 0) {
            char cwd[1024]{};
            getcwd(cwd, sizeof(cwd));
            if (getcwd(cwd, sizeof(cwd)) != nullptr) {
                std::cout << "Current working directory: " << cwd << std::endl;
            } else {
                std::perror("getcwd failed");
            }
            std::perror("stat failed");
            return false;
        }
        return S_ISDIR(st.st_mode); //是否为目录
    }
    static bool isRegular(const std::string &filename) {
        struct stat st{};
        int ret = stat(filename.c_str(), &st);
        if (ret < 0) {
            return false;
        }
        return S_ISREG(st.st_mode);  //是否为常规文件
    }

    //http请求的资源路径有效性判断
    static bool validPath(const std::string &path) {
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
    void reSet() {
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
    inline bool hasHeader(const std::string &key) const { return _headers.contains(key); }
    std::string getHeader(const std::string &key) const { return _headers.contains(key) ? _headers.at(key) : ""; }
    inline void setParam(const std::string &key, const std::string &val) { _params.emplace(key, val); }
    inline bool hasParam(const std::string &key) const { return _params.contains(key);}
    inline std::string getParam(const std::string &key) const { return _params.contains(key) ? _params.at(key) : ""; }
    //获取正文长度
    size_t contentLength() const {
        // Content-Length: 1234\r\n
        if (!hasHeader("Content-Length")) {
            return 0;
        }
        std::string clen = getHeader("Content-Length");
        return std::stol(clen);
    }
    //判断是否是短链接  : ture -> 短链接
    bool isClose() const {
        // 没有Connection字段，或者有Connection但是值是close，则都是短链接，否则就是长连接
        if (getHeader("Connection") == "keep-alive") {
            return false;
        }
        return true;
    }
};

class HttpResponse {
public:
    int _status;
    bool _redirect_flag;
    std::string _body;
    std::string _redirect_url;
    std::unordered_map<std::string, std::string> _headers;
public:
    HttpResponse(): _redirect_flag(false), _status(200) {}
    explicit HttpResponse(int status): _redirect_flag(false), _status(status) {}
    void reSet() {
        _status = 200;
        _redirect_flag = false;
        _body.clear();
        _redirect_url.clear();
        _headers.clear();
    }
    inline void setHeader(const std::string &key, const std::string &val) { _headers.emplace(key, val); }
    inline bool hasHeader(const std::string &key) { return _headers.find(key) != _headers.end(); }
    inline std::string getHeader(const std::string &key) { return (_headers.find(key) != _headers.end()) ? _headers.at(key) : ""; }
    void setContent(const std::string &body,  const std::string &type = "text/html") {
        _body = body;
        setHeader("Content-Type", type);
    }
    void setRedirect(const std::string &url, int statu = 302) {
        _status = statu;
        _redirect_flag = true;
        _redirect_url = url;
    }
    bool isClose() {
        if (getHeader("Connection") == "keep-alive") {
            return false;
        }
        return true;
    }
};

typedef enum {
    RECV_HTTP_ERROR,
    RECV_HTTP_LINE,
    RECV_HTTP_HEAD,
    RECV_HTTP_BODY,
    RECV_HTTP_OVER
}HttpRecStatus;

#define MAX_LINE 8192
class HttpContext {
private:
    int _resp_status; //响应状态码
    HttpRecStatus _recv_status; //当前接收及解析的阶段状态
    HttpRequest _request;  //已经解析得到的请求信息
private:
    bool parseHttpLine(const std::string& line) {
        std::smatch matches;
        //std::regex::icase  匹配忽略大小写
        std::regex e("(GET|HEAD|POST|PUT|DELETE) ([^?]*)(?:\\?(.*))? (HTTP/1\\.[01])(?:\n|\r\n)?", std::regex::icase);
        if (!std::regex_match(line, matches, e)) {
            _recv_status = RECV_HTTP_ERROR;
            _resp_status = 400;//BAD REQUEST
            return false;
        }
        //0 : GET /hello/login?user=Dusong&pass=123123 HTTP/1.1
        //1 : GET
        //2 : /hello/login
        //3 : user=dusong&pass=123123
        //4 : HTTP/1.1
        //请求方法的获取
        _request._method = matches[1];
        std::transform(_request._method.begin(), _request._method.end(), _request._method.begin(), ::toupper);
        //资源路径的获取，需要进行URL解码操作，但是不需要+转空格
        _request._path = Util::urlDecode(matches[2], false);
        //协议版本的获取
        _request._version = matches[4];
        //查询字符串的获取与处理
        std::vector<std::string> query_string_array;
        std::string query_string = matches[3];
        //查询字符串的格式 key=val&key=val....., 先以 & 符号进行分割，得到各个字串
        Util::split(query_string, &query_string_array, "&");
        //针对各个字串，以 = 符号进行分割，得到key 和val， 得到之后也需要进行URL解码
        bool result = std::ranges::all_of(query_string_array, [&](auto& str) {
            size_t pos = str.find("=");
            if (pos == std::string::npos) {
                _recv_status = RECV_HTTP_ERROR;
                _resp_status = 400; // BAD REQUEST
                return false;
            }
            std::string key = Util::urlDecode(str.substr(0, pos), true);
            std::string val = Util::urlDecode(str.substr(pos + 1), true);
            _request.setParam(key, val);
            return true;
        });
        if (!result) {
            return false;
        }
        return true;
    }
    bool recvHttpLine(Buffer* buf) {
        if (_recv_status != RECV_HTTP_LINE) return false;
        std::string line = buf->getLineAndMove();
        //缓冲区中的数据不足一行
        if (line.empty()) {
            //缓冲区中的数据大于了最大请求行的长度，但是却没有读完  ->  error
            if (buf->readAbleSize() > MAX_LINE) {
                _recv_status = RECV_HTTP_ERROR;
                _resp_status = 414; //URI TOO LONG
                return false;
            }
            //缓冲区中数据不足一行，但是也不多，就等等新数据的到来
            return true;
        }
        if (line.size() > MAX_LINE) {
            _recv_status = RECV_HTTP_ERROR;
            _resp_status = 414;//URI TOO LONG
            return false;
        }
        if (!parseHttpLine(line)) {
            return false;
        }
        _recv_status = RECV_HTTP_HEAD;
        return true;
    }
    bool recvHttpHead(Buffer* buf) {
        if (_recv_status != RECV_HTTP_HEAD) return false;
        //读取每一行字段和字段值，放入request对象中
        while (1) {
            std::string line = buf->getLineAndMove();
            if (line.empty()) {
                if (buf->readAbleSize() > MAX_LINE) {
                    _recv_status = RECV_HTTP_ERROR;
                    _resp_status = 414;//URI TOO LONG
                    return false;
                }
                return true;
            }
            if (line.size() > MAX_LINE) {
                _recv_status = RECV_HTTP_ERROR;
                _resp_status = 414;//URI TOO LONG
                return false;
            }
            if (line == "\n" || line == "\r\n") {
                break;
            }
            if (!parseHttpHead(line)) {
                return false;
            }
        }
        //头部处理完毕，进入正文获取阶段
        _recv_status = RECV_HTTP_BODY;
        return true;
    }
    bool parseHttpHead(std::string& line) {
        //key: val\r\nkey: val\r\n....
        if (line.back() == '\n') line.pop_back();//末尾是换行则去掉换行字符
        if (line.back() == '\r') line.pop_back();//末尾是回车则去掉回车字符
        size_t pos = line.find(": ");
        if (pos == std::string::npos) {
            _recv_status = RECV_HTTP_ERROR;
            _resp_status = 400;
            return false;
        }
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 2);
        _request.setHeader(key, val);
        return true;
    }
    bool recvHttpBody(Buffer* buf) {
        if (_recv_status != RECV_HTTP_BODY) return false;
        size_t content_length = _request.contentLength();
        // 没正文
        if (content_length == 0) {
            _recv_status = RECV_HTTP_OVER;
            return true;
        }
        size_t real_len = content_length - _request._body.size();//实际还需要接收的正文长度
        //能够全部读取完正文
        if (buf->readAbleSize() >= real_len) {
            _request._body.append(buf->readPosition(), real_len);
            buf->moveReadOffset(real_len);
            _recv_status = RECV_HTTP_OVER;
            return true;
        }
        //不能一次性全部读完
        _request._body.append(buf->readPosition(), buf->readAbleSize());
        buf->moveReadOffset(buf->readAbleSize());
        return true;
    }
public:
    HttpContext() : _resp_status(200), _recv_status(RECV_HTTP_LINE) {}
    void reSet() {
        _resp_status = 200;
        _recv_status = RECV_HTTP_LINE;
        _request.reSet();
    }
    inline int respStatus() const { return _resp_status; }
    inline HttpRecStatus recStatus() { return _recv_status; }

    HttpRequest& request() { return _request; }
    //接收并解析HTTP请求
    void recvHttpRequest(Buffer* buf) {
        switch (_recv_status) {
            case RECV_HTTP_LINE: recvHttpLine(buf);
            case RECV_HTTP_HEAD: recvHttpHead(buf);
            case RECV_HTTP_BODY: recvHttpBody(buf);
        }
    }
};



class HttpServer {
private:
    using Handler = std::function<void(const HttpRequest&, HttpResponse*)>;
    using Handlers = std::vector<std::pair<std::regex, Handler>>;
    Handlers _get_route;
    Handlers _post_route;
    Handlers _put_route;
    Handlers _delete_route;
    std::string _basedir; //静态资源根目录
    TcpServer _server;
private:
    static void errorHandler(const HttpRequest& req, HttpResponse* rsp) {
        std::string body;
        body += "<html>";
        body += "<head>";
        body += "<meta http-equiv='Content-Type' content='text/html;charset=utf-8'>";
        body += "</head>";
        body += "<body>";
        body += "<h1>";
        body += std::to_string(rsp->_status);
        body += " ";
        body += Util::statusDesc(rsp->_status);   //状态码描述
        body += "</h1>";
        body += "</body>";
        body += "</html>";
        rsp->setContent(body, "text/html");     //设置正文，并设置Content-Type值
    }

    //组织响应报文和发送
    void writeReponse(const sPtrConnection& conn, const HttpRequest& req, HttpResponse& rsp) {
        //填写头部字段
        if (req.isClose()) {
            rsp.setHeader("Connection", "close");
        } else {
            rsp.setHeader("Connection", "keep-alive");
        }
        if (!rsp._body.empty() && !rsp.hasHeader("Content-Length")) {
            rsp.setHeader("Content-Length", std::to_string(rsp._body.size()));
        }
        if (!rsp._body.empty() && !rsp.hasHeader("Content-Type")) {
            rsp.setHeader("Content-Type", "application/octet-stream");
        }
        if (rsp._redirect_flag) {   //重定向
            rsp.setHeader("Location", rsp._redirect_url);
        }

        //组织http响应报文
        std::stringstream rsp_str;
        rsp_str << req._version << " " << std::to_string(rsp._status) << " " << Util::statusDesc(rsp._status) << "\r\n";
        for (auto& head : rsp._headers) {
            rsp_str << head.first << ": " << head.second << "\r\n";
        }
        rsp_str << "\r\n";
        rsp_str << rsp._body;

        //发送数据
        conn->send(rsp_str.str().c_str(), rsp_str.str().size());
    }
    bool isFileHandler(const HttpRequest& req) {
        // 必须设置了静态资源根目录
        if (_basedir.empty()) {
            return false;
        }
        if (req._method != "GET" && req._method != "HEAD") {
            return false;
        }
        // 判断合法路径
        if (!Util::validPath(req._path)) {
            return false;
        }
        // 4. 请求的资源必须存在,且是一个普通文件
        //   /image/a.png  ->   ./wwwroot/image/a.png
        std::string req_path = _basedir + req._path;//为了避免直接修改请求的资源路径，因此定义一个临时对象
        if (req._path.back() == '/') {
            req_path += "index.html";
        }
        if (!Util::isRegular(req_path)) {   // 普通文件
            return false;
        }
        return true;
    }
    //静态资源的请求处理 --- 将静态资源文件的数据读取出来，放到rsp的_body中, 并设置mime
    void fileHandler(const HttpRequest& req, HttpResponse* rsp) {
        std::string req_path = _basedir + req._path;
        if (req._path.back() == '/') {
            req_path += "index.html";
        }
        bool ret = Util::readFile(req_path, &rsp->_body);
        if (!ret) {
            return;
        }
        std::string mime = Util::extMime(req_path);
        rsp->setHeader("Content-Type", mime);
    }
    //功能性请求的分类处理
    //在对应请求方法的路由表中，查找是否含有对应资源请求的处理函数，有则调用，没有则发挥404
    //Handlers: key:正则表达式   value: 处理函数
    //  eg.  /numbers/(\d+)       /numbers/12345
    void dispatcher(HttpRequest& req, HttpResponse* rsp, Handlers& handlers) {
        for (const auto& [re, functor] : handlers) {
            //const std::regex& re = handler.first;
            //const Handler& functor = handler.second;
            bool ret = std::regex_match(req._path, req._matches, re);
            if (!ret) {
                continue;
            }
            return functor(req, rsp);  //传入请求信息，和空的rsp，执行处理函数
        }
        rsp->_status = 404;
    }
    void route(HttpRequest& req, HttpResponse* rsp) {
        if (isFileHandler(req)) {
            //静态资源请求
            return fileHandler(req, rsp);
        }
        if (req._method == "GET" || req._method == "HEAD") {
            return dispatcher(req, rsp, _get_route);
        } else if (req._method == "POST") {
            return dispatcher(req, rsp, _post_route);
        } else if (req._method == "PUT") {
            return dispatcher(req, rsp, _put_route);
        } else if (req._method == "DELETE") {
            return dispatcher(req, rsp, _delete_route);
        }
        rsp->_status = 405;// Method Not Allowed
    }

    //建立链接调用设置上下文的回调
    void OnConnected(const sPtrConnection& conn) {
        conn->setContext(HttpContext());
        std::cout << "NEW CONNECTION: " << conn.get() << std::endl;
    }

    //缓冲区数据解析+处理回调
    void OnMessage(const sPtrConnection& conn, Buffer* buffer) {
        while (buffer->readAbleSize() > 0) {
            //1. 获取上下文
            auto* context = conn->getContext()->get<HttpContext>();

            context->recvHttpRequest(buffer);   //解析请求报文
            HttpRequest& req = context->request();
            HttpResponse rsp(context->respStatus());
            if (context->respStatus() >= 400) {
                //进行错误响应，关闭连接
                errorHandler(req, &rsp);//填充一个错误显示页面数据到rsp中
                writeReponse(conn, req, rsp);//组织响应发送给客户端
                context->reSet();   //刷新上下文
                buffer->moveReadOffset(buffer->readAbleSize());   //清空缓冲区
                conn->shutdown();//关闭连接
                return;
            }
            if (context->recStatus() != RECV_HTTP_OVER) {
                //当前请求还没有接收完整,则退出，等新数据到来再重新继续处理
                return;
            }
            route(req, &rsp);
            writeReponse(conn, req, rsp);
            context->reSet();
            if (rsp.isClose()) conn->shutdown();      //短链接通信后直接关闭
        }
    }
public:
    HttpServer(int port, int timeout = DEFAULT_TIMEOUT) : _server(port) {
        _server.enableInactiveRelease(timeout);
        _server.setConnectedCallback([this](auto && PH1) { OnConnected(std::forward<decltype(PH1)>(PH1)); });
        _server.setMessageCallback([this](auto && PH1, auto && PH2) { OnMessage(std::forward<decltype(PH1)>(PH1), std::forward<decltype(PH2)>(PH2)); });
        _server.setAnyEventCallback([this](auto && PH1) {
            std::cout << "setAnyEventCallback" << std::endl;
        });

    }
    void setBaseDir(const std::string& path) {
        assert(Util::isDirectory(path));
        _basedir = path;
    }
    /*设置/添加，请求（请求的正则表达）与处理函数的映射关系*/
    void GET(const std::string& pattern, const Handler& handler) {
        _get_route.emplace_back(std::regex(pattern), handler);
    }
    void POST(const std::string& pattern, const Handler& handler) {
        _post_route.emplace_back(std::regex(pattern), handler);
    }
    void PUT(const std::string& pattern, const Handler& handler) {
        _put_route.emplace_back(std::regex(pattern), handler);
    }
    void DELETE(const std::string& pattern, const Handler& handler) {
        _delete_route.emplace_back(std::regex(pattern), handler);
    }
    void setThreadCount(int count) {
        _server.setThreadCount(count);
    }
    void listen() {
        _server.run();
    }
};