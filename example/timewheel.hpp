#include <memory>
#include <functional>
#include <unordered_map>
#include <vector>
#include <cstdint>


using taskFunc = std::function<void()>;
using releaseFunc = std::function<void()>;
struct timerTask{
private:
    uint64_t _id;
    uint32_t _timeout;
    bool _canceled;     //true该任务被取消
    taskFunc _task_cb;
    releaseFunc _release;
public:
    timerTask(uint64_t id, uint32_t delay, const taskFunc& task_cb) 
    :_id(id), _timeout(delay), _task_cb(task_cb), _canceled(false) {}
    ~timerTask() {
        if (!_canceled) _task_cb(); 
        _release();
    }
    void setRelease(const releaseFunc& cb) { _release = cb; }   //将任务从_timer哈希表中销毁
    uint32_t getDelayTime() { return _timeout; }
    void cancel() { _canceled = true; }
};

class timerWheel {
private:
    using weakTask = std::weak_ptr<timerTask>;
    using sPtrTask = std::shared_ptr<timerTask>;
    int _capacity;
    std::vector<std::vector<sPtrTask>> _wheel;
    int _tick;
    std::unordered_map<uint64_t, weakTask> _timers;     //记录每个id的指针位置，但是不增加引用计数

private:
    void removeTimer(uint64_t id) {
        if (_timers.contains(id)) {
            _timers.erase(id);
        }
    }

public:
    timerWheel(): _capacity(60), _tick(0), _wheel(_capacity) {}
    void timerAdd(uint64_t id, uint32_t delay, const taskFunc& cb) {
        sPtrTask sptr(new timerTask(id, delay, cb));
        sptr->setRelease(std::bind(&timerWheel::removeTimer, this, id));
        int pos = (_tick + delay) % _capacity;
        _wheel[pos].push_back(sptr);
        _timers[id] = weakTask(sptr);
    }
    void timerRefresh(uint64_t id) {
        if (~_timers.contains(id)) { return; }
        sPtrTask sptr = _timers[id].lock();     //获取weak_ptr管理的对象的shared_ptr
        int delay = sptr->getDelayTime();
        int pos = (_tick + delay) % _capacity;
        _wheel[pos].push_back(sptr);
    }
    void runTimerTask() {
        _tick = (_tick + 1) % _capacity;
        _wheel[_tick].clear();
    }
    void timerCancel(uint64_t id) {
        if (_timers.contains(id)) {
            sPtrTask sptr = _timers[id].lock();
            if (sptr) {
                sptr->cancel();
            }
        }
    }

};