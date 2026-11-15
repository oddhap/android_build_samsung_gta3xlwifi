#pragma once
#include <memory>
#include <vector>
#include <cstdint>
namespace android {
inline constexpr int OK=0;
template<class T> class wp;
template<class T> class sp:public std::shared_ptr<T>{
 public:using std::shared_ptr<T>::shared_ptr;sp()=default;sp(const std::shared_ptr<T>&p):std::shared_ptr<T>(p){}
 template<class U>sp(const sp<U>&p):std::shared_ptr<T>(p){}
 template<class...A>static sp<T>make(A&&...a){return std::make_shared<T>(std::forward<A>(a)...);}
 void clear(){this->reset();}
};
template<class T>class wp:public std::weak_ptr<T>{
 public:using std::weak_ptr<T>::weak_ptr;wp()=default;wp(const sp<T>&p):std::weak_ptr<T>(p){}
 static wp<T>fromExisting(T*p){return sp<T>(std::static_pointer_cast<T>(p->shared_from_this()));}
 sp<T>promote()const{return this->lock();}
};
class IBinder:public std::enable_shared_from_this<IBinder>{
 public:class DeathRecipient{public:virtual ~DeathRecipient()=default;virtual void binderDied(const wp<IBinder>&)=0;};
 virtual ~IBinder()=default;int linkError=0;std::vector<sp<DeathRecipient>>deaths;
 int linkToDeath(const sp<DeathRecipient>&d){if(linkError)return linkError;deaths.push_back(d);return OK;}
 int unlinkToDeath(const sp<DeathRecipient>&d){for(auto i=deaths.begin();i!=deaths.end();++i)if(*i==d){deaths.erase(i);return OK;}return -1;}
 void kill(){auto current=deaths;deaths.clear();for(auto&d:current)d->binderDied(wp<IBinder>(sp<IBinder>(shared_from_this())));}
};
namespace binder{class Status{public:static constexpr int EX_SECURITY=-1;int code=0,exception=0;
 static Status ok(){return {};}
 static Status fromServiceSpecificError(int c){Status s;s.code=c;return s;}
 static Status fromExceptionCode(int c){Status s;s.exception=c;return s;}
 bool isOk()const{return !code&&!exception;}
};}
}
