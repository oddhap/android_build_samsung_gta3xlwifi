#pragma once
#include <string>
#ifndef EREMOTEIO
#define EREMOTEIO 121
#endif
#ifndef EUCLEAN
#define EUCLEAN 117
#endif
enum IptablesTarget{V4=1,V6=2,V4V6=3};
class IptablesRestoreInterface{public:virtual ~IptablesRestoreInterface()=default;virtual int execute(IptablesTarget,const std::string&,std::string*)=0;};
