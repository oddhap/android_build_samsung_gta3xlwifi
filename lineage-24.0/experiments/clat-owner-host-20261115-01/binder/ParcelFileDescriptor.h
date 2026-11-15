#pragma once
namespace android::os {class ParcelFileDescriptor{int fd;public:explicit ParcelFileDescriptor(int value):fd(value){}int get()const{return fd;}};}
