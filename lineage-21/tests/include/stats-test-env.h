#pragma once
#include <cstdio>
FILE* gta3xlwifiTestOpen(const char* name, const char* mode);
#define fopen gta3xlwifiTestOpen
