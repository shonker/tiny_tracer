#pragma once

#include <cctype>
#include <string>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <map>
#include <vector>


struct FuncInfo
{
    FuncInfo()
    {
    }

    FuncInfo(const FuncInfo& a)
    {
        this->dllName = a.dllName;
        this->funcName = a.funcName;
    }

    virtual bool load(const std::string& line, char delimiter);

    bool isValid() const
    {
        return dllName.length() > 0 && funcName.length() > 0;
    }

    std::string dllName;
    std::string funcName;
};

struct WFuncInfo : public FuncInfo
{
    WFuncInfo() : paramCount(0)
    {
    }

    WFuncInfo(const WFuncInfo& a)
    {
        this->dllName = a.dllName;
        this->funcName = a.funcName;
        this->paramCount = a.paramCount;
    }

    virtual bool load(const std::string &line, char delimiter);

    bool update(const WFuncInfo &func_info);

    size_t paramCount;
};

struct WSyscallInfo
{
    WSyscallInfo() : syscallId(0), paramCount(0)
    {
    }

    bool load(const std::string& line, char delimiter);

    bool update(const WSyscallInfo& syscall_info);

    uint32_t syscallId;
    size_t paramCount;
};

class FuncWatchList {
public:
    FuncWatchList()
    {
    }

    ~FuncWatchList()
    {
    }

    size_t loadList(const char* filename);

    std::vector<WFuncInfo> funcs;
    std::map<uint32_t, WSyscallInfo> syscalls;

private:
    bool appendFunc(WFuncInfo& info);
    void appendSyscall(WSyscallInfo& syscall_info);

    WFuncInfo* findFunc(const std::string& dllName, const std::string& funcName);
};

//---

class FuncExcludeList {
public:
    FuncExcludeList()
    {
    }

    ~FuncExcludeList()
    {
    }

    bool isEmpty() { return this->funcs.size() > 0 ? false : true; }

    bool contains(const std::string& dll_name, const std::string& func);

    size_t loadList(const char* filename);

    std::vector<FuncInfo> funcs;

private:
    bool appendFunc(FuncInfo& info);

    FuncInfo* findFunc(const std::string& dllName, const std::string& funcName);
};