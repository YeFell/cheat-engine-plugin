#pragma once
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <codecvt>

#define ConsoleOut(str,...) Utils::ConsolePrint("INFO:" str "\n", __VA_ARGS__)

#define ConsoleOut_n(str,...) Utils::ConsolePrint("INFO:" str, __VA_ARGS__)

#define ConsolePrintf(str,...) Utils::ConsolePrint(str, __VA_ARGS__)

namespace Utils {
    float itof(long i);
    std::vector<char> HexToBytes(const std::string& hex);

	std::string BytesToString(unsigned char* data, int len);

    std::vector<std::string> Split(std::string str, std::string pattern);


    /*
     * @brief Wait for all the given modules to be loaded
     *
     * @param timeout How long to wait
     * @param modules List of modules to wait for
     *
     * @returns See WaitForSingleObject return values.
     */
    int WaitForModules(std::int32_t timeout, const std::initializer_list<std::wstring>& modules);


    bool Sunday(unsigned char* src, unsigned long len_s, unsigned long* des, unsigned long len_d, unsigned long* buffer);

    /*
     * @brief Scan for a given byte pattern on a module
     *
     * @param module    Base of the module to search
     * @param signature IDA-style byte array pattern
     *
     * @returns Address of the first occurence
     */


    std::uint8_t* PatternScan(HMODULE module, const char* signature);


    void AttachConsole();
    void DetachConsole();
    bool ConsolePrint(const char* fmt, ...);
    void ConsoleSwap();
    std::string UnicodeToUtf8(const std::wstring& wstr);
    std::wstring Utf8ToUnicode(const std::string& str);
    std::wstring AnsiToUnicode(const std::string& s);

    std::string UnicodeToAnsi(const std::wstring& s);

    std::string AnsiToUtf8(const std::string& s);

    std::string Utf8ToAnsi(const std::string& s);

    namespace Base
    {
        byte* get_relative_address(byte* addr);
        byte* get_addr(HMODULE module, const char* signature, int offset1 = 0, int offset2 = 0, int offset3 = 0);
        byte* get_addr_addr(HMODULE module, const char* signature, int offset1 = 0, int offset2 = 0, int offset3 = 0);
        byte* get_call_addr(HMODULE module, const char* signature, int offset1 = 0, int offset2 = 0, int offset3 = 0);
        byte* get_call(HMODULE module, const char* signature, int offset1 = 0, int offset2 = 0, int offset3 = 0);

        template<typename T>
        T get_addr_offset(HMODULE module, const char* signature, int offset1 = 0, int offset2 = 0, int offset3 = 0)
        {
            auto addr = get_addr(module, signature, offset1);
            if (!addr)
                return NULL;
            return *(T*)(addr)+offset3;
        }

        template<typename T>
        T get_call_offset(HMODULE module, const char* signature, int offset1 = 0, int offset2 = 0, int offset3 = 0)
        {
            auto addr = get_call(module, signature, offset1);
            if (!addr)
                return NULL;
            
            return *(T*)(addr + offset2) + offset3;
        }

    }
}
