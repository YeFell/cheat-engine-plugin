#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifndef _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "utils.h"

static HANDLE _out = NULL, _old_out = NULL;
static HANDLE _err = NULL, _old_err = NULL;
static HANDLE _in = NULL, _old_in = NULL;

static bool _swap = false;

float Utils::itof(long i)
{
	float j = NULL;
	*(long*)&j = i;
	return j;
}

std::vector<char> Utils::HexToBytes(const std::string& hex) {
	std::vector<char> res;

	for (auto i = 0u; i < hex.length(); i += 2) {
		std::string byteString = hex.substr(i, 2);
		char byte = (char)strtol(byteString.c_str(), NULL, 16);
		res.push_back(byte);
	}

	return res;
}

std::string Utils::BytesToString(unsigned char* data, int len) {
	constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
								'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	std::string res(len * 2, ' ');
	for (int i = 0; i < len; ++i) {
		res[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
		res[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return res;
}

std::vector<std::string> Utils::Split(std::string str, std::string pattern)
{
	std::string::size_type pos;
	std::vector<std::string> result;
	str += pattern;
	auto size = str.size();
	for (size_t i = 0; i < size; i++)
	{
		pos = str.find(pattern, i);
		if (pos < size)
		{
			std::string s = str.substr(i, pos - i);
			result.push_back(s);
			i = pos + pattern.size() - 1;
		}
	}
	return result;
}


/*
 * @brief Wait for all the given modules to be loaded
 *
 * @param timeout How long to wait
 * @param modules List of modules to wait for
 *
 * @returns See WaitForSingleObject return values.
 */
int Utils::WaitForModules(std::int32_t timeout, const std::initializer_list<std::wstring>& modules)
{
	bool signaled[32] = { 0 };
	bool success = false;

	std::uint32_t totalSlept = 0;

	if (timeout == 0) {
		for (auto& mod : modules) {
			if (GetModuleHandleW(std::data(mod)) == NULL)
				return WAIT_TIMEOUT;
		}
		return WAIT_OBJECT_0;
	}

	if (timeout < 0)
		timeout = INT32_MAX;

	while (true) {
		for (auto i = 0u; i < modules.size(); ++i) {
			auto& module = *(modules.begin() + i);
			if (!signaled[i] && GetModuleHandleW(std::data(module)) != NULL) {
				signaled[i] = true;

				//
				// Checks if all modules are signaled
				//
				bool done = true;
				for (auto j = 0u; j < modules.size(); ++j) {
					if (!signaled[j]) {
						done = false;
						break;
					}
				}
				if (done) {
					success = true;
					goto exit;
				}
			}
		}
		if (totalSlept > std::uint32_t(timeout)) {
			break;
		}
		Sleep(10);
		totalSlept += 10;
	}

exit:
	return success ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
}

/*
 * @brief Scan for a given byte pattern on a module
 *
 * @param module    Base of the module to search
 * @param signature IDA-style byte array pattern
 *
 * @returns Address of the first occurence
 */
std::uint8_t* Utils::PatternScan(HMODULE module, const char* signature)
{
	static auto pattern_to_byte = [](const char* pattern) {
		auto bytes = std::vector<unsigned long>{};
		auto start = const_cast<char*>(pattern);
		auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current) {
			if (*current == '?') {
				++current;
				if (*current == '?')
					++current;
				bytes.push_back('?');
			}
			else {
				bytes.push_back(strtoul(current, &current, 16));
			}
		}
		return bytes;
	};

	auto dosHeader = (PIMAGE_DOS_HEADER)module;
	sizeof(IMAGE_DOS_HEADER);
	auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);
	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto patternBytes = pattern_to_byte(signature);
	auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

	while (patternBytes.size())
	{
		if (patternBytes[patternBytes.size() - 1] != '?')
			break;
		patternBytes.pop_back();
	}

	auto s = (unsigned long)patternBytes.size();
	auto d = patternBytes.data();

	unsigned long i = 0u;
	return Sunday(scanBytes, sizeOfImage, d, s, &i) ? &scanBytes[i] : NULL;
}

bool Utils::Sunday(unsigned char* src, unsigned long len_s, unsigned long* des, unsigned long len_d, unsigned long* buffer)
{
	unsigned int i = 0;
	unsigned int move[256] = { 0 };
	unsigned char* p = src;
	unsigned int max = len_d + 1;
	if (src == NULL || des == NULL)
		return false;

	for (i = 0; i < 256; i++)
		move[i] = max;
	for (i = 0; i < len_d; i++)
		move[des[i]] = len_d - i;

	while (p <= src + len_s - len_d)
	{
		for (i = 0; i < len_d; i++) {
			if (des[i] != '?' && p[i] != des[i]) break;
		}
		if (i == len_d) {
			*buffer = (unsigned long)(p - src); return true;
		}
		else
		{
			p += (max == move['?']) ? move[p[len_d]] : (max == move[p[len_d]]) ? move['?'] : move[p[len_d]];
		}

	}
	return false;
}


void Utils::AttachConsole()
{
	_swap = true;

	_old_out = GetStdHandle(STD_OUTPUT_HANDLE);
	_old_err = GetStdHandle(STD_ERROR_HANDLE);
	_old_in = GetStdHandle(STD_INPUT_HANDLE);

	::AllocConsole() && ::AttachConsole(GetCurrentProcessId());

	_out = GetStdHandle(STD_OUTPUT_HANDLE);
	_err = GetStdHandle(STD_ERROR_HANDLE);
	_in = GetStdHandle(STD_INPUT_HANDLE);

	SetConsoleMode(_out,
		ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);

	SetConsoleMode(_in,
		ENABLE_INSERT_MODE | ENABLE_EXTENDED_FLAGS |
		ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE);

	ConsoleOut("initialization!");
}

void Utils::DetachConsole()
{
	_swap = false;
	if (_out || _err || _in) {
		FreeConsole();

		if (_old_out)
			SetStdHandle(STD_OUTPUT_HANDLE, _old_out);
		if (_old_err)
			SetStdHandle(STD_ERROR_HANDLE, _old_err);
		if (_old_in)
			SetStdHandle(STD_INPUT_HANDLE, _old_in);
		_out = _in = _err = NULL;
	}
}

bool Utils::ConsolePrint(const char* fmt, ...)
{
	if (!_out)
		return false;

	char buf[0x1024];
	va_list va;

	va_start(va, fmt);
	_vsnprintf_s(buf, sizeof(buf), fmt, va);
	va_end(va);

	return WriteConsoleA(_out, buf, static_cast<DWORD>(strlen(buf)), nullptr, nullptr);
}

void Utils::ConsoleSwap()
{
	(_swap = !_swap) ? AttachConsole() : DetachConsole();
}

std::string Utils::UnicodeToUtf8(const std::wstring& wstr)
{
	std::string ret;
	std::wstring_convert< std::codecvt_utf8<wchar_t> > wcv;
	ret = wcv.to_bytes(wstr);
	return ret;
}

std::wstring Utils::Utf8ToUnicode(const std::string& str)
{
	std::wstring ret;
	std::wstring_convert< std::codecvt_utf8<wchar_t> > wcv;
	ret = wcv.from_bytes(str);
	return ret;
}

std::wstring Utils::AnsiToUnicode(const std::string& s)
{
	using default_convert = std::codecvt<wchar_t, char, std::mbstate_t>;
	static std::wstring_convert<default_convert>conv(new default_convert("CHS"));
	return conv.from_bytes(s);
}

std::string Utils::UnicodeToAnsi(const std::wstring& s)
{
	using default_convert = std::codecvt<wchar_t, char, std::mbstate_t>;
	static std::wstring_convert<default_convert>conv(new default_convert("CHS"));
	return conv.to_bytes(s);
}

std::string Utils::AnsiToUtf8(const std::string& s)
{
	static std::wstring_convert<std::codecvt_utf8<wchar_t> > conv;
	return conv.to_bytes(AnsiToUnicode(s));
}

std::string Utils::Utf8ToAnsi(const std::string& s)
{
	static std::wstring_convert<std::codecvt_utf8<wchar_t> > conv;
	return UnicodeToAnsi(conv.from_bytes(s));
}

