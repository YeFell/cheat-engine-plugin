#pragma once
#include "NtFun.h"
#include "KAPCall.h"



class KHack
{
public:
	KHack();
	~KHack();

public:
	SYMBOL_FUNCTION_ADDR	symbol;
	NtFun*					ntfun;
	KAPCall*				kapc;
};

