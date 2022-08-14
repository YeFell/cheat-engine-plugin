#include "global.h"
#include "KHack.h"

KHack::KHack():
	ntfun(new NtFun(this))
{
	RtlZeroMemory(&this->symbol, sizeof(this->symbol));
}

KHack::~KHack()
{
	delete ntfun;
}