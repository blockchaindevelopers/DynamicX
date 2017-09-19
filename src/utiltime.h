// Copyright (c) 2009-2017 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Developers
// Copyright (c) 2014-2017 The Dash Core Developers
// Copyright (c) 2016-2017 Duality Blockchain Solutions Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DYNAMIC_UTILTIME_H
#define DYNAMIC_UTILTIME_H

#include <cstdint>
#include <string>

/* Units of Time */
static const int TIME_ONESECOND = 1;
static const int TIME_ONEMINUTE = TIME_ONESECOND * 60;
static const int TIME_ONEHOUR = TIME_ONEMINUTE * 60;
static const int TIME_ONEDAY = TIME_ONEHOUR * 24;
static const int TIME_ONEWEEK = TIME_ONEDAY * 7;
static const int TIME_ONEMONTH = TIME_ONEWEEK * 30;
static const int TIME_ONEYEAR = TIME_ONEMONTH * 12;

int64_t GetTime();
int64_t GetTimeMillis();
int64_t GetTimeMicros();
int64_t GetLogTimeMicros();
void SetMockTime(int64_t nMockTimeIn);
void MilliSleep(int64_t n);

std::string DateTimeStrFormat(const char* pszFormat, int64_t nTime);
std::string DurationToDHMS(int64_t nDurationTime);

#endif // DYNAMIC_UTILTIME_H
