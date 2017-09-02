// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DYNAMIC_FS_H
#define DYNAMIC_FS_H


#include <boost/filesystem/fstream.hpp>

/** Filesystem operations and types */
namespace fs = boost::filesystem;

/** Bridge operations to C stdio */
namespace fsbridge {
FILE *fopen(const fs::path& p, const char *mode);
FILE *freopen(const fs::path& p, const char *mode, FILE *stream);
};

#endif // DYNAMIC_FS_H

