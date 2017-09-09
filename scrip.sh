#!/bin/bash

for FILE in \
    src/*.cpp \
    src/*.h \
    src/bench/*.cpp \
    src/bench/*.h \
    src/compat/*.cpp \
    src/compat/*.h \
    src/consensus/*.cpp \
    src/consensus/*.h \
    src/crypto/*.cpp \
    src/crypto/*.h \
    src/primitives/*.cpp \
    src/primitives/*.h \
    src/qt/*.cpp \
    src/qt/*.h \
    src/rpc/*.cpp \
    src/rpc/*.h \
    src/script/*.cpp \
    src/script/*.h \
    src/support/*.cpp \
    src/support/*.h \
    src/test/*.cpp \
    src/test/*.h \
    src/wallet/*.cpp \
    src/wallet/*.h \
    src/zmq/*.cpp \
    src/zmq/*.h \
    ; do
    sed -i 's/#include <\(assert\|errno\|limits\|math\|signal\|stdarg\|stdint\|stdio\|stdlib\|string\).h>/#include <c\1>/g' "$FILE"
done
