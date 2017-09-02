#!/bin/bash
# prune include files one at a time, recompile, and put them back if it doesn't compile
# arguments are list of files to check

# Courtesy of https://stackoverflow.com/questions/1301850/tools-to-find-included-headers-which-are-unused

removeinclude() {
    file=$1
    header=$2
    perl -i -p -e 's+([ \t]*#include[ \t][ \t]*[\"\<]'$2'[\"\>])+//REMOVEINCLUDE $1+' $1
}
replaceinclude() {
   file=$1
   perl -i -p -e 's+//REMOVEINCLUDE ++' $1
}

for file in $*
do
    includes=`grep "^[ \t]*#include" $file | awk '{print $2;}' | sed 's/[\"\<\>]//g'`
    echo $includes
    for i in $includes
    do
        touch $file # just to be sure it recompiles
        removeinclude $file $i
        if make -j8 >/dev/null  2>&1;
        then
            grep -v REMOVEINCLUDE $file > tmp && mv tmp $file
            echo removed $i from $file
        else
            replaceinclude $file
            echo $i was needed in $file
        fi
    done
done
