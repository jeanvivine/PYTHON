#!/bin/bash
ps aux | awk {'print $2,$11'} > pid_process_name.txt

cat pid_process_name.txt | awk {'print $1'} | while read line
do
sha256sum /proc/$line/exe
done > hash.txt 2> /dev/null

sed -i -e 's/\/proc\///g' -e 's/\/exe//g' hash.txt

awk 'FNR==NR{a[$2]=$1;next}{if(a[$1]==""){a[$1]=0}; \
   print $1,$2,a[$1]}' hash.txt pid_process_name.txt | awk '$3 != 0' > fusionpid_hash_proc.txt

FILE=/root/Process_Hash.txt
if [ -f "$FILE" ]; then
    cat fusionpid_hash_proc.txt > Process_Hash_grey.txt
else
    cat fusionpid_hash_proc.txt > Process_Hash.txt
fi

rm -rf pid_process_name.txt hash.txt fusionpid_hash_proc.txt
