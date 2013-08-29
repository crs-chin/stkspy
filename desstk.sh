#!/bin/bash

# all radio log file names are assume like htclog naming and numbering
# style.

LOG_TAG=RILC

LOG_FILES=();
i=0;


if ! type -p stkspy > /dev/null;then
    echo "stkspy not available, bailing out...";
    exit -1;
fi

if [ $# -ne 0 ];then
    while [ "$1" != "" ];
    do
        LOG_FILES[$i]="$1";
        shift;
        ((i++));
    done
else
    for f in radio*.txt*;
    do
        if [ "$f" = "radio*.txt*" ];then
            echo "No radio log files found on current dir!";
            exit -1;
        fi

        LOG_FILES[$i]="$f";
        ((i++));
    done
fi

for (( x=0; ((x < i)); ((x++)) ));
do
    for (( y=((x + 1)); ((y < i)); ((y++)) ));
    do
        suffix1=${LOG_FILES[$x]##*.};
        suffix2=${LOG_FILES[$y]##*.};
        if [ $suffix1 = "txt" ];then
            tmp=${LOG_FILES[$y]};
            LOG_FILES[$y]=${LOG_FILES[$x]};
            LOG_FILES[$x]=$tmp;
        elif [ $suffix2 = "txt" ];then
            continue;
        elif ((suffix1 < suffix2));then
            tmp=${LOG_FILES[$y]};
            LOG_FILES[$y]=${LOG_FILES[$x]};
            LOG_FILES[$x]=$tmp;
        else
            continue;
        fi
    done
done

red="\033[0;31m"
green="\033[0;32m"

echo -e "${green}================= Parsing Radio Logs ==================="
for (( j=0; ((j < i)); ((j++)) ));
do
    echo ${LOG_FILES[$j]};
done
echo "========================================================"

for (( j=0; ((j < i)); ((j++)) ));
do
    grep "$LOG_TAG" "${LOG_FILES[$j]}"  | egrep "> STK_SEND_TERMINAL_RESPONSE|> STK_SEND_ENVELOPE_COMMAND|< UNSOL_STK_PROACTIVE_COMMAND" | egrep -o "\([0-9a-fA-F]*\)|\{[0-9a-fA-F]*\}" | egrep -o "[0-9a-fA-F]*" | while read x;
    do
        echo -e "Parsing ${red}$x${green}"
        stkspy "$x"
    done

done
