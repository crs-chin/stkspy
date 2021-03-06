#!/bin/bash
#
# STK raw data analyzer of Android radio log.
# Copyright (C) <2012>  Crs Chin<crs.chin@gmail.com>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.
#/

# all radio log file names are assume like htclog naming and numbering
# style.

LOG_TAG=RILC
DELIM=.
ASCEND="NO"
LOG_FILES=();
i=0;


if ! type -p stkspy > /dev/null;then
    echo "stkspy not available, bailing out...";
    exit -1;
fi

usage()
{
    echo "$0 [OPTIONS] [LOG_FILE_LIST]";
    echo "OPTIONS:";
    echo "    -t       log tag in log files[default:\"${LOG_TAG}\"]";
    echo "    -d       delimeter of log file index[default:\"${DELIM}\"]";
    echo "    -a       parse log file in ascending order[default:\"descending\"]";
    echo "if LOG_FILE_LIST not specified, \"radio\" prefixed files will be checked in current directory";
}


while [ -n "$1" ];
do
    if [ "$1" = "-t" ];then
        shift
        if [ -n "$1" ];then
            LOG_TAG="$1";
            shift
        else
            echo "-t requires a parameter of log tag";
            exit -1;
        fi
    elif [ "$1" = "-d" ];then
        shift
        if [ -n "$1" ];then
            DELIM="$1";
            shift
        else
            echo "-d requires a parameter of log tag";
            exit -1;
        fi
    elif [ "$1" = "-h" ];then
        usage;
        exit 0;
    elif [ "$1" = "-a" ];then
        ASCEND="YES";
        shift
    else
        break;
    fi
done


while [ "$1" != "" ];
do
    LOG_FILES[$i]="$1";
    shift;
    ((i++));
done

if [[ $i == 0 ]];then
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
        suffix1=${LOG_FILES[$x]##*${DELIM}};
        suffix2=${LOG_FILES[$y]##*${DELIM}};
        if [ "$ASCEND" = "YES" ];then
            if [ "$suffix2" = "txt" ];then
                tmp=${LOG_FILES[$y]};
                LOG_FILES[$y]=${LOG_FILES[$x]};
                LOG_FILES[$x]=$tmp;
            elif [ "$suffix1" = "txt" ];then
                continue;
            elif ((suffix1 > suffix2));then
                tmp=${LOG_FILES[$y]};
                LOG_FILES[$y]=${LOG_FILES[$x]};
                LOG_FILES[$x]=$tmp;
            else
                continue;
            fi
        else
            if [ "$suffix1" = "txt" ];then
                tmp=${LOG_FILES[$y]};
                LOG_FILES[$y]=${LOG_FILES[$x]};
                LOG_FILES[$x]=$tmp;
            elif [ "$suffix2" = "txt" ];then
                continue;
            elif ((suffix1 < suffix2));then
                tmp=${LOG_FILES[$y]};
                LOG_FILES[$y]=${LOG_FILES[$x]};
                LOG_FILES[$x]=$tmp;
            else
                continue;
            fi
        fi
    done
done

red="\033[0;31m"
green="\033[0;32m"
blue="\033[0;34m"
if [ ! -t 1 ];then
    red=""
    green=""
    blue=""
fi


if [[ $i == 0 ]];then
    echo "No log file to parse";
    exit 0;
fi

echo -e "${green}================= Parsing Radio Logs ==================="
echo "Parsing using LOG_TAG:\"${LOG_TAG}\", DELIM:\"${DELIM}\""
for (( j=0; ((j < i)); ((j++)) ));
do
    echo ${LOG_FILES[$j]};
done
echo "========================================================"

tmp=`tempfile`;
tmp1=`tempfile`;
tmp2=`tempfile`;
tmp3=`tempfile`;

for (( j=0; ((j < i)); ((j++)) ));
do
    idx_ts=0;
    idx_type=0;
    idx_data=0;
    raw_ts=();
    raw_type=();
    raw_data=();

    grep "$LOG_TAG" "${LOG_FILES[$j]}"  |
    egrep "> STK_SEND_TERMINAL_RESPONSE|> STK_SEND_ENVELOPE_COMMAND|< UNSOL_STK_PROACTIVE_COMMAND|< UNSOL_STK_EVENT_NOTIFY"  > "$tmp";

    egrep -o "STK_SEND_TERMINAL_RESPONSE|STK_SEND_ENVELOPE_COMMAND|UNSOL_STK_PROACTIVE_COMMAND|UNSOL_STK_EVENT_NOTIFY" "$tmp" > "$tmp1"
    while read x;
    do
        #echo "raw_type:$x, $idx_type";
        raw_type[$idx_type]="$x";
        ((idx_type++));
    done < "$tmp1"


    egrep -o "\([0-9a-fA-F]*\)|\{[0-9a-fA-F]*\}" "$tmp" | egrep -o "[0-9a-fA-F]*" > "$tmp2"
    while read x;
    do
        #echo "raw_data:$x, $idx_data";
        raw_data[$idx_data]="$x";
        ((idx_data++));
    done  < "$tmp2"

    egrep -o "^[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]" "$tmp" > "$tmp3";
    while read x;
    do
        #echo "raw_ts:$x, $idx_ts";
        raw_ts[$idx_ts]="$x";
        ((idx_ts++));
    done  < "$tmp3"

    if [[ $idx_ts != $idx_type || $idx_ts != $idx_data ]]; then
        echo "Error parsing ${LOG_FILES[$j]}, index mismatch";
        continue;
    fi

    if [[ $idx_ts > 0 ]];then
        for (( x=0; ((x < idx_ts)); ((x++)) ))
        do
            echo -e "${blue}${raw_ts[$x]}${green}:${red}${raw_type[$x]}${green}";
            stkspy "${raw_data[$x]}"
        done
    fi
done

rm "$tmp"
rm "$tmp1"
rm "$tmp2"
rm "$tmp3"

