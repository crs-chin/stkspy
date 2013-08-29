/*
 * Dessect STK PDU.
 * Copyright (C) <2012>  Crs Chin
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * A GSM 11.14 compliant implementation
 *
 * FIXME: expand to TS 31.111 compliant
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <malloc.h>
#include <iconv.h>
#include <getopt.h>

#define ARRAYSIZE(a)  (sizeof(a)/sizeof(a[0]))
#define RETURN_VAL_IF(val,exp)  do{if(exp) return val;}while(0)

#ifndef VERSION
#define VERSION  "0.1"
#endif

#define BER_TAG_UNKNOWN 0x0
#define BER_PROACTIVE_COMMAND_TAG  0xd0
#define BER_MENU_SELECTION_TAG  0xd3
#define BER_EVENT_DOWNLOAD_TAG  0xd6

#define ERR_OK          0
#define ERR_GENERIC     -1
#define ERR_MALFORMAT   -2

typedef struct _Tag Tag;
typedef struct _CompTlv CompTlv;
typedef void (*Dessector)(CompTlv *);

struct _Tag{
    char *name;
    int val;
    Dessector des;
};

struct _CompTlv{
    const Tag *tag;
    int cr;                     /* comprehention required */
    int len;
    char *val;
    CompTlv *nxt;
};

typedef struct _BerTlv{
    int tag;
    int len;                    /* binary len */
    char *txt;
    CompTlv *tlvs;
    CompTlv *end;
}BerTlv;


static void des_details(CompTlv *);
static void des_identities(CompTlv *);
static void des_result(CompTlv *);
static void des_duration(CompTlv *);
static void des_alpha_id(CompTlv *);
static void des_address(CompTlv *);
static void des_ussd_string(CompTlv *);
static void des_sms_tpdu(CompTlv *);
static void des_text_string(CompTlv *);
static void des_tone(CompTlv *);
static void des_item(CompTlv *);
static void des_item_id(CompTlv *);
static void des_response_length(CompTlv *);
static void des_file_list(CompTlv *);
static void des_help_request(CompTlv *);
static void des_default_test(CompTlv *);
static void des_event_list(CompTlv *);
static void des_icon_id(CompTlv *);
static void des_item_icon_id_list(CompTlv *);
static void des_immediate_response(CompTlv *);
static void des_language(CompTlv *);
static void des_url(CompTlv *);
static void des_browser_temination_cause(CompTlv *);
static void des_text_attribute(CompTlv *);
static void des_unknown(CompTlv *);

static const Tag g_tag[] = {
    {"COMMAND_DETAILS", 0x01, des_details},
    {"DEVICE_IDENTITIES", 0x02, des_identities},
    {"RESULT", 0x03, des_result},
    {"DURATION", 0x04, des_duration},
    {"ALPHA_ID", 0x05, des_alpha_id},
    {"ADDRESS", 0x06, des_address},
    {"USSD_STRING", 0x0a, des_ussd_string},
    {"SMS_TPDU", 0x0b, des_sms_tpdu},
    {"TEXT_STRING", 0x0d, des_text_string},
    {"TONE", 0x0e, des_tone},
    {"ITEM", 0x0f, des_item},
    {"ITEM_ID", 0x10, des_item_id},
    {"RESPONSE_LENGTH", 0x11, des_response_length},
    {"FILE_LIST", 0x12, des_file_list},
    {"HELP_REQUEST", 0x15, des_help_request},
    {"DEFAULT_TEXT", 0x17, des_default_test},
    {"EVENT_LIST", 0x19, des_event_list},
    {"ICON_ID", 0x1e, des_icon_id},
    {"ITEM_ICON_ID_LIST", 0x1f, des_item_icon_id_list},
    {"IMMEDIATE_RESPONSE", 0x2b, des_immediate_response},
    {"LANGUAGE", 0x2d, des_language},
    {"URL", 0x31, des_url},
    {"BROWSER_TERMINATION_CAUSE", 0x34, des_browser_temination_cause},
    {"TEXT_ATTRIBUTE", 0x50, des_text_attribute},
};


static inline CompTlv *new_tlv(void)
{
    return (CompTlv *)malloc(sizeof(CompTlv));
}

static inline void *memdup(const void *src, size_t len)
{
    void *dest = malloc(len);

    if(dest)
        memcpy(dest, src, len);
    return dest;
}


static int from_hex_char(char c)
{
    if(c >= '0' && c <= '9')
        return c - '0';
    if(c >= 'a' && c <= 'f')
        return 10 + c - 'a';
    if(c >= 'A' && c <= 'F')
        return 10 + c - 'A';
    return -1;
}

static char *from_hex_string(const char *str, int *len)
{
    const char *p;
    char *bin, *q;
    int l;

    if(! str || ! *str || ! len)
        return NULL;

    l = strlen(str) / 2;
    if(! l)
        return NULL;

    *len = l;
    bin = (char *)malloc(l);
    if(! bin)
        return NULL;

    for(p = str, q = bin; l; l--)  {
        *q++ = ((from_hex_char(*p) << 4) | from_hex_char(*(p + 1)));
        p += 2;
    }

    return bin;
}


static void hex_dump(char *_val, int len)
{
    unsigned char *val = _val;
    int i;

    for(i = 0; i < len;)  {
        if(! (i % 16))
            printf("\t%-.02X~%.02X  ", i, i + 15);

        if(! (i % 8) && (i % 16))
            printf("  ");

        switch(len - i)  {
        default:
            printf("%02X %02X %02X %02X ", val[i], val[i + 1], val[i + 2], val[i + 3]);
            i += 4;
            break;
        case 2:
        case 3:
            printf("%02X %02X ", val[i], val[i + 1]);
            i += 2;
            break;
        case 1:
            printf("%02X", val[i]);
            i += 1;
            break;
        }

        if(! (i % 16))
            printf("\n");
    }

    if(i % 16)
        printf("\n");
}


static char *to_utf8(char *text, int len, const char *coding)
{
    char *inbuf, *outbuf, *str;
    size_t in, sz, out, res;
    iconv_t ct;

    if(len < 0)
        in = strlen(text);
    else
        in = (size_t)len;
    sz = out = in;

    str = (char *)malloc(sz + 1);
    if(! str)
        return NULL;

    ct = iconv_open("UTF8", coding);
    if(ct == (iconv_t)-1)  {
        printf("Failed encoding convert from %s to UTF8\n", coding);
        free(str);
        return NULL;
    }

    for(inbuf = text, outbuf = str;;)  {
        res = iconv(ct, &inbuf, &in, &outbuf, &out);
        if(res == -1)  {
            if(errno == E2BIG)  {
                sz += in;
                out += in;
                str = (char *)realloc(str, sz + 1);
                if(! str)  {
                    printf("OOM converting encoding!\n");
                    break;
                }
                outbuf = str + sz - out;
                continue;
            }
        }
        break;
    }

    iconv_close(ct);
    str[sz - out] = '\0';
    return str;
}


static char *decode_ucs16be(unsigned char *txt, int len)
{
    unsigned short *ucs16 = (unsigned short *)txt;

    /* skipping ending 0xFFFF */
    for(len /= 2; len >= 1 && ucs16[len - 1] == 0xFFFF; len--);
    if(! len)
        return strdup("");
    return to_utf8((char *)ucs16, len * 2, "UTF16BE");
}


static const char *gsm_alphabet[] = {
    "@", "£", "$", "¥", "è", "é", "ù", "ì", "ò", "Ç", "\n", "Ø", "ø", "\r", "Å", "å", /* 0x00 */
    "Δ", "_", "Φ", "Γ", "Λ", "Ω", "Π", "Ψ", "Σ", "Θ", "Ξ", "\x1B", "Æ", "æ", "ß", "É", /* 0x10 */
    " ", "!", "\"", "#", "¤", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", /* 0x20 */
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?", /* 0x30 */
    "¡", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", /* 0x40 */
    "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "Ä", "Ö", "Ñ", "Ü", "§", /* 0x50 */
    "¿", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", /* 0x60 */
    "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "ä", "ö", "ñ", "ü", "à", /* 0x70 */
};

static const char *gsm_alphabet_ex[128] = {
    [0x0A] = "\n",
    [0x14] = "^",
    [0x28] = "{", [0x29] = "}", [0x2F] = "\\",
    [0x3C] = "[", [0x3D] = "~", [0x3E] = "]",
    [0x40] = "|",
    [0x60] = "€",
};

static char *decode_gsm8bit_unpacked(unsigned char *pdu, int len)
{
    char *str, *p;
    int esc, c, i, j, sz = len;

    str = (char *)malloc(sz + 1);
    if(! str)  {
        printf("OOM allocating str:%d!\n", sz + 1);
        return NULL;
    }

    for(esc = 0, i = 0, j = 0; j < len; j++)  {
        c = pdu[j] & 0x7F;
        if(c == 0x1B)  {
            esc = 1;
            continue;
        }

        if(i + 4 > sz)  {
            sz += (len / 2 ? : 4);
            p = (char *)realloc(str, sz + 1);
            if(! str)  {
                printf("OOM realloc str!\n");
                str[i] = '\0';
                return str;
            }
            str = p;
        }

        if(esc)  {
            /* fake a invalid escaped char as a space */
            if(! gsm_alphabet_ex[c])
                str[i++] = ' ';
            else  {
                strcpy(str + i, gsm_alphabet_ex[c]);
                i += strlen(gsm_alphabet_ex[c]);
            }
            esc = 0;
            continue;
        }

        strcpy(str + i, gsm_alphabet[c]);
        i += strlen(gsm_alphabet[c]);
    }

    str[i] = '\0';
    return str;
}


static char *decode_ucs2(char *pdu, char base, int len)
{
    char *ret, *tmp;
    size_t sz = len;
    int i, j, m;

    ret = (char *)malloc(sz + 1);
    if(! ret)  {
        printf("OOM alloc buffer!\n");
        return NULL;
    }

    for(i = 0, j = 0; i < len;)  {
        if(j == sz)  {
            sz += len;
            ret = (char *)realloc(ret, sz);
            if(! ret)  {
                printf("OOM enlarge buffer\n");
                break;
            }
        }

        if(pdu[i] < 0)
            ret[j++] = (char)(base + (pdu[i++] & 0x7F));

        for(m = i; m < len && pdu[m] >= 0; m++)
            ;

        tmp = decode_gsm8bit_unpacked(pdu + i, m - i);
        if(tmp)  {
            int l = strlen(tmp);

            if(l > sz - j)  {
                sz += l;
                ret = (char *)realloc(ret, sz);
                if(! ret)  {
                    printf("OOM enlarge buffer\n");
                    break;
                }
            }
            strcpy(ret + j, tmp);
            j += l;
            free(tmp);
        }
        i += m;
    }

    ret[j] = '\0';
    return ret;
}


static char *decode_adn(char *_pdu, int len)
{
    unsigned char *pdu = _pdu;
    int i = 0, l = 0, ucs2 = 0;
    char base = '\0';

    if(! len)
        return strdup("");

    if(len >= 1 && pdu[i] == 0x80)
        return decode_ucs16be(pdu + 1, len - 1);

    if(len >= 3 && pdu[i] == 0x81)  {
        l = pdu[i + 1] & 0xff;
        if(l > len - 3)
            l = len - 3;
        base = (char)((pdu[i + 2] & 0xff) << 7);
        i += 3;
        ucs2 = 1;
    }else if(len >= 4 && pdu[i] == 0x82)  {
        l = pdu[i + 1] & 0xff;
        if(l > len - 4)
            l = len - 4;
        base = (char)(((pdu[i + 2] & 0xff) << 8) | (pdu[i + 3] & 0xff));
        i += 4;
        ucs2 = 1;
    }

    if(ucs2)
        return decode_ucs2(pdu + i, base, len - i);

    return decode_gsm8bit_unpacked(pdu, len);
}


static void des_default(CompTlv *tlv)
{
    printf("\n");
    /* will alway dump hex string */
    //hex_dump(tlv->val, tlv->len);
}


static void des_details(CompTlv *tlv)
{
    unsigned int cmd, cmd_type, cmd_qual, i, qual_prt = 0;
    char *cmd_desc[5] = { [0 ... 4] = NULL };
    char *type;

    if(tlv->len != 3)  {
        printf("\n\tBad Command Detail PDU\n");
        return;
    }
    cmd = tlv->val[0] & 0xff;
    cmd_type = tlv->val[1] & 0xff;
    cmd_qual = tlv->val[2] & 0xff;
    switch(cmd_type)  {
    case 0x21:
        type = "DISPLAY_TEXT";
        cmd_desc[0] = (cmd_qual & 0x01) ? "high priority" : "normal priority";
        cmd_desc[1] = (cmd_qual & 0x80) ? "wait for user to clear message" : "clear message after a delay";
        break;
    case 0x22:
        type = "GET_INKEY";
        cmd_desc[0] = (cmd_qual & 0x01) ? "alphabet set" : "digits (0-9, *, # and +) only";
        cmd_desc[1] = (cmd_qual & 0x02) ? "UCS2 alphabet" : "SMS default alphabet";
        cmd_desc[2] = (cmd_qual & 0x80) ? "help information available" : "no help information available";
        break;
    case 0x23:
        type = "GET_INPUT";
        cmd_desc[0] = (cmd_qual & 0x01) ? "alphabet set" : "digits (0-9, *, # and +) only";
        cmd_desc[1] = (cmd_qual & 0x02) ? "UCS2 alphabet" : "SMS default alphabet";
        cmd_desc[2] = (cmd_qual & 0x04) ? "user input shall not be revealed in any way" : "ME may echo user input on the display";
        cmd_desc[3] = (cmd_qual & 0x08) ? "user input to be in SMS packed format" : "user input to be in unpacked format";
        cmd_desc[4] = (cmd_qual & 0x80) ? "help information available" : "no help information available";
        break;
    case 0x15:
        type = "LAUNCH_BROWSER";
        break;
    case 0x20:
        type = "PLAY_TONE";
        break;
    case 0x01:
        type = "REFRESH";
        switch(cmd_qual)  {
        case 0x00:
            cmd_desc[0] = "SIM Initialization and Full File Change Notification";
            break;
        case 0x01:
            cmd_desc[0] = "File Change Notification";
            break;
        case 0x02:
            cmd_desc[0] = "SIM Initialization and File Change Notification";
            break;
        case 0x03:
            cmd_desc[0] = "SIM Initialization";
            break;
        case 0x04:
            cmd_desc[0] = "SIM Reset";
            break;
        case 0x05 ... 0xFF:
            cmd_desc[0] = "Reserved value";
            break;
        }
        break;
    case 0x24:
        type = "SELECT_ITEM";
        cmd_desc[0] = (cmd_qual & 0x80) ? "help information available" : "no help information available";
        break;
    case 0x11:
        type = "SEND_SS";
        break;
    case 0x12:
        type = "SEND_USSD";
        break;
    case 0x13:
        type = "SEND_SMS";
        cmd_desc[0] = (cmd_qual & 0x01) ? "SMS packing by the ME required" : "packing not required";
        break;
    case 0x14:
        type = "SEND_DTMF";
        break;
    case 0x05:
        type = "SET_UP_EVENT_LIST";
        break;
    case 0x28:
        type = "SET_UP_IDLE_MODE_TEXT";
        break;
    case 0x25:
        type = "SET_UP_MENU";
        cmd_desc[0] = (cmd_qual & 0x80) ? "help information available" : "no help information available";
        break;
    case 0x10:
        type = "SET_UP_CALL";
        switch(cmd_qual)  {
        case 0x00:
            cmd_desc[0] = "setup call only if not currently busy on another call";
            break;
        case 0x01:
            cmd_desc[0] = "setup call only if not currently busy on another call, with redial";
            break;
        case 0x02:
            cmd_desc[0] = "setup call, putting all other calls (if any) on hold";
            break;
        case 0x03:
            cmd_desc[0] = "setup call, putting all other calls (if any) on hold, with redial";
            break;
        case 0x04:
            cmd_desc[0] = "setup call, disconnecting all other calls (if any)";
            break;
        case 0x05:
            cmd_desc[0] = "setup call, disconnecting all other calls (if any), with redial";
            break;
        case 0x06 ... 0xFF:
            cmd_desc[0] = "Reserved value";
            break;
        }
        break;
    case 0x26:
        type = "PROVIDE_LOCAL_INFORMATION";
        switch(cmd_qual)  {
        case 0x00:
            cmd_desc[0] = "Location Information (MCC, MNC, LAC and Cell Identity)";
            break;
        case 0x01:
            cmd_desc[0] = "IMEI of the ME";
            break;
        case 0x02:
            cmd_desc[0] = "Network Measurement Results";
            break;
        case 0x03 ... 0xFF:
            cmd_desc[0] = "Reserved";
            break;
        }
        break;
    case 0x40:
        type = "OPEN_CHANNEL";
        break;
    case 0x41:
        type = "CLOSE_CHANNEL";
        break;
    case 0x42:
        type = "RECEIVE_DATA";
        break;
    case 0x43:
        type = "SEND_DATA";
        break;
    default:
        type = "UNKNOWN";
        break;
    }

    printf("\n\t%s(0x%X):\n", type, cmd_type);
    printf("\tCommand Number:0x%X\n", cmd);
    for(i = 0; i < 5; i++)  {
        if(cmd_desc[i])  {
            if(! qual_prt)  {
                qual_prt = 1;
                printf("\tCommand Qualifier(0x%X):\n", cmd_qual);
            }
            printf("\t\t%s\n", cmd_desc[i]);
        }
    }
}


static void des_identities(CompTlv *tlv)
{
    int src_id, dest_id;
    const char *str;

    if(tlv->len != 2)  {
        printf("\n\tBad Identities PDU\n");
        return;
    }

    src_id = tlv->val[0] & 0xff;
    dest_id = tlv->val[1] & 0xff;

    switch(src_id)  {
    case 0x01:
        str = "KEYPAD";
        break;
    case 0x02:
        str = "DISPLAY";
        break;
    case 0x03:
        str = "EARPIECE";
        break;
    case 0x81:
        str = "UICC";
        break;
    case 0x82:
        str = "TERMINAL";
        break;
    case 0x83:
        str = "NETWORK";
        break;
    default:
        str = "<UNKNOWN>";
        break;
    }
    printf("\n\tSource: %s(0x%X)\n", str, src_id);

    switch(dest_id)  {
    case 0x01:
        str = "KEYPAD";
        break;
    case 0x02:
        str = "DISPLAY";
        break;
    case 0x03:
        str = "EARPIECE";
        break;
    case 0x81:
        str = "UICC";
        break;
    case 0x82:
        str = "TERMINAL";
        break;
    case 0x83:
        str = "NETWORK";
        break;
    default:
        str = "<UNKNOWN>";
        break;
    }
    printf("\tDestination: %s(0x%X)\n", str, dest_id);
}

/* using more readable description */
#if 1
static const char *string_result(unsigned int code)
{
    switch(code)  {
    /*
     * Results '0X' and '1X' indicate that the command has been
     * performed.
     */
    /** Command performed successfully */
    case 0x00:
        return "Command performed successfully";
    case 0x01:
        return "Command performed with partial comprehension";
    case 0x02:
        return "Command performed, with missing information";
    case 0x03:
        return "REFRESH performed with additional EFs read";
    /*
     * Command performed successfully, but requested icon could not be
     * displayed
     */
    case 0x04:
        return "Command performed successfully, but requested icon could not be displayed";
    case 0x05:
        return "Command performed, but modified by call control by USIM";
    case 0x06:
        return "Command performed successfully, limited service";
    case 0x07:
        return "Command performed with modification";
    case 0x08:
        return "REFRESH performed but indicated USIM was not active";
    case 0x10:
        return "Proactive UICC session terminated by the user";
    case 0x11:
        return "Backward move in the proactive UICC session requested by the user";
    case 0x12:
        return "No response from user";
    case 0x13:
        return "Help information required by the user";
    case 0x14:
        return "USSD or SS transaction terminated by the user";
    /*
     * Results '2X' indicate to the UICC that it may be worth re-trying the
     * command at a later opportunity.
     */
    case 0x20:
        return "ME currently unable to process command";
    case 0x21:
        return "Network currently unable to process command";
    case 0x22:
        return "User did not accept the proactive command";
    case 0x23:
        return "User cleared down call before connection or network release";
    case 0x24:
        return "Action in contradiction with the current timer state";
    case 0x25:
        return "Interaction with call control by USIM, temporary problem";
    case 0x26:
        return "Launch browser generic error code";
    /*
     *  results '2X' indicate to the UICC that it may be worth
     *  re-trying the command at a later opportunity
     */
    case 0x30:
        return "Command beyond ME's capabilities";
    case 0x31:
        return "Command type not understood by ME";
    case 0x32:
        return "Command data not understood by ME";
    case 0x33:
        return "Command number not known by ME";
    case 0x34:
        return "SS Return Error";
    case 0x35:
        return "SMS RP-ERROR";
    case 0x36:
        return "Error, required values are missing";
    case 0x37:
        return "USSD Return Error";
    case 0x38:
        return "MultipleCard commands error";
    case 0x39:
        return "Interaction with call control by USIM or MO short message control by USIM, permanent problem";
    case 0x3A:
        return "Bearer Independent Protocol error";
    default:
        return "<Unknown Code>";
    }
}

#else

static const char *string_result(unsigned int code)
{
    switch(code)  {
    /*
     * Results '0X' and '1X' indicate that the command has been performed.
     */

    /** Command performed successfully */
    case 0x00:
        return "OK";

    /** Command performed with partial comprehension */
    case 0x01:
        return "PRFRMD_WITH_PARTIAL_COMPREHENSION";

    /** Command performed, with missing information */
    case 0x02:
        return "PRFRMD_WITH_MISSING_INFO";

    /** REFRESH performed with additional EFs read */
    case 0x03:
        return "PRFRMD_WITH_ADDITIONAL_EFS_READ";

    /**
     * Command performed successfully, but requested icon could not be
     * displayed
     */
    case 0x04:
        return "PRFRMD_ICON_NOT_DISPLAYED";

    /** Command performed, but modified by call control by NAA */
    case 0x05:
        return "PRFRMD_MODIFIED_BY_NAA";

    /** Command performed successfully, limited service */
    case 0x06:
        return "PRFRMD_LIMITED_SERVICE";

    /** Command performed with modification */
    case 0x07:
        return "PRFRMD_WITH_MODIFICATION";

    /** REFRESH performed but indicated NAA was not active */
    case 0x08:
        return "PRFRMD_NAA_NOT_ACTIVE";

    /** Command performed successfully, tone not played */
    case 0x09:
        return "PRFRMD_TONE_NOT_PLAYED";

    /** Proactive UICC session terminated by the user */
    case 0x10:
        return "UICC_SESSION_TERM_BY_USER";

    /** Backward move in the proactive UICC session requested by the user */
    case 0x11:
        return "BACKWARD_MOVE_BY_USER";

    /** No response from user */
    case 0x12:
        return "NO_RESPONSE_FROM_USER";

    /** Help information required by the user */
    case 0x13:
        return "HELP_INFO_REQUIRED";

    /** USSD or SS transaction terminated by the user */
    case 0x14:
        return "USSD_SS_SESSION_TERM_BY_USER";


    /*
     * Results '2X' indicate to the UICC that it may be worth re-trying the
     * command at a later opportunity.
     */

    /** Terminal currently unable to process command */
    case 0x20:
        return "TERMINAL_CRNTLY_UNABLE_TO_PROCESS";

    /** Network currently unable to process command */
    case 0x21:
        return "NETWORK_CRNTLY_UNABLE_TO_PROCESS";

    /** User did not accept the proactive command */
    case 0x22:
        return "USER_NOT_ACCEPT";

    /** User cleared down call before connection or network release */
    case 0x23:
        return "USER_CLEAR_DOWN_CALL";

    /** Action in contradiction with the current timer state */
    case 0x24:
        return "CONTRADICTION_WITH_TIMER";

    /** Interaction with call control by NAA, temporary problem */
    case 0x25:
        return "NAA_CALL_CONTROL_TEMPORARY";

    /** Launch browser generic error code */
    case 0x26:
        return "LAUNCH_BROWSER_ERROR";

    /** MMS temporary problem. */
    case 0x27:
        return "MMS_TEMPORARY";


    /*
     * Results '3X' indicate that it is not worth the UICC re-trying with an
     * identical command, as it will only get the same response. However, the
     * decision to retry lies with the application.
     */

    /** Command beyond terminal's capabilities */
    case 0x30:
        return "BEYOND_TERMINAL_CAPABILITY";

    /** Command type not understood by terminal */
    case 0x31:
        return "CMD_TYPE_NOT_UNDERSTOOD";

    /** Command data not understood by terminal */
    case 0x32:
        return "CMD_DATA_NOT_UNDERSTOOD";

    /** Command number not known by terminal */
    case 0x33:
        return "CMD_NUM_NOT_KNOWN";

    /** SS Return Error */
    case 0x34:
        return "SS_RETURN_ERROR";

    /** SMS RP-ERROR */
    case 0x35:
        return "SMS_RP_ERROR";

    /** Error, required values are missing */
    case 0x36:
        return "REQUIRED_VALUES_MISSING";

    /** USSD Return Error */
    case 0x37:
        return "USSD_RETURN_ERROR";

    /** MultipleCard commands error */
    case 0x38:
        return "MULTI_CARDS_CMD_ERROR";

    /**
     * Interaction with call control by USIM or MO short message control by
     * USIM, permanent problem
     */
    case 0x39:
        return "USIM_CALL_CONTROL_PERMANENT";

    /** Bearer Independent Protocol error */
    case 0x3a:
        return "BIP_ERROR";

    /** Access Technology unable to process command */
    case 0x3b:
        return "ACCESS_TECH_UNABLE_TO_PROCESS";

    /** Frames error */
    case 0x3c:
        return "FRAMES_ERROR";

    /** MMS Error */
    case 0x3d:
        return "MMS_ERROR";
    default:
        return "UNKNOWN_CODE";
    }
}

#endif

/* FIXME: extra info parsing */
static void des_result(CompTlv *tlv)
{
    if(tlv->len == 2)  {
        printf("\n\tResult: %s(0x%X)", string_result(tlv->val[0]), tlv->val[0]);
        printf("\n\tInfo: 0x%X\n", tlv->val[1]);
    }else if(tlv->len == 1)  {
        printf("\n\tResult: %s(0x%X)\n", string_result(tlv->val[0]), tlv->val[0]);
    }else  {
        printf("\n\t<Empty Result>\n");
    }
}


static void des_duration(CompTlv *tlv)
{
    int val, unit;
    const char *str;

    if(tlv->len != 2)  {
        printf("\n\t<Invalid Time Duration Tlv>\n");
        if(tlv->len)
            hex_dump(tlv->val, tlv->len);
    }else  {
        unit = tlv->val[0] & 0xff;
        val = tlv->val[1] & 0xff;

        switch(unit)  {
        case 0x00:
            str = "Minute(s)";
            break;
        case 0x01:
            str = "Second(s)";
            break;
        case 0x02:
            str = "* 10 Second(s)";
            break;
        default:
            str = "<Uknown Unit>";
            break;
        }
        printf("\n\tTime: %d %s\n", val, str);
    }
}


static void des_alpha_id(CompTlv *tlv)
{
    char *str;

    if(! tlv->len)  {
        printf("\n\tAlpha ID:Default Message\n");
        return;
    }

    str = decode_adn(tlv->val, tlv->len);
    if(str)
        printf("\n\tAlpha ID:%s\n", str);
    else  {
        printf("\n\t<Unable to decode>");
        des_default(tlv);
    }
}


static void des_address(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_ussd_string(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_sms_tpdu(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_text_string(CompTlv *tlv)
{
    unsigned char coding;
    char *txt;

    if(tlv->len)  {
        coding = tlv->val[0] & 0x0C;
        if(coding == 0x00)  {
            printf("\n\tCoding Scheme: GSM 7-bit Packed\n");
            hex_dump(tlv->val + 1, tlv->len - 1);
        }else if(coding == 0x04)  {
            printf("\n\tCoding Scheme: GSM 8-bit Unpacked\n");
            hex_dump(tlv->val + 1, tlv->len - 1);
        } else if(coding == 0x08)  {
            printf("\n\tCoding Scheme: UCS2(UTF-16BE)");
            txt = to_utf8(tlv->val + 1, tlv->len - 1, "UTF16BE");
            if(txt)  {
                printf("\n\tText: %s\n", txt);
                free(txt);
            }else  {
                printf("\n\tText: <Fail to decode>\n", txt);
                if(tlv->len - 1 > 0)
                    hex_dump(tlv->val + 1, tlv->len - 1);
            }
        }
    }else  {
        printf("\n\t<Empty Text>\n");
    }
}


static void des_tone(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_item(CompTlv *tlv)
{
    int id;
    char *txt;

    if(tlv->len)  {
        id = tlv->val[0] & 0xff;
        txt = decode_adn(tlv->val + 1, tlv->len - 1);

        printf("\n\tItem ID:0x%x", id);
        if(txt)  {
            printf("\n\tItem Text:%s\n", txt);
            free(txt);
        }else  {
            printf("\n\tItem Text:\n");
            hex_dump(tlv->val + 1, tlv->len - 1);
        }
    }else  {
        printf("\n\t<Null Item>\n");
    }
}


static void des_item_id(CompTlv *tlv)
{
    if(tlv->len != 1)  {
        printf("\n\tBad Item ID\n");
        return;
    }

    printf("\n\tItem ID:0x%X\n", tlv->val[0]);
}


static void des_response_length(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_file_list(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_help_request(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_default_test(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_event_list(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_icon_id(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_item_icon_id_list(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_immediate_response(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_language(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_url(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_browser_temination_cause(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_text_attribute(CompTlv *tlv)
{
    des_default(tlv);
}


static void des_unknown(CompTlv *tlv)
{
    des_default(tlv);
}

static const Tag *find_tag(int tag)
{
    const Tag *t;
    int i;

    for(i = 0, t = g_tag; i < ARRAYSIZE(g_tag); i++, t++)  {
        if(t->val == tag)
            return t;
    }

    return NULL;
}


static CompTlv *decode_tlv(const char *pdu, int *eatup, int length)
{
    CompTlv *tlv = NULL;
    int i = 0, tag, cr, len;

    tag = pdu[i++] & 0xff;
    switch(tag)  {
    case 0:
    case 0xff:
    case 0x80:
        printf("Unexpected tlv tag:0x%x\n", tag);
        return NULL;
    case 0x7f:
        RETURN_VAL_IF(NULL, i + 2 > length);

        tag = ((pdu[i] & 0xff) << 8) | (pdu[i + 1] & 0xff);
        cr = (tag & 0x8000) != 0;
        i += 2;
        break;
    default:
        cr = (tag & 0x80) != 0;
        tag &= ~0x80;
        break;
    }

    RETURN_VAL_IF(NULL, i + 1 > length);

    len = pdu[i++] & 0xff;
    if(len == 0x81)  {
        RETURN_VAL_IF(NULL, i + 1 > length);

        len = pdu[i++] & 0xff;
        if(len < 0x80)  {
            printf("Unexpected tlv len:0x%x\n", len);
            return NULL;
        }
    }else if(len == 0x82)  {
        RETURN_VAL_IF(NULL, i + 2 > length);

        len = ((pdu[i] & 0xff) << 8) | (pdu[i + 1] & 0xff);
        i += 2;
        if(len < 0x100)  {
            printf("Unexpected tlv len:0x%x\n", len);
            return NULL;
        }
    }else if(len == 0x83)  {
        RETURN_VAL_IF(NULL, i + 3 > length);

        len = ((pdu[i] & 0xff) << 16)
            | ((pdu[i + 1] & 0xff) << 8)
            | (pdu[i + 2] & 0xff);
        i += 3;
        if(len < 0x10000)  {
            printf("Unexpected tlv len:0x%x\n", len);
            return NULL;
        }
    }else if(len >= 0x80)  {
        printf("Unexpected tlv len:0x%x\n", len);
        return NULL;
    }

    RETURN_VAL_IF(NULL, i + len > length);

    tlv = new_tlv();
    if(tlv)  {
        tlv->cr = cr;
        tlv->len = len;
        tlv->nxt = NULL;

        tlv->tag = find_tag(tag);
        if(! tlv->tag)  {
            Tag *t = (Tag *)malloc(sizeof(Tag));
            if(! t)  {
                free(tlv);
                tlv = NULL;
            }else  {
                t->name = "<UNKNOWN>";
                t->val = tag;
                t->des = des_unknown;
                tlv->tag = t;
                tlv->val = memdup(pdu + i, len);
            }
        }else  {
            tlv->val = memdup(pdu + i, len);
        }
    }

    *eatup = i + len;
    return tlv;
}


static void decode_tlvs(BerTlv *bt, const char *pdu, int len)
{
    CompTlv *tlv;
    int i, eatup;

    for(i = 0; i < len;)  {
        tlv = decode_tlv(pdu + i, &eatup, len);
        if(! tlv)
            break;
        i += eatup;
        if(! bt->tlvs)
            bt->tlvs = tlv;
        if(bt->end)
            bt->end->nxt = tlv;
        bt->end = tlv;
    }
}


static int decode(BerTlv *bt, const char *pdu_txt)
{
    int tag, tag_len, i = 0, len = 0;
    char *raw = from_hex_string(pdu_txt, &len);

    if(! raw)
        return ERR_GENERIC;

    bt->txt = strdup(pdu_txt);
    if(! bt->txt)  {
        free(raw);
        return ERR_GENERIC;
    }

    tag = raw[i++] & 0xff;
    if(tag == BER_PROACTIVE_COMMAND_TAG
       || tag == BER_MENU_SELECTION_TAG
       || tag == BER_EVENT_DOWNLOAD_TAG)  {
        if(len <= 3)  {
            free(raw);
            return ERR_MALFORMAT;
        }

        tag_len = raw[i++] & 0xff;
        if(tag_len == 0x81)  {
            tag_len = raw[i++] & 0xff;
            if(tag_len < 0x80)  {
                free(raw);
                return ERR_MALFORMAT;
            }
        }else if(tag_len >= 0x80)  {
            free(raw);
            return ERR_MALFORMAT;
        }else if(tag_len == 0x00)  {
            i++;
        }
    }else  {
        tag = BER_TAG_UNKNOWN;
    }

    bt->tag = tag;
    bt->len = len;
    bt->tlvs = NULL;
    bt->end = NULL;

    if(tag == BER_TAG_UNKNOWN)
        decode_tlvs(bt, raw, len);
    else
        decode_tlvs(bt, &raw[i], len - i);

    free(raw);
    return ERR_OK;
}


static void free_bertlv(BerTlv *bt)
{
    CompTlv *tlv, *prev;

    free(bt->txt);
    for(prev = NULL, tlv = bt->tlvs; tlv; tlv = tlv->nxt)  {
        if(! strcmp(tlv->tag->name, "<UNKNOWN>"))
            free((void *)tlv->tag);

        free(tlv->val);
        if(prev)
            free(prev);
        prev = tlv;
    }

    if(prev)
        free(prev);
}


static void dump_bertlv(BerTlv *bt)
{
    CompTlv *tlv;
    const char *tag_str = "BER_TAG_UNKNOWN";

    printf("DECODING:%s\n", bt->txt ? : "<NULL>");
    switch(bt->tag)  {
    case BER_PROACTIVE_COMMAND_TAG:
        tag_str = "PROACTIVE_COMMAND";
        break;
    case BER_MENU_SELECTION_TAG:
        tag_str = "MENU_SELECTION";
        break;
    case BER_EVENT_DOWNLOAD_TAG:
        tag_str = "EVENT_DOWNLOAD";
        break;
    default:
        break;
    }

    printf("%s(0x%X:%d):\n", tag_str, bt->tag, bt->len);

    if(! bt->tlvs)  {
        printf("<No Tlv or any parsed>\n");
        return;
    }

    printf("============= Dumping Tlv Begin ==================\n");
    for(tlv = bt->tlvs; tlv; tlv = tlv->nxt)  {
        printf("%s%s%s%s(0x%X:%d):", 
               tlv->tag->name,
               tlv->cr ? "[" : "",
               tlv->cr ? "CR" : "",
               tlv->cr ? "]" : "",
               tlv->tag->val,
               tlv->len);
        tlv->tag->des(tlv);
        hex_dump(tlv->val, tlv->len);
    }
    printf("============== Dumping Tlv End ===================\n");
}


static inline void usage(const char *prg)
{
    printf("%s [OPTIONS] STK_PDU1 STK_PDU2\n", prg);
    printf("OPTIONS:\n"
           "-h|--help           show this message\n"
           "-v|--version        version info\n"
           "NOTE:\n"
           "  GSM 11.14 compliant\n"
           "  But still many tag dessectors not implemented\n");
}

static inline void version(void)
{
    printf("stkspy version %s\n", VERSION);
}


int main(int argc, char *argv[])
{
    BerTlv bt;
    int i, c, idx;

    for(;;)  {
        static struct option opts[] = {
            {"help", 0, NULL, 'h'},
            {"version", 0, NULL, 'v'},
            {NULL, 0, NULL, 0}
        };

        c = getopt_long(argc, argv, "hv", opts, &idx);
        if(-1 == c)
            break;

        switch(c)  {
        case 'h':
            usage(argv[0]);
            exit(0);
        case 'v':
            version();
            exit(0);
        default:
            usage(argv[0]);
            exit(-1);
            break;
        }
    }

    if(optind >= argc)  {
        printf("STK PDU list expected!\n");
        usage(argv[0]);
        exit(-1);
    }

    for(i = optind; i < argc; i++)  {
        if(ERR_OK == decode(&bt, argv[i]))  {
            dump_bertlv(&bt);
            if(i + 1 < argc)
                printf("\n\n");
            free_bertlv(&bt);
        }
    }

    return 0;
}

