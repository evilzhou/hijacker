#include <jni.h>
#include "logger/logger.h"
#include "Substrate/SubstrateHook.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stack>

static const char base64_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '+', '/'};

static const unsigned char base64_suffix_map[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 255,
    255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
    255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
    19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
    37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255 };

static char cmove_bits(unsigned char src, unsigned lnum, unsigned rnum) {
    src <<= lnum; // src = src << lnum;
    src >>= rnum; // src = src >> rnum;
    return src;
}

extern "C" int base64_encode(const char *indata, int inlen, char *outdata, int *outlen) {
    
    int ret = 0; // return value
    if (indata == NULL || inlen == 0) {
        return ret = -1;
    }
    
    int in_len = 0; // 源字符串长度, 如果in_len不是3的倍数, 那么需要补成3的倍数
    int pad_num = 0; // 需要补齐的字符个数, 这样只有2, 1, 0(0的话不需要拼接, )
    if (inlen % 3 != 0) {
        pad_num = 3 - inlen % 3;
    }
    in_len = inlen + pad_num; // 拼接后的长度, 实际编码需要的长度(3的倍数)
    
    int out_len = in_len * 8 / 6; // 编码后的长度
    
    char *p = outdata; // 定义指针指向传出data的首地址
    
    //编码, 长度为调整后的长度, 3字节一组
    for (int i = 0; i < in_len; i+=3) {
        int value = *indata >> 2; // 将indata第一个字符向右移动2bit(丢弃2bit)
        char c = base64_alphabet[value]; // 对应base64转换表的字符
        *p = c; // 将对应字符(编码后字符)赋值给outdata第一字节
        
        //处理最后一组(最后3字节)的数据
        if (i == inlen + pad_num - 3 && pad_num != 0) {
            if(pad_num == 1) {
                *(p + 1) = base64_alphabet[(int)(cmove_bits(*indata, 6, 2) + cmove_bits(*(indata + 1), 0, 4))];
                *(p + 2) = base64_alphabet[(int)cmove_bits(*(indata + 1), 4, 2)];
                *(p + 3) = '=';
            } else if (pad_num == 2) { // 编码后的数据要补两个 '='
                *(p + 1) = base64_alphabet[(int)cmove_bits(*indata, 6, 2)];
                *(p + 2) = '=';
                *(p + 3) = '=';
            }
        } else { // 处理正常的3字节的数据
            *(p + 1) = base64_alphabet[cmove_bits(*indata, 6, 2) + cmove_bits(*(indata + 1), 0, 4)];
            *(p + 2) = base64_alphabet[cmove_bits(*(indata + 1), 4, 2) + cmove_bits(*(indata + 2), 0, 6)];
            *(p + 3) = base64_alphabet[*(indata + 2) & 0x3f];
        }
        
        p += 4;
        indata += 3;
    }
    
    if(outlen != NULL) {
        *outlen = out_len;
    }
    
    return ret;
}

int base64_decode(const char *indata, int inlen, char *outdata, int *outlen) {
    
    int ret = 0;
    if (indata == NULL || inlen <= 0 || outdata == NULL || outlen == NULL) {
        return ret = -1;
    }
    if (inlen % 4 != 0) { // 需要解码的数据不是4字节倍数
        return ret = -2;
    }
    
    int t = 0, x = 0, y = 0, i = 0;
    unsigned char c = 0;
    int g = 3;
    
    while (indata[x] != 0) {
        // 需要解码的数据对应的ASCII值对应base64_suffix_map的值
        c = base64_suffix_map[indata[x++]];
        if (c == 255) return -1;// 对应的值不在转码表中
        if (c == 253) continue;// 对应的值是换行或者回车
        if (c == 254) { c = 0; g--; }// 对应的值是'='
        t = (t<<6) | c; // 将其依次放入一个int型中占3字节
        if (++y == 4) {
            outdata[i++] = (unsigned char)((t>>16)&0xff);
            if (g > 1) outdata[i++] = (unsigned char)((t>>8)&0xff);
            if (g > 2) outdata[i++] = (unsigned char)(t&0xff);
            y = t = 0;
        }
    }
    if (outlen != NULL) {
        *outlen = i;
    }
    return ret;
}

static int (*old_base64_encode)(const char *indata, int inlen, char *outdata, int *outlen);
int my_base64_encode(const char *indata, int inlen, char *outdata, int *outlen)
{
    return base64_encode(indata, inlen, outdata, outlen);
}

struct ENV
{
    unsigned int R0;
    unsigned int R1;
    unsigned int R2;
    unsigned int R3;
    unsigned int R4;
    unsigned int R5;
    unsigned int R6;
    unsigned int R7;
    unsigned int R8;
    unsigned int R9;
    unsigned int R10;
    unsigned int R11;
    unsigned int IP;
    unsigned int SP;
    unsigned int LR;
    unsigned int PC;
};

extern "C" void __attribute__((naked)) trampoline_test()
{
	__asm__("mov r0, r0			    \t\n"
			"mov r0, r0			    \t\n"
			"mov r0, r0			    \t\n"
			"mov r0, r0			    \t\n"
			"push {r0-r14}			\t\n"
			"mov r0, sp				\t\n"
            "ldr r1, [pc, #-32]		\t\n"
            "ldr lr, [pc, #-32]		\t\n"
			"blx lr					\t\n"
			"pop {r0-r14}			\t\n"
			"ldr lr, [pc, #-36]     \t\n"
			"blx lr		            \t\n"
			"push {r0-r14}			\t\n"
			"mov r0, sp				\t\n"
			"ldr r1, [pc, #-64]		\t\n"
			"ldr lr, [pc, #-60]		\t\n"
			"blx lr					\t\n"
			"pop {r0-r14}			\t\n"
			"bx lr                  \t\n"
            "mov r0, r0"
			);
}

const char trampoline[] = {
0x00, 0x00, 0xA0, 0xE1, 0x00, 0x00, 0xA0, 0xE1,  0x00, 0x00, 0xA0, 0xE1, 0x00, 0x00, 0xA0, 0xE1,
0xFF, 0x7F, 0x2D, 0xE9, 0x0D, 0x00, 0xA0, 0xE1,  0x20, 0x10, 0x1F, 0xE5, 0x20, 0xE0, 0x1F, 0xE5,
0x3E, 0xFF, 0x2F, 0xE1, 0xFF, 0x7F, 0xBD, 0xE8,  0x24, 0xE0, 0x1F, 0xE5, 0x3E, 0xFF, 0x2F, 0xE1,
0xFF, 0x7F, 0x2D, 0xE9, 0x0D, 0x00, 0xA0, 0xE1,  0x40, 0x10, 0x1F, 0xE5, 0x3C, 0xE0, 0x1F, 0xE5,
0x3E, 0xFF, 0x2F, 0xE1, 0xFF, 0x7F, 0xBD, 0xE8,  0x1E, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0xA0, 0xE1};

static void* allocTrampoline()
{
    static void* allocedBuffer=nullptr;
    static int indexUsed=-1;
    if (allocedBuffer == nullptr)
    {
        indexUsed=-1;
        allocedBuffer = mmap(0, 1024*1024*4, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    }
    if (allocedBuffer != nullptr)
    {
        indexUsed++;
        void* addr = (void*)((unsigned int)allocedBuffer + indexUsed*80);
        memcpy(addr, trampoline, 80);
        return addr;
    }
}

static __thread int indexLR=-1;
static __thread unsigned int savedLR[1024]={0x00};

void precall(ENV *env, void* ud)
{
    indexLR++;
    savedLR[indexLR] = env->LR;
    LOGD("precall");
}

void postcall(ENV *env, void* ud)
{
    LOGD("postcall");
    env->LR = savedLR[indexLR];
    indexLR--;
}

extern "C" int main()
{
	int encodedSize=0;
	char encodeBuffer[256]={0x00};

	base64_encode("hello", 5, encodeBuffer, &encodedSize);
	LOGD("%s", encodeBuffer);

    unsigned int* addr = (unsigned int*)allocTrampoline();
    LOGD("addr %p", addr);

    getchar();

    MSHookFunction((void*)base64_encode, (void*)(addr+4), (void**)&old_base64_encode);

    const char testit[] = "testit";
    *addr = *(unsigned int*)testit;
    *(addr+1) = (unsigned int)precall;
    *(addr+2) = (unsigned int)postcall;
    *(addr+3) = (unsigned int)old_base64_encode;

    for (int i=0; i<5; i++)
    {
        base64_encode("hello", 5, encodeBuffer, &encodedSize);
	    LOGD("%s", encodeBuffer);
    }

	return 0;
}