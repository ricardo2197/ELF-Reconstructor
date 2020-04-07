#ifndef DBGTRACE_HPP
#define DBGTRACE_HPP

#include <stdio.h>
#include <string.h> 

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

#if defined(DEBUG)
    #define ___DBG(m_, f_, ...) fprintf(stderr,   \
                        m_" %s:%03d:%s() - " f_ "\n",  \
                        __FILE__, __LINE__, __func__, ##__VA_ARGS__);

    #define DBGE(_f, ...) ___DBG(RED "[ ERROR ]" RESET, _f, ##__VA_ARGS__)
    #define DBGW(_f, ...) ___DBG(YEL "[WARNING]" RESET, _f, ##__VA_ARGS__)
    #define DBGI(_f, ...) ___DBG(BLU "[  INFO ]" RESET, _f, ##__VA_ARGS__)

#else

   #define ___DBG(m_, f_, ...) fprintf(stderr,   \
                        m_" - " f_ "\n",  \
                        ##__VA_ARGS__);

    #define DBGE(_f, ...) ___DBG(RED "[ ERROR ]" RESET, _f, ##__VA_ARGS__)
    #define DBGW(_f, ...) ___DBG(YEL "[WARNING]" RESET, _f, ##__VA_ARGS__)
    #define DBGI(_f, ...) ___DBG(BLU "[  INFO ]" RESET, _f, ##__VA_ARGS__)

#endif
#endif