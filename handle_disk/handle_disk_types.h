
#ifndef BYTE
#define BYTE	unsigned char
#endif

#ifndef WORD
#define WORD	unsigned short
#endif

#ifndef DWORD
#define DWORD	unsigned long
#endif

#ifndef INT
#define INT  int
#endif

#ifndef UCHAR
#define UCHAR  unsigned char
#endif

#ifndef ULONG
#define ULONG  unsigned long
#endif

#ifndef USHORT
#define USHORT	unsigned short
#endif

#ifndef LCN
#define LCN unsigned __int64
#endif

#ifndef BYTE
#define BYTE unsigned __int8
#endif



typedef union tag_QWORD
{
	BYTE ByPart[8];
	struct
	{
		DWORD dwLow;
		DWORD dwHigh;
	} DualPart;
	__int64 QuadPart;
}QWORD;

#ifndef NULL
#define NULL 0
#endif

#ifndef ERRCODE
#define ERRCODE unsigned short
#endif


