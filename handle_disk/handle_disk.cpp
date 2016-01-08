#include <stdio.h>
#include <winsock2.h> 

#include "handle_disk_types.h"
#include "handle_disk_const.h"
#include "handle_disk_struct.h"


#pragma comment(lib, "ws2_32") 

/*全局变量*/
unsigned __int64 g_ll_file_size		= 0;
dbr_list_t* g_dbr_list_head			= NULL;
int g_n_dbr							= 0;
int g_n_part						= 0;
int g_n_page						= 0;



/*64位转大端模式*/
#define INT64_TO_NET(val)   ((__int64) ( \
	(((__int64) (val) &                  \
	(__int64) (0x00000000000000ffU)) << 56) | \
	(((__int64) (val) &                       \
	(__int64) (0x000000000000ff00U)) << 40) | \
	(((__int64) (val) &                       \
	(__int64) (0x0000000000ff0000U)) << 24) | \
	(((__int64) (val) &                       \
	(__int64) (0x00000000ff000000U)) <<  8) | \
	(((__int64) (val) &                       \
	(__int64) (0x000000ff00000000U)) >>  8) | \
	(((__int64) (val) &                       \
	(__int64) (0x0000ff0000000000U)) >> 24) | \
	(((__int64) (val) &                       \
	(__int64) (0x00ff000000000000U)) >> 40) | \
	(((__int64) (val) &                       \
	(__int64) (0xff00000000000000U)) >> 56)));


void ErrorOut(char* buf)
{            
	printf("%s Error Code:%d\n", buf, GetLastError());
	exit (0);
}


// 创建一个空链表 用来存储需要重构的信息
dbr_list_t *CreateDBRHead()
{
	dbr_list_t *pTemp = NULL;
	pTemp = (dbr_list_t*)malloc(sizeof(dbr_list_t));
	if(NULL == pTemp)    
	{
		ErrorOut("Malloc Error!");
		return NULL;
	}
	else
	{ 
		// 初始化链表 返回p
		pTemp->p_next	= NULL;
		pTemp->dbr		= NULL;
		pTemp->n_type	= 0;
		pTemp->ll_offset= 0;
		pTemp->flag		= 0;
		pTemp->ll_start_sector = 0;
		pTemp->ll_total_sector = 0;
		pTemp->n_is_org = 0;
		return(pTemp);
	}
}


// 往dbrList中插入一个元素
int InsertDBRList(dbr_list_t* p_dbr_head, char* sz_data, int n_type,__int64 i, LCN ll_offset) 
{  
	int j = 0;  

	dbr_list_t *pTemp	= NULL;   // 临时指针
	dbr_list_t *s		= NULL;   

	pTemp = p_dbr_head;  
	while(pTemp != NULL&& j < i)    // 插入到头结点的下一个节点
	{   
		if (!memcmp(pTemp->p_next->dbr, sz_data, 512))
		{
			free(sz_data);
			return 0;
		}
		pTemp = pTemp->p_next;   
		j++;    
	}  

	if (pTemp == NULL) 
	{
		ErrorOut("Insert dbrList Error!");
	}

	s = (dbr_list_t *)malloc(sizeof(dbr_list_t)); 
	memset(s, 0, sizeof(dbr_list_t));

	if(NULL == s) 
	{
		ErrorOut("Insert dbrList Error!");
	}
	else
	{ 
		s->dbr			= sz_data;
		s->n_type		= n_type;
		s->ll_offset	= ll_offset;
		s->p_next		= pTemp->p_next; 
		s->ll_start_sector = 0;
		s->ll_total_sector = 0;
		s->flag			   = 0;
		s->n_is_org		   = 0;
		pTemp->p_next = s; 
		g_n_dbr++;
		return 1;
	} 
	return 0;
}

// 销毁dbrList链表
void FreeDBRList(dbr_list_t* &List)
{
	dbr_list_t* pTemp;

	while(List)
	{
		pTemp = (List)->p_next;
		free(List);
		List = pTemp;
	}
}



// 创建一个空链表 用来存储需要重构的信息
rebuild_content_t *CreateReBuildHead()
{
	rebuild_content_t *pTemp = NULL;
	pTemp = (rebuild_content_t*)malloc(sizeof(rebuild_content_t));
	if(NULL == pTemp)    
	{
		ErrorOut("Malloc Error!");
		return NULL;
	}
	else
	{ 
		// 初始化链表 返回p
		pTemp->p_next	= NULL;
		pTemp->content	= NULL;
		pTemp->ll_offset= 0;
		pTemp->n_size	= 0;
		return(pTemp);
	}
}


// 往dbrList中插入一个元素
int InsertRebuildList(rebuild_content_t* p_rebuild_head, char* sz_data, int n_size, LCN ll_offset, __int64 i) 
{  
	int j = 0;  

	rebuild_content_t *pTemp	= NULL;   // 临时指针
	rebuild_content_t *s		= NULL;   

	pTemp = p_rebuild_head;  
	while(pTemp != NULL&& j < i)    // 插入到头结点的下一个节点
	{   
		pTemp = pTemp->p_next;   
		j++;    
	}  

	if (pTemp == NULL) 
	{
		ErrorOut("Insert dbrList Error!");
	}

	s = (rebuild_content_t *)malloc(sizeof(rebuild_content_t)); 
	memset(s, 0, sizeof(rebuild_content_t));

	if(NULL == s) 
	{
		ErrorOut("Insert rebuild_content_t Error!");
	}
	else
	{ 
		s->content		= sz_data;
		s->n_size		= n_size;
		s->ll_offset	= ll_offset;
		s->p_next		= pTemp->p_next; 
		pTemp->p_next = s; 
		return 1;
	} 
	return 0;
}

// 销毁dbrList链表
void FreeRebuildList(rebuild_content_t* &List)
{
	rebuild_content_t* pTemp;

	while(List)
	{
		pTemp = (List)->p_next;
		free(List);
		List = pTemp;
	}
}


/*得到文件大小*/
__int64 ToGetFileSize(char* pFile)
{
	DWORD	dwFileSizeHigh	= 0;
	long	filesize		= 0;
	__int64 nFileSize		= 0;

	HANDLE hFile = CreateFileA((LPCSTR)pFile, 
		GENERIC_READ,               
		FILE_SHARE_READ,
		NULL, 
		OPEN_EXISTING, 
		FILE_FLAG_SEQUENTIAL_SCAN, 
		NULL);

	if ( hFile == INVALID_HANDLE_VALUE)
	{                 
		ErrorOut("CreateFile Error!");
	}

	nFileSize = GetFileSize(hFile, &dwFileSizeHigh);
	nFileSize += (((__int64) dwFileSizeHigh) << 32);

	CloseHandle(hFile);
	return nFileSize;
}


int test_FAT(const fat_boot_sector* fat_header, LCN l_size)
{
	if(!(fat_header->marker==0xAA55
		&& (fat_header->ignored[0]==0xeb || fat_header->ignored[0]==0xe9)
		&& (fat_header->fats==1 || fat_header->fats==2)))
		return 1;   /* Obviously not a FAT */
	switch(fat_header->sectors_per_cluster)
	{
	case 1:	case 2:	case 4:	case 8:	case 16:	case 32:	case 64:	case 128:
		break;
	default:
		return 1;
	}
	switch(fat_header->fats)
	{
	case 1:
		break;
	case 2:
		break;
	default:
		return 1;
	}
	return 0;
}


int test_NTFS(const ntfs_boot_sector*ntfs_header, LCN l_size)
{
	LCN lba = l_size / SECTOR_SIZE;
	chs tmp;
	int verbose = 1;
	//LBA2CHS(lba, tmp);

	if(ntfs_header->marker!=0xAA55 ||
		(ntfs_header->reserved)>0 ||
		ntfs_header->fats>0 ||
		ntfs_header->dir_entries[0]!=0 || ntfs_header->dir_entries[1]!=0 ||
		ntfs_header->sectors[0]!=0 || ntfs_header->sectors[1]!=0 ||
		ntfs_header->fat_length!=0 || (ntfs_header->total_sect)!=0 ||
		memcmp(ntfs_header->system_id,"NTFS",4)!=0)
		return 1;
	switch(ntfs_header->sectors_per_cluster)
	{
	case 1: case 2: case 4: case 8: case 16: case 32: case 64: case 128:
		break;
	default:
		return 1;
	}
 	return 0;
}


bool ReadFileOffset(char* file_path, __int64 ll_offset, long l_buf_size, char* buf, __in DWORD dwMoveMethod)
{
	DWORD readsize;
	LARGE_INTEGER tmp = {0};

	HANDLE hFile = CreateFileA(file_path, 
		GENERIC_READ,               
		FILE_SHARE_READ,
		NULL, 
		OPEN_EXISTING, 
		FILE_FLAG_SEQUENTIAL_SCAN, 
		NULL);
	if ( hFile == INVALID_HANDLE_VALUE){                               //Open the data file.
		ErrorOut("CreateFile() Error!");
	}
	tmp.QuadPart = ll_offset;
	tmp.LowPart = SetFilePointer(hFile, tmp.QuadPart, &tmp.HighPart, dwMoveMethod);
	if (ReadFile(hFile, buf, l_buf_size, &readsize, NULL))
	{
		CloseHandle(hFile);
		return 1;
	}else
	{
		CloseHandle(hFile);
		return 0;
	}
}


bool WriteFileOffset(char* file_path, __int64 ll_offset, long l_buf_size, char* buf, __in DWORD dwMoveMethod)
{
	DWORD readsize;
	LARGE_INTEGER tmp = {0};

	HANDLE hFile = CreateFileA(file_path, 
		GENERIC_WRITE | GENERIC_READ,               
		FILE_SHARE_WRITE|FILE_SHARE_READ,
		NULL, 
		OPEN_EXISTING, 
		FILE_FLAG_SEQUENTIAL_SCAN, 
		NULL);

	if ( hFile == INVALID_HANDLE_VALUE){                               //Open the data file.
		ErrorOut("CreateFile() Error!");
	}
	tmp.QuadPart = ll_offset;
	tmp.LowPart = SetFilePointer(hFile, tmp.QuadPart, &tmp.HighPart, dwMoveMethod);
	if (WriteFile(hFile, buf, l_buf_size, &readsize, NULL))
	{
		CloseHandle(hFile);
		return 1;
	}else
	{
		CloseHandle(hFile);
		return 0;
	}
}


void ToGetDBR(char* p_file, long l_size, LCN offset)
{
	long i = 0;
	char *buf	= NULL;
	char *temp	= NULL;
	LCN ll_offset = 0;
	
	do 
	{
		buf = p_file + i * SECTOR_SIZE;
		if (!test_NTFS((ntfs_boot_sector*)buf, offset + i * SECTOR_SIZE))
		{
			ll_offset = offset + (i * SECTOR_SIZE);

			temp = (char*)malloc(512);
			memcpy(temp, buf, 512);
			if (InsertDBRList(g_dbr_list_head, temp, 1, g_n_dbr, ll_offset))    // NTFS type is 1)
			{
				//printf ("Found NTFS! AT %lld sectors\n", ll_offset / SECTOR_SIZE);
			}
			ll_offset = 0;
			temp = NULL;
		}
		if(!test_FAT((fat_boot_sector*)buf, offset + i * SECTOR_SIZE))
		{
			ll_offset = offset + (i * SECTOR_SIZE);

			temp = (char*)malloc(512);
			memcpy(temp, buf, 512);
			if (InsertDBRList(g_dbr_list_head, temp, 2, g_n_dbr, ll_offset))    // NTFS type is 2)
			{
				//printf("Found FAT! AT %lld sectors\n", ll_offset / SECTOR_SIZE);
			}
			ll_offset = 0;
			temp = NULL;
		}
		i++;
	} while (i * SECTOR_SIZE < l_size);
}


int Maping_file(char* big_file, LCN lOffset, long lSize)
{
	char* pDPT_File;                                                  //存放指向内存映射文件的首地址

	HANDLE hFile = CreateFileA(big_file, 
		GENERIC_READ,               
		FILE_SHARE_READ,
		NULL, 
		OPEN_EXISTING, 
		FILE_FLAG_SEQUENTIAL_SCAN, 
		NULL);

	if ( hFile == INVALID_HANDLE_VALUE){                               //Open the data file.
		ErrorOut("CreateFile() Error!");
	}

	HANDLE hFileMapping = CreateFileMapping(hFile, 
		NULL,         //Create the file-mapping object.
		PAGE_READONLY,
		0, 
		0,
		NULL);
	if (hFileMapping == INVALID_HANDLE_VALUE){
		ErrorOut("CreateFileMapping() Error!");
	}
	PBYTE pbFile = (PBYTE) MapViewOfFile(hFileMapping, FILE_MAP_READ,
		lOffset & 0xFFFFFFFF00000000,                                                             // Offset high
		lOffset & 0xFFFFFFFF,                                                                     // Offset low
		lSize);                                                                                   // bytes to map
	if (pbFile == INVALID_HANDLE_VALUE){
		ErrorOut("MapViewOfFile() Error!");
	}
	//printf("%lld,  %lld\n", g_ll_file_size, lOffset);

	//////////////////////////////////////////////
	pDPT_File = (char*)pbFile;
	ToGetDBR(pDPT_File, lSize, lOffset);

	//////////////////////////////////////////////

	UnmapViewOfFile(pbFile);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	return 0;
}

// 
// big_file: 需要映射的文件路径
// ll_file_size: 需要映射的文件总大小

int ToMapping(char *big_file, unsigned __int64 ll_file_size)
{ 
	LCN i = 0;

	//得到系统分配粒度
	SYSTEM_INFO sinf;
	GetSystemInfo(&sinf);
	DWORD dwAll = sinf.dwAllocationGranularity;

	printf ("Total %dM.\nSearching...\n", ll_file_size / (BYTE_PER_M));

	if (ll_file_size <= MAPPING_SIZE)                                      //内存镜像小于64M时，一次性挂载
	{
		Maping_file(big_file, 0, ll_file_size);
	}else{
		for (i = 0; i < (ll_file_size / MAPPING_SIZE) ; i++)                 //否则以64M为一个镜像映射单位，循环挂载，直到全部映射完成
		{ 
			if (i == 0){
				Maping_file(big_file, (i * (MAPPING_SIZE)) - (i * (MAPPING_SIZE) % dwAll), MAPPING_SIZE);
			}else {
				Maping_file(big_file, (i * (MAPPING_SIZE)) - ((i * (MAPPING_SIZE)) % dwAll), MAPPING_SIZE);         
			}
		}
		if (ll_file_size > (i * MAPPING_SIZE)){                             //最后一次可能并不是64M，需要根据实际大小来映射
			Maping_file(big_file, i * MAPPING_SIZE - ((i * MAPPING_SIZE) % dwAll), ll_file_size - i * MAPPING_SIZE);
		}
	}
	return 0;
}

int JudgeMFT(char* file_path, dbr_list* p_dbr, ntfs_boot_sector* ntfs)
{

	char sz_temp1[4] = {0};
	char sz_temp2[4] = {0};
	DWORD readsize;
	LARGE_INTEGER tmp1 = {0};
	LARGE_INTEGER tmp2 = {0};
	tmp1.QuadPart = p_dbr->ll_offset + (ntfs->mft_lcn.QuadPart * ntfs->sectors_per_cluster * SECTOR_SIZE);
	tmp2.QuadPart = p_dbr->ll_offset - (ntfs->sectors_nbr * SECTOR_SIZE) + (ntfs->mft_lcn.QuadPart * ntfs->sectors_per_cluster * SECTOR_SIZE);

	if (!ReadFileOffset(file_path, tmp1.QuadPart, 4, sz_temp1, FILE_BEGIN))
		ErrorOut("ReadFile Error!\n");
	
	if (!memcmp(sz_temp1, "FILE", 4))
	{
		p_dbr->ll_start_sector = p_dbr->ll_offset / SECTOR_SIZE;
		return 1;
	}else
	{
		if (!ReadFileOffset(file_path, tmp2.QuadPart, 4, sz_temp2, FILE_BEGIN))
			ErrorOut("ReadFile Error!\n");
		
		if (!memcmp(sz_temp2, "FILE", 4))
		{
			p_dbr->ll_start_sector = p_dbr->ll_offset / SECTOR_SIZE - ntfs->sectors_nbr;
			p_dbr->n_is_org = 1;
			return 1;
		}
	}
	return 0;
}


int JudgeFAT(char *file_path, dbr_list* p_dbr, fat_boot_sector* fat)
{
	char sz_temp1[4] = {0};
	char sz_temp2[4] = {0};
	LARGE_INTEGER tmp1 = {0};
	LARGE_INTEGER tmp2 = {0};

	char flag[4] = {'\xf8', '\xff', '\xff', '\x0f'};

	DWORD readsize = 0;
	
	tmp1.QuadPart = p_dbr->ll_offset + (fat->reserved * SECTOR_SIZE);
	tmp2.QuadPart = p_dbr->ll_offset - ((fat->backup_boot + fat->reserved) * SECTOR_SIZE);

	if (!ReadFileOffset(file_path, tmp1.QuadPart, 4, sz_temp1, FILE_BEGIN))
		ErrorOut("ReadFile Error!\n");
	
	if (!memcmp(sz_temp1, flag, 4))
	{
		p_dbr->ll_start_sector = p_dbr->ll_offset / SECTOR_SIZE;
		return 1;
	}else
	{
		if (!ReadFileOffset(file_path, tmp2.QuadPart, 4, sz_temp2, FILE_BEGIN))
			ErrorOut("ReadFile Error!\n");

		if (!memcmp(sz_temp2, flag, 4))
		{
			p_dbr->ll_start_sector = p_dbr->ll_offset / SECTOR_SIZE - fat->backup_boot;
			p_dbr->n_is_org = 1; 
			return 1;
		}
	}
	return 0;
}


void GetDPT(char* file_path)
{
	dbr_list* p_dbr_temp	= NULL;   
	ntfs_boot_sector* p_ntfs_temp	= NULL;
	fat_boot_sector* p_fat_temp	= NULL;
	dbr_list* p_dbr_temp_temp = NULL;
	int flag = 0;

	for(p_dbr_temp = g_dbr_list_head->p_next; p_dbr_temp != NULL;) 
	{  
		if (p_dbr_temp->n_type == 1)       //  NTFS
		{
			p_ntfs_temp = (ntfs_boot_sector*)p_dbr_temp->dbr;
			if (p_ntfs_temp->sectors_nbr < (g_ll_file_size / SECTOR_SIZE))   // 获取到的大小不能比总大小还大
			{
				flag = 0;
				flag = JudgeMFT(file_path, p_dbr_temp, p_ntfs_temp);

				if (flag)
				{
					p_dbr_temp->flag = 1;
					p_dbr_temp->ll_total_sector = (LCN)p_ntfs_temp->sectors_nbr;
					//g_n_part++;
				}

				printf("Type: NTFS.\tOffset: %I64u.\tSize %I64u.\t Hidden: %lu\tMFT at %I64u cluster.\t MFT is %s!\n",
				p_dbr_temp->ll_offset / SECTOR_SIZE, 
				(LCN)p_ntfs_temp->sectors_nbr, 
				p_ntfs_temp->hidden,
				p_ntfs_temp->mft_lcn.QuadPart,
				flag ? "Right" : "Wrong");
			}
		}
		else if (p_dbr_temp->n_type == 2)    // FAT
		{
			p_fat_temp = (fat_boot_sector*)p_dbr_temp->dbr;

			if (!memcmp(p_fat_temp->BS_FilSysType, "FAT32", 5))  // 只处理FAT32
			{
				flag = 0;
				flag = JudgeFAT(file_path, p_dbr_temp, p_fat_temp);

				if (flag)
				{
					p_dbr_temp->flag = 1;
					//g_n_part++;
				}

				if (p_dbr_temp->p_next != NULL )
				{
					if ( p_dbr_temp->p_next->ll_offset - p_dbr_temp->ll_offset > 1024 * 1024)
					{
						printf("Type: FAT32.\tOffset: %I64u.\tSize %I64u.\t Hidden: %lu.\t\t\tFAT is %s!\n", 
							p_dbr_temp->ll_offset / SECTOR_SIZE , 
							(p_dbr_temp->p_next->ll_offset - p_dbr_temp->ll_offset) /SECTOR_SIZE, 
							p_fat_temp->hidden,
							flag ? "Right":"Wrong");
						p_dbr_temp->ll_total_sector = (p_dbr_temp->p_next->ll_offset - p_dbr_temp->ll_offset) / SECTOR_SIZE;
						//p_dbr_temp->ll_start_sector = 
					}
				}else
				{
					printf("Type: FAT32.\tOffset: %I64u.\tSize %I64u.\t Hidden: %lu.\t\t\tFAT is %s!\n", 
					p_dbr_temp->ll_offset / SECTOR_SIZE , 
					(g_ll_file_size - p_dbr_temp->ll_offset) / (512), 
					p_fat_temp->hidden,
					flag ? "Right":"Wrong");
					p_dbr_temp->ll_total_sector = (g_ll_file_size - p_dbr_temp->ll_offset) / SECTOR_SIZE;
				}
			}

 		}
		p_dbr_temp = p_dbr_temp->p_next;
	}  
};

void HandleFile(char* file_path, rebuild_content_t* p_rebuild_list)
{
	char* sz_vhd_buf = (char*)malloc(SECTOR_SIZE);
	memset(sz_vhd_buf, 0, SECTOR_SIZE);

	rebuild_content_t* p_rebuild_tmp = NULL;
	char tmp[SECTOR_SIZE] = {0};

/////////////////////////////// Handle VHD
	hd_ftr* vhd;
	vhd = (hd_ftr*)data;
	LARGE_INTEGER offset = {0};
	DWORD readsize = 0;

	/*Set hd_ftr struct*/
	vhd->orig_size = 0;   // clear
	vhd->orig_size = g_ll_file_size - SECTOR_SIZE;
	vhd->orig_size = INT64_TO_NET(vhd->orig_size);
	vhd->curr_size = vhd->orig_size;
	vhd->checksum = 0;

	/*calc checksum*/
	unsigned int temp = 0;
	for (int i = 0; i < 512; i++)
	{
		temp += data[i];
	}
	vhd->checksum = htonl(~temp);
///////////////////////////////////////////


	for(p_rebuild_tmp = p_rebuild_list->p_next; p_rebuild_tmp != NULL;) 
	{
		if (!ReadFileOffset(file_path, p_rebuild_tmp->ll_offset, p_rebuild_tmp->n_size, tmp, FILE_BEGIN))
			ErrorOut("Backup Read Error!\n");
		
		if (!WriteFileOffset(file_path, p_rebuild_tmp->ll_offset, p_rebuild_tmp->n_size, p_rebuild_tmp->content, FILE_BEGIN))
			ErrorOut("Backup Write Error!\n");

		memcpy(p_rebuild_tmp->content, tmp, p_rebuild_tmp->n_size);       // BackUp SECTOR
		p_rebuild_tmp = p_rebuild_tmp->p_next;
	}

/////////////////////////////////////////////////// BackUp VHD
	ReadFileOffset(file_path, -SECTOR_SIZE, SECTOR_SIZE, sz_vhd_buf, FILE_END);
	
/////////////////////////////////////////////*	*/// Write VHD
	WriteFileOffset(file_path, -SECTOR_SIZE, SECTOR_SIZE, (char*)vhd, FILE_END);

	printf("WriteFile Success! You can mount it as vhd file now!\n");
 	system("pause");


////////////////////////// Restore SECTOR

	for(p_rebuild_tmp = p_rebuild_list->p_next; p_rebuild_tmp != NULL;) 
	{
		if (!ReadFileOffset(file_path, p_rebuild_tmp->ll_offset, p_rebuild_tmp->n_size, tmp, FILE_BEGIN))
			ErrorOut("Restore Read Error!\n");

		if (!WriteFileOffset(file_path, p_rebuild_tmp->ll_offset, p_rebuild_tmp->n_size, p_rebuild_tmp->content, FILE_BEGIN))
			ErrorOut("Restore Write Error!\n");
		memcpy(p_rebuild_tmp->content, tmp, p_rebuild_tmp->n_size);       // BackUp SECTOR
		p_rebuild_tmp = p_rebuild_tmp->p_next;
	}

///////////////////////// Restore VHD
	WriteFileOffset(file_path, -SECTOR_SIZE, SECTOR_SIZE, sz_vhd_buf, FILE_END);

	printf("Restore File Success!\n");
}



/*显示DPT*/
int ShowDPT()
{
	dbr_list* p_dbr_temp = NULL;   

	__int64 tmp = 0;

	printf("\n\nChosse the partition you want to rebuild?\n");
	for(p_dbr_temp = g_dbr_list_head->p_next; p_dbr_temp != NULL;) 
	{
		if (p_dbr_temp->flag) // 需要添加
		{
			p_dbr_temp->flag = 0;   // 清空标志位置
			if (tmp < p_dbr_temp->ll_start_sector)
			{
				printf("\nPartition with type %s.\tStart with %lld sectors.\t Size %lld sectors.\t End with %lld sectors.\nIs this partition you want to restore?(y/n)", 
					(p_dbr_temp->n_type == 1?"NTFS":"FAT32"), 
					p_dbr_temp->ll_start_sector,
					p_dbr_temp->ll_total_sector,
					p_dbr_temp->ll_start_sector + p_dbr_temp->ll_total_sector
					);
				
				if (getchar() == 'y')
				{
					p_dbr_temp->flag = 1;
					tmp = p_dbr_temp->ll_start_sector + p_dbr_temp->ll_total_sector;
					g_n_part++;
					getchar();
				}else
					getchar();
			}
		}
		p_dbr_temp = p_dbr_temp->p_next;
	}
	return 0;
}


void ReBuildDPT(char* sz_file_path)
{
	char* sz_tmp = NULL;
	dbr_list* p_dbr_temp = NULL; 
	dbr_list* p_dbr_temp_tmp = NULL;
	unsigned char sign[2] = {0x55, 0xAA};
	__int64 tmp = 0;
	int k = 0;
	int i = 0;


	rebuild_content_t* rebuild_list = CreateReBuildHead();

	if (g_n_part <= 4)
	{
		sz_tmp = (char*)malloc(4 * sizeof(PartTableRecord) + 2);
		memset(sz_tmp, 0, 4 * sizeof(PartTableRecord) + 2);
		for(p_dbr_temp = g_dbr_list_head->p_next; p_dbr_temp != NULL;) 
		{
			if (p_dbr_temp->flag)  // 是否需可用信息
			{
				*(sz_tmp + k * 16 + 4) = (p_dbr_temp->n_type == 1) ? 0x07 : 0x0B; // byPartType
				memcpy(sz_tmp + k * 16 + 8, (char *)&(p_dbr_temp->ll_start_sector), sizeof(__int64));  // dwStartSector
				memcpy(sz_tmp + k * 16 + 12, (char *)&(p_dbr_temp->ll_total_sector), sizeof(__int64)); // dwTotalSector
				k++;

				if (p_dbr_temp->n_is_org)  // 是否起始扇区
				{
					InsertRebuildList(rebuild_list, p_dbr_temp->dbr, SECTOR_SIZE, p_dbr_temp->ll_start_sector * SECTOR_SIZE, i++);
				}
			}
			p_dbr_temp = p_dbr_temp->p_next;
		}
		memcpy(sz_tmp + 64, sign, 2);  
		InsertRebuildList(rebuild_list, sz_tmp, 4 * sizeof(PartTableRecord) + 2, 446, i++);
		
	}
	else
	{
		sz_tmp = (char*)malloc(4 * sizeof(PartTableRecord) + 2);
		memset(sz_tmp, 0, 4 * sizeof(PartTableRecord) + 2);
		for(p_dbr_temp = g_dbr_list_head->p_next; p_dbr_temp != NULL;) 
		{
	
			if (p_dbr_temp->flag)  // 是否需可用信息
			{
				if (k < 3)
				{
					if (k != 2)
					{
						*(sz_tmp + k * 16 + 4) = (p_dbr_temp->n_type == 1) ? 0x07 : 0x0B; // byPartType
						memcpy(sz_tmp + k * 16 + 8, (char *)&(p_dbr_temp->ll_start_sector), sizeof(__int64));  // dwStartSector
						tmp = p_dbr_temp->ll_total_sector + 1;
						memcpy(sz_tmp + k * 16 + 12, (char *)&tmp, sizeof(__int64)); // dwTotalSector
						k++;
					}
					else
					{
						*(sz_tmp + k * 16 + 4) = (p_dbr_temp->n_type == 1) ? 0x07 : 0x0B; // byPartType
						memcpy(sz_tmp + k * 16 + 8, (char *)&(p_dbr_temp->ll_start_sector), sizeof(__int64));  // dwStartSector
						tmp = p_dbr_temp->ll_total_sector + 1;
						memcpy(sz_tmp + k * 16 + 12, (char *)&tmp, sizeof(__int64)); // dwTotalSector
						k++;
				
						for (p_dbr_temp_tmp = p_dbr_temp->p_next; p_dbr_temp_tmp != NULL;)
						{
							if (p_dbr_temp_tmp->flag)
							{
								*(sz_tmp + k * 16 + 4) = 0x05; // byPartType
								tmp = p_dbr_temp_tmp->ll_start_sector - 1;
								memcpy(sz_tmp + k * 16 + 8, (char *)&tmp, sizeof(__int64));  // dwStartSector
								tmp = (g_ll_file_size/SECTOR_SIZE) - p_dbr_temp_tmp->ll_start_sector + 1;
								memcpy(sz_tmp + k * 16 + 12, (char *)&tmp, sizeof(__int64)); // dwTotalSector
								k++;
								memcpy(sz_tmp + 64, sign, 2);  
								InsertRebuildList(rebuild_list, sz_tmp, 4 * sizeof(PartTableRecord) + 2, 446, i++);
								break;
							}
							p_dbr_temp_tmp = p_dbr_temp_tmp->p_next;
						}
					}
				}
				else
				{
					sz_tmp = NULL;
					sz_tmp = (char*)malloc(4 * sizeof(PartTableRecord) + 2);
					memset(sz_tmp, 0, 4 * sizeof(PartTableRecord) + 2);
					*(sz_tmp + 4) = (p_dbr_temp->n_type == 1) ? 0x07 : 0x0B; // byPartType

					tmp = 1;   // 扩展分区偏移地址从当前地址算起（相对地址）
					memcpy(sz_tmp + 8, (char *)&tmp, sizeof(__int64));  // dwStartSector
					memcpy(sz_tmp + 12, (char *)&(p_dbr_temp->ll_total_sector), sizeof(__int64)); // dwTotalSector

					if (p_dbr_temp->p_next != NULL)
					{
						for (p_dbr_temp_tmp = p_dbr_temp->p_next; p_dbr_temp_tmp != NULL;)
						{
							if (p_dbr_temp_tmp->flag)
							{
								*(sz_tmp + 16 + 4) = 0x05; // byPartType
								tmp = p_dbr_temp_tmp->ll_start_sector - p_dbr_temp->ll_start_sector;
								//tmp = 1;
								memcpy(sz_tmp + 16 + 8, (char *)&tmp, sizeof(__int64));  // dwStartSector
								tmp = (g_ll_file_size/SECTOR_SIZE) - p_dbr_temp_tmp->ll_start_sector;
								memcpy(sz_tmp + 16 + 12, (char *)&tmp, sizeof(__int64)); // dwTotalSector
								break;
							}
							p_dbr_temp_tmp = p_dbr_temp_tmp->p_next;
						}
					}
					memcpy(sz_tmp + 64, sign, 2);  
					InsertRebuildList(rebuild_list, sz_tmp, 66, (p_dbr_temp->ll_start_sector - 1) * SECTOR_SIZE + 446, i++);
				}

				if (p_dbr_temp->n_is_org)  // 是否起始扇区
				{
					InsertRebuildList(rebuild_list, p_dbr_temp->dbr, SECTOR_SIZE, p_dbr_temp->ll_start_sector * SECTOR_SIZE, i++);
				}
			}
			p_dbr_temp = p_dbr_temp->p_next;
		}
	}
	HandleFile(sz_file_path, rebuild_list);
	FreeRebuildList(rebuild_list);
}


void main(int argc, char* argv[])
{
	int xx = sizeof(PartTableRecord);
	xx = sizeof(rebuild_content_t);
	g_dbr_list_head = CreateDBRHead();
	g_ll_file_size	= ToGetFileSize(argv[1]);
	
	ToMapping(argv[1], g_ll_file_size);
	printf("Searching Down!\n");
	
	GetDPT(argv[1]);
	ShowDPT();
	ReBuildDPT(argv[1]);
	FreeDBRList(g_dbr_list_head);
	printf("All Down!\n");
} 