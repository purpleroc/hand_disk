

/*vhd尾部信息结构*/
typedef struct hd_ftr_t
{ 
	char   cookie[8];       /* Identifies original creator of the disk      */ 
	unsigned int    features;        /* Feature Support -- see below                 */ 
	unsigned int    ff_version;      /* (major,minor) version of disk file           */ 
	unsigned __int64  data_offset;     /* Abs. offset from SOF to next structure       */ 
	unsigned int    timestamp;       /* Creation time.  secs since 1/1/2000GMT       */ 
	char   crtr_app[4];     /* Creator application                          */ 
	unsigned int    crtr_ver;        /* Creator version (major,minor)                */ 
	unsigned int    crtr_os;         /* Creator host OS                              */ 
	unsigned __int64   orig_size;       /* Size at creation (bytes)                     */ 
	unsigned __int64  curr_size;       /* Current size of disk (bytes)                 */ 
	unsigned int    geometry;        /* Disk geometry                                */ 
	unsigned int    type;            /* Disk type                                    */ 
	unsigned int    checksum;        /* 1's comp sum of this struct.                 */ 
	unsigned char uu[16];        /* Unique disk ID, used for naming parents      */ 
	char   saved;           /* one-bit -- is this disk/VM in a saved state? */ 
	char   hidden;          /* tapdisk-specific field: is this vdi hidden?  */ 
	char   reserved[426];   /* padding                                      */ 
}hd_ftr; 


// /*
// *	分区表记录，一共64个字节
// *	磁头，柱面，扇区 的实际值还需要转换计算
// */
typedef struct PartTableRecord_t
{

	BYTE	byIsBoot;			//引导分区		1B	1B	80（引导分区），00（非引导分区）
	BYTE	byStartHead;		//起始磁头		1B	2B
	BYTE	byStartSector;		//起始扇区		1B	3B	
	BYTE	byStartCylinder;	//起始柱面		1B	4B
	BYTE	byPartType;			//分区类型		1B	5B	07（NTFS），0F（扩展分区），0B（FAT32），06（FAT16）
	BYTE	byEndHead;			//结束磁头		1B	6B
	BYTE	byEndSector;		//结束扇区		1B	7B
	BYTE	byEndCylinder;		//结束柱面		1B	8B
	DWORD	dwStartSector;		//开始扇区		4B	12B		
	DWORD	dwTotalSector;		//分区扇区数	4B	16B	最大2T Byte

} PartTableRecord;


// #pragma pack(2)
// typedef struct DBR_T
// {
// 	UCHAR boot_code[446];
// 	PartTableRecord partition[4];
// 	UCHAR sign[2];
// }DBR;


typedef struct dbr_list_t
{
	char* dbr;
	int n_type;
	int flag;
	int n_is_org;
	__int64 ll_offset;
	__int64 ll_total_sector;
	__int64 ll_start_sector;

	dbr_list_t* p_next;
	dbr_list_t()
	{
		dbr = NULL;
		n_type			= 0;
		p_next			= 0;
		ll_offset		= 0;
		n_is_org		= 0;
		flag			= 0;
		ll_total_sector = 0;
		ll_start_sector = 0;
	}
}dbr_list;



typedef struct rebuild_content_t
{
	char*	content;
	int		n_size;
	__int64 ll_offset;
	rebuild_content_t* p_next;

	rebuild_content_t()
	{
		content			= NULL;
		p_next			= NULL;
		n_size			= 0;
		ll_offset		= 0;
	}
}rebuild_content;



/*64位整形结构体*/
struct int64tonet  
{  
	union
	{  
		__int64 w_;  
		int r_[2];  
	}w, r;  

	int64tonet(__int64 i)  
	{  
		w.w_ = i;  
		r.r_[0] = htonl(w.r_[1]);  
		r.r_[1] = htonl(w.r_[0]);  
	}  

	__int64 operator()()  
	{  
		return r.w_;  
	}  
};  

typedef struct chs_t
{
	LCN c;
	LCN h;
	LCN s;
	chs_t()
	{
		c = 0;
		h = 0;
		s = 0;
	}
}chs;



typedef struct ntfs_boot_sector_t {
	BYTE	ignored[3];	/* 0x00 Boot strap short or near jump */
	char	system_id[8];	/* 0x03 Name : NTFS */
	BYTE	sector_size[2];	/* 0x0B bytes per logical sector */
	BYTE	sectors_per_cluster;	/* 0x0D sectors/cluster */
	WORD	reserved;	/* 0x0E reserved sectors = 0 */
	BYTE	fats;		/* 0x10 number of FATs = 0 */
	BYTE	dir_entries[2];	/* 0x11 root directory entries = 0 */
	BYTE	sectors[2];	/* 0x13 number of sectors = 0 */
	BYTE	media;		/* 0x15 media code (unused) */
	WORD	fat_length;	/* 0x16 sectors/FAT = 0 */
	WORD	secs_track;	/* 0x18 sectors per track */
	WORD	heads;		/* 0x1A number of heads */
	DWORD	hidden;		/* 0x1C hidden sectors (unused) */
	DWORD	total_sect;	/* 0x20 number of sectors = 0 */
	BYTE	physical_drive;	/* 0x24 physical drive number  */
	BYTE	unused;		/* 0x25 */
	WORD	reserved2;	/* 0x26 usually 0x80 */
	LCN	sectors_nbr;	/* 0x28 total sectors nbr */
	QWORD	mft_lcn;	/* 0x30 Cluster location of mft data.*/
	QWORD	mftmirr_lcn;	/* 0x38 Cluster location of copy of mft.*/
	char   clusters_per_mft_record;		/* 0x40 */
	BYTE  	reserved0[3];               	/* zero */
	char	clusters_per_index_record;	/* 0x44 clusters per index block */
	BYTE  	reserved1[3];               	/* zero */
	LCN 	volume_serial_number;       	/* 0x48 Irrelevant (serial number). */
	DWORD 	checksum;                   	/* 0x50 Boot sector checksum. */
	BYTE  	bootstrap[426];             	/* 0x54 Irrelevant (boot up code). */
	WORD	marker;				/* 0x1FE */
}ntfs_boot_sector ;



typedef struct fat_boot_sector_t {
	BYTE	ignored[3];	/* 0x00 Boot strap short or near jump */
	char	system_id[8];	/* 0x03 Name - can be used to special case
							partition manager volumes */
	BYTE	sector_size[2];	/* 0x0B bytes per logical sector */
	BYTE	sectors_per_cluster;	/* 0x0D sectors/cluster */
	WORD	reserved;	/* 0x0E reserved sectors */
	BYTE	fats;		/* 0x10 number of FATs */
	BYTE	dir_entries[2];	/* 0x11 root directory entries */
	BYTE	sectors[2];	/* 0x13 number of sectors */
	BYTE	media;		/* 0x15 media code (unused) */
	WORD	fat_length;	/* 0x16 sectors/FAT */
	WORD	secs_track;	/* 0x18 sectors per track */
	WORD	heads;		/* 0x1A number of heads */
	DWORD	hidden;		/* 0x1C hidden sectors (unused) */
	DWORD	total_sect;	/* 0x20 number of sectors (if sectors == 0) */

	/* The following fields are only used by FAT32 */
	DWORD	fat32_length;	/* 0x24=36 sectors/FAT */
	WORD	flags;		/* 0x28 bit 8: fat mirroring, low 4: active fat */
	BYTE	version[2];	/* 0x2A major, minor filesystem version */
	DWORD	root_cluster;	/* 0x2C first cluster in root directory */
	WORD	info_sector;	/* 0x30 filesystem info sector */
	WORD	backup_boot;	/* 0x32 backup boot sector */
	BYTE	BPB_Reserved[12];	/* 0x34 Unused */
	BYTE	BS_DrvNum;		/* 0x40 */
	BYTE	BS_Reserved1;		/* 0x41 */
	BYTE	BS_BootSig;		/* 0x42 */
	BYTE	BS_VolID[4];		/* 0x43 */
	BYTE	BS_VolLab[11];		/* 0x47 */
	BYTE	BS_FilSysType[8];	/* 0x52=82*/

	/* */
	BYTE	nothing[420];	/* 0x5A */
	WORD	marker;
}fat_boot_sector;



