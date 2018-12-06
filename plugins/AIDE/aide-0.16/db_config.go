package aide

import "strconv"

const (
	DO_INIT    uint64 = (1 << 0)
	DO_COMPARE uint64 = (1 << 1)
	DO_DIFF    uint64 = (1 << 2)

	/* WE need this for rx_rules since enums are not orrable (horrible) */
	DB_FILENAME uint64 = (1 << 0)  /* "name",   */
	DB_LINKNAME uint64 = (1 << 1)  /* "lname",   */
	DB_PERM     uint64 = (1 << 2)  /* "perm",    */
	DB_UID      uint64 = (1 << 3)  /* "uid",     */
	DB_GID      uint64 = (1 << 4)  /* "gid",     */
	DB_SIZE     uint64 = (1 << 5)  /* "size",    */
	DB_ATIME    uint64 = (1 << 6)  /* "atime",   */
	DB_CTIME    uint64 = (1 << 7)  /* "ctime",   */
	DB_MTIME    uint64 = (1 << 8)  /* "mtime",   */
	DB_INODE    uint64 = (1 << 9)  /* "inode",   */
	DB_BCOUNT   uint64 = (1 << 10) /* "bcount",  */
	DB_LNKCOUNT uint64 = (1 << 11) /* "lcount",  */
	DB_MD5      uint64 = (1 << 12) /* "md5",     */
	DB_SHA1     uint64 = (1 << 13) /* "sha1",    */
	DB_RMD160   uint64 = (1 << 14) /* "rmd160",  */
	DB_TIGER    uint64 = (1 << 15) /* "tiger",   */
	/*
	  We want to matk these newertheless we have a
	  hash-functon or not.
	*/

	DB_CRC32  uint64 = (1 << 16) /* "crc32",   */
	DB_HAVAL  uint64 = (1 << 17) /* "haval",   */
	DB_GOST   uint64 = (1 << 18) /* "gost",    */
	DB_CRC32B uint64 = (1 << 19) /* "crc32b",  */
	// #define DB_ATTR    (1LLU<<20)     /* "attr"    */
	DB_ACL   uint64 = (1 << 21) /* "acl"      */
	DB_BSIZE uint64 = (1 << 22) /* "bsize"    */
	DB_RDEV  uint64 = (1 << 23) /* "rdev"     */
	DB_DEV   uint64 = (1 << 24) /* "dev"      */

	DB_CHECKMASK  uint64 = (1 << 25) /* "checkmask"*/
	DB_SIZEG      uint64 = (1 << 26) /* "unknown"  */
	DB_CHECKINODE uint64 = (1 << 27) /* "checkinode"*/
	DB_NEWFILE    uint64 = (1 << 28) /* "allow new file" */
	DB_RMFILE     uint64 = (1 << 29) /* "allot rm file" */
	DB_SHA256     uint64 = (1 << 30) /* "sha256",  */
	DB_SHA512     uint64 = (1 << 31) /* "sha512",  */
	DB_SELINUX    uint64 = (1 << 32) /* "selinux", */
	DB_XATTRS     uint64 = (1 << 33) /* "xattrs",  */
	DB_WHIRLPOOL  uint64 = (1 << 34) /* "whirlpool",  */
	DB_FTYPE      uint64 = (1 << 35) /* "file type",  */
	DB_E2FSATTRS  uint64 = (1 << 36) /* "ext2 file system attributes"  */

	// DB_FIELD
	DB_filename     uint64 = 0  /* "name",   */
	DB_linkname     uint64 = 1  /* "lname",   */
	DB_perm         uint64 = 2  /* "perm",    */
	DB_uid          uint64 = 3  /* "uid",     */
	DB_gid          uint64 = 4  /* "gid",     */
	DB_size         uint64 = 5  /* "size",    */
	DB_atime        uint64 = 6  /* "atime",   */
	DB_ctime        uint64 = 7  /* "ctime",   */
	DB_mtime        uint64 = 8  /* "mtime",   */
	DB_inode        uint64 = 9  /* "inode",   */
	DB_bcount       uint64 = 10 /* "bcount",  */
	DB_lnkcount     uint64 = 11 /* "lcount",  */
	DB_md5          uint64 = 12 /* "md5",     */
	DB_sha1         uint64 = 13 /* "sha1",    */
	DB_rmd160       uint64 = 14 /* "rmd160",  */
	DB_tiger        uint64 = 15 /* "tiger",   */
	DB_crc32        uint64 = 16 /* "crc32",   */
	DB_haval        uint64 = 17 /* "haval",   */
	DB_gost         uint64 = 18 /* "gost",    */
	DB_crc32b       uint64 = 19 /* "crc32b",  */
	DB_attr         uint64 = 20 /* attributes */
	DB_acl          uint64 = 21 /* access control list */
	DB_bsize        uint64 = 22 /* "bsize"    */
	DB_rdev         uint64 = 23 /* "rdev"     */
	DB_dev          uint64 = 24 /* "dev"      */
	DB_checkmask    uint64 = 25 /* "checkmask"*/
	DB_allownewfile uint64 = 26 /* "allownewfile */
	DB_allowrmfile  uint64 = 27 /* "allowrmfile" */
	DB_sha256       uint64 = 28 /* "sha256",  */
	DB_sha512       uint64 = 29 /* "sha512",  */
	DB_whirlpool    uint64 = 30 /* "whirlpool",  */
	DB_selinux      uint64 = 31 /* "selinux",  */
	DB_xattrs       uint64 = 32 /* "xattrs",  */
	DB_e2fsattrs    uint64 = 33 /* "e2fsattrs"     */
	DB_unknown      uint64 = 34 /* "unknown"  */

	DB_HASHES uint64 = (DB_MD5 | DB_SHA1 | DB_RMD160 | DB_TIGER | DB_CRC32 | DB_HAVAL | DB_GOST | DB_CRC32B | DB_SHA256 | DB_SHA512 | DB_WHIRLPOOL)
)

var DB_field_names []string = []string{
	"name",
	"lname",
	"perm",
	"uid",
	"gid",
	"size",
	"atime",
	"ctime",
	"mtime",
	"inode",
	"bcount",
	"lcount",
	"md5",
	"sha1",
	"rmd160",
	"tiger",
	"crc32",
	"haval",
	"gost",
	"crc32b",
	"attr",
	"acl",
	"bsize",
	"rdev",
	"dev",
	"checkmask",
	"allownewfile",
	"allowrmfile",
	"sha256",
	"sha512",
	"whirlpool",
	"selinux",
	"xattrs",
	"e2fsattrs",
	"unknown"}

type DB_Line struct {
	/*
		md5			[]byte
		sha1		[]byte
		rmd160		[]byte
		tiger		[]byte

		sha256		[]byte
	*/
	Sha512 string	`json:"sha512"`

	/*
		crc32		[]byte // MHASH only
		haval		[]byte
		gost		[]byte
		crc32b		[]byte
		whirlpool	[]byte
	*/

	Perm   string	`json:"permStr"`
	Perm_o uint64 //Permission for tree traverse

	Uid uint64		`json:"uid"`
	Gid uint64		`json:"gid"`

	//Atime	string
	Ctime string	`json:"ctime"`
	Mtime string	`json:"mtime"`

	Inode string	`json:"inodeStr"`
	Nlink string	`json:"lcountStr"`

	size   string	`json:"sizeStr"`
	size_o uint64
	Bcount uint64

	Filename string	`json:"name"`
	Fullpath string
	Linkname string	`json:"lname"`

	Cntx string

	Attr string		`json:"attrStr"`
}

type JsonSrc_Spec struct {
	ItemsCount uint64	`json:"itemsCount"`
	Items	[]string	`json:"items"`
}

type SelTreeRx struct{
	RxS	[]Rx_rule	`json:"sRx"`
	RxN	[]Rx_rule	`json:"nRx"`
	RxE	[]Rx_rule	`json:"eRx"`
}

type JsonSrc struct {
	Spec 	JsonSrc_Spec `json:"spec"`
	RxLists	SelTreeRx	`json:"rxLists"`
	FilesDB	[]DB_Line	`json:"filesDB"`
}

type JsonDB struct {
	FilePath string
	RawData       []byte
	Jdb	JsonSrc
}

type DB_config struct {

	Config_check	int

	/* What are we supposed to do */
	Action	uint64

	jsonDB *JsonDB

	Tree *Seltree

}

func (dbLine *DB_Line) ToDBTreeLine() (*DBTree_Line) {
	var treeLine = new(DBTree_Line)

	treeLine.Attr, _ = strconv.ParseUint(dbLine.Attr, 10, 64)
	treeLine.Inode, _ = strconv.ParseUint(dbLine.Inode, 10, 64)
	treeLine.Nlink, _ = strconv.ParseUint(dbLine.Nlink, 10, 64)
	treeLine.Perm, _ = strconv.ParseUint(dbLine.Perm, 10, 64)
	treeLine.size, _ = strconv.ParseUint(dbLine.size, 10, 64)

	treeLine.Gid = dbLine.Gid
	treeLine.Uid = dbLine.Uid
	treeLine.Bcount = dbLine.Bcount
	treeLine.Perm_o = dbLine.Perm_o
	treeLine.size_o = dbLine.size_o

	treeLine.Fullpath = dbLine.Fullpath
	treeLine.Filename = dbLine.Filename
	treeLine.Linkname = dbLine.Linkname
	treeLine.Ctime = dbLine.Ctime
	treeLine.Mtime = dbLine.Mtime
	treeLine.Cntx = dbLine.Cntx
	treeLine.Sha512 = dbLine.Sha512

	return treeLine
}

