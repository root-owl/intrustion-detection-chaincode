package aide

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"strconv"
)

const (
	RETOK	uint64 = 0
	RETFAIL	uint64 = 1

	DO_INIT    uint64 = (1 << 0)
	DO_COMPARE uint64 = (1 << 1)
	DO_DIFF    uint64 = (1 << 2)

	/* WE need this for rx_rules since enums are not orrable (horrible) */
	DB_FILENAME DB_ATTR_TYPE = (1 << 0)  /* "name",   */
	DB_LINKNAME DB_ATTR_TYPE = (1 << 1)  /* "lname",   */
	DB_PERM     DB_ATTR_TYPE = (1 << 2)  /* "perm",    */
	DB_UID      DB_ATTR_TYPE = (1 << 3)  /* "uid",     */
	DB_GID      DB_ATTR_TYPE = (1 << 4)  /* "gid",     */
	DB_SIZE     DB_ATTR_TYPE = (1 << 5)  /* "size",    */
	DB_ATIME    DB_ATTR_TYPE = (1 << 6)  /* "atime",   */
	DB_CTIME    DB_ATTR_TYPE = (1 << 7)  /* "ctime",   */
	DB_MTIME    DB_ATTR_TYPE = (1 << 8)  /* "mtime",   */
	DB_INODE    DB_ATTR_TYPE = (1 << 9)  /* "inode",   */
	DB_BCOUNT   DB_ATTR_TYPE = (1 << 10) /* "bcount",  */
	DB_LNKCOUNT DB_ATTR_TYPE = (1 << 11) /* "lcount",  */
	DB_MD5      DB_ATTR_TYPE = (1 << 12) /* "md5",     */
	DB_SHA1     DB_ATTR_TYPE = (1 << 13) /* "sha1",    */
	DB_RMD160   DB_ATTR_TYPE = (1 << 14) /* "rmd160",  */
	DB_TIGER    DB_ATTR_TYPE = (1 << 15) /* "tiger",   */
	/*
	  We want to matk these newertheless we have a
	  hash-functon or not.
	*/

	DB_CRC32  DB_ATTR_TYPE = (1 << 16) /* "crc32",   */
	DB_HAVAL  DB_ATTR_TYPE = (1 << 17) /* "haval",   */
	DB_GOST   DB_ATTR_TYPE = (1 << 18) /* "gost",    */
	DB_CRC32B DB_ATTR_TYPE = (1 << 19) /* "crc32b",  */
	// #define DB_ATTR    (1LLU<<20)     /* "attr"    */
	DB_ACL   DB_ATTR_TYPE = (1 << 21) /* "acl"      */
	DB_BSIZE DB_ATTR_TYPE = (1 << 22) /* "bsize"    */
	DB_RDEV  DB_ATTR_TYPE = (1 << 23) /* "rdev"     */
	DB_DEV   DB_ATTR_TYPE = (1 << 24) /* "dev"      */

	DB_CHECKMASK  DB_ATTR_TYPE = (1 << 25) /* "checkmask"*/
	DB_SIZEG      DB_ATTR_TYPE = (1 << 26) /* "unknown"  */
	DB_CHECKINODE DB_ATTR_TYPE = (1 << 27) /* "checkinode"*/
	DB_NEWFILE    DB_ATTR_TYPE = (1 << 28) /* "allow new file" */
	DB_RMFILE     DB_ATTR_TYPE = (1 << 29) /* "allot rm file" */
	DB_SHA256     DB_ATTR_TYPE = (1 << 30) /* "sha256",  */
	DB_SHA512     DB_ATTR_TYPE = (1 << 31) /* "sha512",  */
	DB_SELINUX    DB_ATTR_TYPE = (1 << 32) /* "selinux", */
	DB_XATTRS     DB_ATTR_TYPE = (1 << 33) /* "xattrs",  */
	DB_WHIRLPOOL  DB_ATTR_TYPE = (1 << 34) /* "whirlpool",  */
	DB_FTYPE      DB_ATTR_TYPE = (1 << 35) /* "file type",  */
	DB_E2FSATTRS  DB_ATTR_TYPE = (1 << 36) /* "ext2 file system attributes"  */

	// DB_FIELD
	DB_filename     DB_ATTR_TYPE = 0  /* "name",   */
	DB_linkname     DB_ATTR_TYPE = 1  /* "lname",   */
	DB_perm         DB_ATTR_TYPE = 2  /* "perm",    */
	DB_uid          DB_ATTR_TYPE = 3  /* "uid",     */
	DB_gid          DB_ATTR_TYPE = 4  /* "gid",     */
	DB_size         DB_ATTR_TYPE = 5  /* "size",    */
	DB_atime        DB_ATTR_TYPE = 6  /* "atime",   */
	DB_ctime        DB_ATTR_TYPE = 7  /* "ctime",   */
	DB_mtime        DB_ATTR_TYPE = 8  /* "mtime",   */
	DB_inode        DB_ATTR_TYPE = 9  /* "inode",   */
	DB_bcount       DB_ATTR_TYPE = 10 /* "bcount",  */
	DB_lnkcount     DB_ATTR_TYPE = 11 /* "lcount",  */
	DB_md5          DB_ATTR_TYPE = 12 /* "md5",     */
	DB_sha1         DB_ATTR_TYPE = 13 /* "sha1",    */
	DB_rmd160       DB_ATTR_TYPE = 14 /* "rmd160",  */
	DB_tiger        DB_ATTR_TYPE = 15 /* "tiger",   */
	DB_crc32        DB_ATTR_TYPE = 16 /* "crc32",   */
	DB_haval        DB_ATTR_TYPE = 17 /* "haval",   */
	DB_gost         DB_ATTR_TYPE = 18 /* "gost",    */
	DB_crc32b       DB_ATTR_TYPE = 19 /* "crc32b",  */
	DB_attr         DB_ATTR_TYPE = 20 /* attributes */
	DB_acl          DB_ATTR_TYPE = 21 /* access control list */
	DB_bsize        DB_ATTR_TYPE = 22 /* "bsize"    */
	DB_rdev         DB_ATTR_TYPE = 23 /* "rdev"     */
	DB_dev          DB_ATTR_TYPE = 24 /* "dev"      */
	DB_checkmask    DB_ATTR_TYPE = 25 /* "checkmask"*/
	DB_allownewfile DB_ATTR_TYPE = 26 /* "allownewfile */
	DB_allowrmfile  DB_ATTR_TYPE = 27 /* "allowrmfile" */
	DB_sha256       DB_ATTR_TYPE = 28 /* "sha256",  */
	DB_sha512       DB_ATTR_TYPE = 29 /* "sha512",  */
	DB_whirlpool    DB_ATTR_TYPE = 30 /* "whirlpool",  */
	DB_selinux      DB_ATTR_TYPE = 31 /* "selinux",  */
	DB_xattrs       DB_ATTR_TYPE = 32 /* "xattrs",  */
	DB_e2fsattrs    DB_ATTR_TYPE = 33 /* "e2fsattrs"     */
	DB_unknown      DB_ATTR_TYPE = 34 /* "unknown"  */

	DB_HASHES DB_ATTR_TYPE = (DB_MD5 | DB_SHA1 | DB_RMD160 | DB_TIGER | DB_CRC32 | DB_HAVAL | DB_GOST | DB_CRC32B | DB_SHA256 | DB_SHA512 | DB_WHIRLPOOL)
)

var DB_field_names []string = []string {
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

	Size   string	`json:"sizeStr"`
	Size_o uint64
	Bcount uint64

	Filename string	`json:"name"`
	Fullpath string
	Linkname string	`json:"lname"`

	Cntx string

	Attr string		`json:"attrStr"`

	///// node attrs
	Attr_node string		`json:"attrStr_node"`
	Changed_attrs_node string		`json:"changed_attrs_node"`
	Checked_node string			`json:"checked_node"`
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
	RawDataSha512	[]byte
	Jdb	JsonSrc
}

type DB_config struct {

	Config_check	int

	Limit []byte

	/* What are we supposed to do */
	Action	uint64

	jdbOldPath string
	jdbNewPath string
	jdbDiskPath string

	JdbOld *JsonDB
	JdbNew *JsonDB
	JdbDisk *JsonDB

	Ignored_added_attrs DB_ATTR_TYPE
	Ignored_removed_attrs DB_ATTR_TYPE
	Ignored_changed_attrs DB_ATTR_TYPE
	Forced_attrs DB_ATTR_TYPE

	Ntotal, Nadd, Nrem, Nchg int64
	Report_base16 int64
	Report_quiet int64
	Report_detailed_init int
	Grouped int
	Summarize_changes int

	Verbose_level int

	Tree *Seltree

}

func New_DB_confg(oldJsPath, newJsPath, diskJsPath string) (*DB_config) {

	var dbc = new(DB_config)

	dbc.jdbOldPath = oldJsPath
	dbc.jdbNewPath = newJsPath
	dbc.jdbDiskPath = diskJsPath

	dbc.Limit = nil
	dbc.JdbOld = nil
	dbc.JdbNew = nil
	dbc.JdbDisk = nil

	dbc.Tree = nil

	/*
	dbc.Action |= DO_COMPARE
	dbc.Grouped = 1
	dbc.Summarize_changes = 1
	dbc.Verbose_level = 5
	*/

	return dbc
}

func (conf *DB_config)Load_JSON_DB(db uint64)  {

	var err error
	var jdb *JsonDB = nil
	var dbPath string = ""


	switch db {
	case DB_OLD:
		jdb, err = NewJDB(conf.jdbOldPath)
		dbPath = conf.jdbOldPath
		break
	case DB_NEW:
		jdb, err = NewJDB(conf.jdbNewPath)
		dbPath = conf.jdbNewPath
		break
	case DB_DISK:
		jdb, err = NewJDB(conf.jdbDiskPath)
		dbPath = conf.jdbDiskPath
		break
	}

	if err != nil {
		fmt.Printf("--- Load_JSON_DB()-->NewJDB() db:%d path:%s %s err:%s \n", db, dbPath, err)
	} else {
		//var newStr []byte
		//fmt.Printf("+++ Jdb: %+v \n", jdb.Jdb)

		//newStr, err = json.Marshal(&jdb.Jdb)
		//newStr, err = json.MarshalIndent(&jdb.Jdb,"", "    ")
		//fmt.Printf("+++ newStr:\n%s \n", newStr)

		fmt.Printf("+++ Load_JSON_DB()-->NewJDB() db:%d path:%s success.\n", db, dbPath)

		h512 := sha512.New()
		h512.Write(jdb.RawData)
		jdb.RawDataSha512 = h512.Sum(nil)

		switch db {
		case DB_OLD:
			conf.JdbOld = jdb
			break
		case DB_NEW:
			conf.JdbNew = jdb
			break
		case DB_DISK:
			conf.JdbDisk = jdb
			break
		}
	}
}

func (jdb *JsonDB) Print_JDB_singleHash()  {
	fmt.Printf("\n---------------- Sha512 of :%s start --------------------\n", jdb.FilePath)
	fmt.Printf("sha512:%x\n", jdb.RawDataSha512)
	fmt.Printf("---------------- Sha512 of :%s end --------------------\n", jdb.FilePath)
}

func (conf *DB_config) Print_JDB_Hashes()  {
	fmt.Printf("\n+++++ Is different between old and new DB:%v\n", bytes.Equal(conf.JdbOld.RawData, conf.JdbNew.RawData))
	conf.JdbOld.Print_JDB_singleHash()
	conf.JdbNew.Print_JDB_singleHash()
}

func (dbLine *DB_Line) ToDBTreeLine() (*DBTree_Line) {
	var treeLine = new(DBTree_Line)

	var tmp uint64 = 0
	//var itmp int64 = 0
	tmp, _ = strconv.ParseUint(dbLine.Attr, 10, 64)
	/*
	itmp, _ = strconv.ParseInt(dbLine.Attr, 10, 64)
	if dbLine.Filename == "/folder_b/folder_ba" {
		fmt.Printf("DB_DISK filename:%s tmp:0x%x itmp:0x%x tmpd:%d itmpd:%d \n", dbLine.Filename, tmp, itmp, tmp, itmp)
	}
	*/
	treeLine.Attr = DB_ATTR_TYPE(tmp)
	treeLine.Inode, _ = strconv.ParseUint(dbLine.Inode, 10, 64)
	treeLine.Nlink, _ = strconv.ParseUint(dbLine.Nlink, 10, 64)
	tmp, _ = strconv.ParseUint(dbLine.Perm, 8, 64)
	treeLine.Perm = mode_t(tmp)
	treeLine.Size, _ = strconv.ParseUint(dbLine.Size, 10, 64)
	/*
	if dbLine.Filename == "/file_a" {
		fmt.Printf(" +++ ToDBTreeLine() size:%s", dbLine.Size)
	}
	*/

	treeLine.Gid = dbLine.Gid
	treeLine.Uid = dbLine.Uid
	treeLine.Bcount = dbLine.Bcount
	treeLine.Perm_o = mode_t(dbLine.Perm_o)
	treeLine.Size_o = dbLine.Size_o

	treeLine.Fullpath = dbLine.Fullpath
	treeLine.Filename = dbLine.Filename
	treeLine.Linkname = dbLine.Linkname
	treeLine.Ctime = dbLine.Ctime
	treeLine.Mtime = dbLine.Mtime
	treeLine.Cntx = dbLine.Cntx
	treeLine.Sha512 = dbLine.Sha512

	// node attrs
	tmp, _ = strconv.ParseUint(dbLine.Attr_node, 10, 64)
	treeLine.Attr_node = DB_ATTR_TYPE(tmp)
	tmp, _ = strconv.ParseUint(dbLine.Changed_attrs_node, 10, 64)
	treeLine.Changed_attrs_node = DB_ATTR_TYPE(tmp)
	tmp, _ = strconv.ParseUint(dbLine.Checked_node, 10, 64)
	treeLine.Checked_node = tmp


	return treeLine
}

