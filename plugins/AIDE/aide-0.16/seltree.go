package aide

import (
  "container/list"
)

type mode_t uint64
type DB_ATTR_TYPE uint64

type DBTree_Line struct {
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

	Perm   mode_t	`json:"perm"`
	Perm_o mode_t //Permission for tree traverse

	Uid uint64		`json:"uid"`
	Gid uint64		`json:"gid"`

	//Atime	string
	Ctime string	`json:"ctime"`
	Mtime string	`json:"mtime"`

	Inode uint64	`json:"inode"`
	Nlink uint64	`json:"lcount"`

	Size   uint64	`json:"size"`
	Size_o uint64
	Bcount uint64

	Filename string	`json:"name"`
	Fullpath string
	Linkname string	`json:"lname"`

	Cntx string

	Attr DB_ATTR_TYPE		`json:"attr"`

	///// node attrs
	Attr_node DB_ATTR_TYPE		`json:"attr_node"`
	Changed_attrs_node DB_ATTR_TYPE		`json:"changed_attrs_node"`
	Checked_node uint64			`json:"checked_node"`
}

/* seltree structure
 * lists have regex_t* in them
 * checked is whether or not the node has been checked yet and status
 * when added
 * path is the path of the node
 * parent is the parent, NULL if root
 * childs is list of seltree*:s
 * new_data is this nodes new attributes (read from disk or db in --compare)
 * old_data is this nodes old attributes (read from db)
 * attr attributes to add for this node and possibly for its children
 * changed_attrs changed attributes between new_data and old_data
 */

type Seltree struct {

	Sel_rx_lst *list.List
	Neg_rx_lst *list.List
	Equ_rx_lst *list.List
	Childs *list.List
	Parent *Seltree

	Path string
	Checked uint64

	Conf_lineno int64
	Rx string

	Attr DB_ATTR_TYPE

	New_data *DBTree_Line
	Old_data *DBTree_Line

	Changed_attrs DB_ATTR_TYPE

}








