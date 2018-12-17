package aide

import (
	"bytes"
	"container/list"
	"fmt"
	"regexp"
	"strings"
)

type RESTRICTION_TYPE uint64
const (
	RESTRICTION_FT_REG	RESTRICTION_TYPE = 1 << 0  /* file */
	RESTRICTION_FT_DIR	RESTRICTION_TYPE = 1 << 1  /* dir */
	RESTRICTION_FT_FIFO	RESTRICTION_TYPE = 1 << 2  /* fifo */
	RESTRICTION_FT_LNK	RESTRICTION_TYPE = 1 << 3  /* link */
	RESTRICTION_FT_BLK	RESTRICTION_TYPE = 1 << 4  /* block device */
	RESTRICTION_FT_CHR	RESTRICTION_TYPE = 1 << 5  /* char device */
	RESTRICTION_FT_SOCK	RESTRICTION_TYPE = 1 << 6  /* socket */
	RESTRICTION_FT_DOOR	RESTRICTION_TYPE = 1 << 7  /* door */
	RESTRICTION_FT_PORT	RESTRICTION_TYPE = 1 << 8  /* port */
	RESTRICTION_NULL	RESTRICTION_TYPE = 0

	/* Traditional mask definitions for st_mode. */
	/* The ugly casts on only some of the definitions are to avoid suprising sign
	 * extensions such as S_IFREG != (mode_t) S_IFREG when ints are 32 bits.
	 */
	S_IFMT	mode_t = 0170000	/* type of file */
	S_IFLNK	mode_t = 0120000	/* type of file */
	S_IFREG	mode_t = 0100000	/* regular */
	S_IFBLK	mode_t = 0060000		/* block special */
	S_IFDIR	mode_t = 0040000  	/* directory */
	S_IFCHR	mode_t = 0020000		/* character special */
	S_IFIFO	mode_t = 0010000		/* this is a FIFO */
	S_ISUID	mode_t = 0004000		/* set user id on execution */
	S_ISGID	mode_t = 0002000		/* set group id on execution */

	/* next is reserved for future use */
	S_ISVTX   uint64 = 01000		/* save swapped text even after use */

	/* POSIX masks for st_mode. */
	S_IRWXU   mode_t = 00700		/* owner:  rwx------ */
	S_IRUSR   mode_t = 00400		/* owner:  r-------- */
	S_IWUSR   mode_t = 00200		/* owner:  -w------- */
	S_IXUSR   mode_t = 00100		/* owner:  --x------ */

	S_IRWXG   mode_t = 00070		/* group:  ---rwx--- */
	S_IRGRP   mode_t = 00040		/* group:  ---r----- */
	S_IWGRP   mode_t = 00020		/* group:  ----w---- */
	S_IXGRP   mode_t = 00010		/* group:  -----x--- */

	S_IRWXO   mode_t = 00007		/* others: ------rwx */
	S_IROTH   mode_t = 00004		/* others: ------r-- */
	S_IWOTH   mode_t = 00002		/* others: -------w- */
	S_IXOTH   mode_t = 00001		/* others: --------x */

)

/* The following macros test st_mode (from POSIX Sec. 5.6.1.1). */
func S_ISREG(mode mode_t) bool {
	return ((mode) & S_IFMT) == S_IFREG	/* is a reg file */
}

func S_ISDIR(mode mode_t) bool {
	return ((mode) & S_IFMT) == S_IFDIR /* is a directory */
}

func S_ISCHR(mode mode_t) bool {
	return ((mode) & S_IFMT) == S_IFCHR 	/* is a char spec */
}

func S_ISBLK(mode mode_t) bool {
	return ((mode) & S_IFMT) == S_IFBLK /* is a block spec */
}

func S_ISLNK(mode mode_t) bool {
	return ((mode) & S_IFMT) == S_IFLNK /* is a block spec */
}

func S_ISFIFO(mode mode_t) bool {
	return ((mode) & S_IFMT) == S_IFIFO /* is a pipe/FIFO */
}

type Rx_rule struct {
	//char* rx; /* Regular expression in text form */
	Rx string `json:"rx"`
	Crx	*regexp.Regexp
	//pcre* crx; /* Compiled regexp */
	//DB_ATTR_TYPE attr; /* Which attributes to save */
	Attr DB_ATTR_TYPE `json:"attr"`
	//long  conf_lineno; /* line no. of rule definition*/
	Conf_lineno int64 `json:"cfgNo"`
	//RESTRICTION_TYPE restriction;
	Restriction RESTRICTION_TYPE `json:"restriction"`
}


func easy_compare(attrType DB_ATTR_TYPE, l1 *DBTree_Line, l2 *DBTree_Line, ret *DB_ATTR_TYPE) {

	if (((attrType & l1.Attr) != 0) && ((attrType & l2.Attr) != 0)) && (l1.Size != l2.Size) {
		*ret |= DB_SIZE
		}

	switch attrType {
	case DB_SIZE:
		if (((attrType & l1.Attr) != 0) && ((attrType & l2.Attr) != 0)) && (l1.Size != l2.Size) {
			*ret |= DB_SIZE
		}
		break
	case DB_BCOUNT:
		if (((attrType & l1.Attr) != 0) && ((attrType & l2.Attr) != 0)) && (l1.Bcount != l2.Bcount) {
			*ret |= DB_BCOUNT
		}
		break
	case DB_PERM:
		if (((attrType & l1.Attr) != 0) && ((attrType & l2.Attr) != 0)) && (l1.Perm != l2.Perm) {
			*ret |= DB_PERM
		}
		break
	case DB_UID:
		if (((attrType & l1.Attr) != 0) && ((attrType & l2.Attr) != 0)) && (l1.Uid != l2.Uid) {
			*ret |= DB_UID
		}
		break
	case DB_GID:
		if (((attrType & l1.Attr) != 0) && ((attrType & l2.Attr) != 0)) && (l1.Gid != l2.Gid) {
			*ret |= DB_GID
		}
		break
	case DB_MTIME:
		if (((attrType & l1.Attr) != 0) && ((attrType & l2.Attr) != 0)) && (l1.Mtime != l2.Mtime) {
			*ret |= DB_MTIME
		}
		break
	case DB_CTIME:
		if (((attrType & l1.Attr) != 0) && ((attrType & l2.Attr) != 0)) && (l1.Ctime != l2.Ctime) {
			*ret |= DB_CTIME
		}
		break
	case DB_INODE:
		if (((attrType & l1.Attr) != 0) && ((attrType & l2.Attr) != 0)) && (l1.Inode != l2.Inode) {
			*ret |= DB_INODE
		}
		break
	case DB_LNKCOUNT:
		/*
		if l1.Filename == "/file_a" {
			fmt.Printf("0x%x", *ret)
		}
		*/
		if (((attrType & l1.Attr) != 0) && ((attrType & l2.Attr) != 0)) && (l1.Nlink != l2.Nlink) {
			*ret |= DB_LNKCOUNT
		}
		break
	}
}

func has_str_changed(old string, new string) (bool) {
	return ((old != "" && new != "") && old != new ) ||
		(( old != "" && new == "") || ( old == "" && new != ""))
}

type IsStrChange func(old string, new string) bool

func easy_function_compare(attrType DB_ATTR_TYPE, l1 *DBTree_Line, l2 *DBTree_Line, ret *DB_ATTR_TYPE, isStrChange IsStrChange) {
	/*
	if((a&l1->attr && (a&l2->attr)) && c(l1->b,l2->b)){ \
		ret|=a; \
	*/

	if ((attrType & l1.Attr) != 0 && (attrType & l2.Attr) != 0) && isStrChange(l1.Linkname, l2.Linkname) {
		*ret |= attrType
	}
}

func has_md_changed(old []byte, new []byte) bool {
	//error(255,"Debug, has_md_changed %p %p\n",old,new);
	return ((old != nil && new != nil) && bytes.Compare(old, new) != 0) ||
		((old != nil && new == nil) || (old == nil && new != nil))
}

type IsMdChange func(old []byte, new []byte) bool

func easy_md_compare(attrType DB_ATTR_TYPE, l1 *DBTree_Line, l2 *DBTree_Line, ret *DB_ATTR_TYPE, isMdChange IsMdChange) {
		/*
	#define easy_md_compare(a,b,c) \
	if((a&l1->attr && (a&l2->attr)) && has_md_changed(l1->b,l2->b, c)){ \
	ret|=a; \
	}
	*/
	if ((attrType & l1.Attr) != 0 && (attrType & l2.Attr) != 0) && isMdChange([]byte(l1.Sha512), []byte(l2.Sha512)) {
		*ret |= attrType
	}
}

/*
 * Returns the changed attributes for two database lines.
 *
 * Attributes are only compared if they exist in both database lines.
*/
func get_changed_attributes(l1 *DBTree_Line, l2 *DBTree_Line) (DB_ATTR_TYPE) {

	var ret DB_ATTR_TYPE = 0

	if ((DB_FTYPE & l1.Attr) != 0 && (DB_FTYPE & l2.Attr) != 0) && ((l1.Perm & S_IFMT) != (l2.Perm & S_IFMT)) {
		ret |= DB_FTYPE
		}
	//easy_function_compare(DB_LINKNAME,linkname,has_str_changed);
	easy_function_compare(DB_LINKNAME, l1, l2, &ret, has_str_changed)
	if ((DB_SIZEG & l1.Attr) != 0 && (DB_SIZEG & l2.Attr) != 0) && (l1.Size > l2.Size) {
		ret |= DB_SIZEG
		}
	//easy_compare(DB_SIZE,size);
	easy_compare(DB_SIZE, l1, l2, &ret)
	//easy_compare(DB_BCOUNT,bcount);
	easy_compare(DB_BCOUNT, l1, l2, &ret)
	//easy_compare(DB_PERM,perm);
	easy_compare(DB_PERM, l1, l2, &ret)
	//easy_compare(DB_UID,uid);
	easy_compare(DB_UID, l1, l2, &ret)
	//easy_compare(DB_GID,gid);
	easy_compare(DB_GID, l1, l2, &ret)
	//easy_compare(DB_ATIME,atime);
	//easy_compare(DB_MTIME,mtime);
	easy_compare(DB_MTIME, l1, l2, &ret)
	//easy_compare(DB_CTIME,ctime);
	easy_compare(DB_CTIME, l1, l2, &ret)
	//easy_compare(DB_INODE,inode);
	easy_compare(DB_INODE, l1, l2, &ret)
	//easy_compare(DB_LNKCOUNT,nlink);
	easy_compare(DB_LNKCOUNT, l1, l2, &ret)

	/*
	easy_md_compare(DB_MD5,md5,HASH_MD5_LEN);
	easy_md_compare(DB_SHA1,sha1,HASH_SHA1_LEN);
	easy_md_compare(DB_RMD160,rmd160,HASH_RMD160_LEN);
	easy_md_compare(DB_TIGER,tiger,HASH_TIGER_LEN);
	easy_md_compare(DB_SHA256,sha256,HASH_SHA256_LEN);
	easy_md_compare(DB_SHA512,sha512,HASH_SHA512_LEN);
	*/
	easy_md_compare(DB_SHA512, l1, l2, &ret, has_md_changed)

	/*
	#ifdef WITH_MHASH
	easy_md_compare(DB_CRC32,crc32,HASH_CRC32_LEN);
	easy_md_compare(DB_HAVAL,haval,HASH_HAVAL256_LEN);
	easy_md_compare(DB_GOST,gost,HASH_GOST_LEN);
	easy_md_compare(DB_CRC32B,crc32b,HASH_CRC32B_LEN);
	easy_md_compare(DB_WHIRLPOOL,whirlpool,HASH_WHIRLPOOL_LEN);
	#endif

	#ifdef WITH_ACL
	easy_function_compare(DB_ACL,acl,has_acl_changed);
	#endif
	#ifdef WITH_XATTR
	easy_function_compare(DB_XATTRS,xattrs,have_xattrs_changed);
	#endif
	#ifdef WITH_SELINUX
	easy_function_compare(DB_SELINUX,cntx,has_str_changed);
	#endif
	#ifdef WITH_E2FSATTRS
	easy_function_compare(DB_E2FSATTRS,e2fsattrs,has_e2fsattrs_changed);
	#endif
	error(255,"Debug, changed attributes for entry %s [%llx %llx]: %llx\n", l1->filename,l1->attr,l2->attr,ret);
	*/
	return ret
}

func Compare_node_by_path(n1 interface{}, n2 interface{}) (int) {

	if n1 == nil && n2 == nil {
		return 0
	} else if n1 != nil && n2 == nil {
		return 1
	} else if n1 == nil && n2 != nil {
		return -1
	}

	t1, _ := n1.(*Seltree)
	t2, _ := n2.(*Seltree)

	return strings.Compare(t1.Path, t2.Path)
}

func strlastslash(str string) string {

	sPath := []byte(str + "\x00")
	ldx := bytes.LastIndex(sPath, []byte("/"))

	//sPath[ldx + 1] = '\x00'
	if ldx == 0 {
		return string(sPath[:1])
	} else {
		return string(sPath[:ldx])
	}
}

func strrxtok(rx string) (string) {
	var p []byte = nil
	var i int = 0

	/* The following code assumes that the first character is a slash */
	var lastslash int = 1

	p = []byte(rx)
	p[0] = '/'

	for i = 1; i < len(p); i++ {
		switch p[i] {
		case '/':
			lastslash = i
			break
		case '(':
		case '^':
		case '$':
		case '*':
		case '[':
			i = len(p)
			break
		case '\\':
			p = append(p[:i], p[i + 1:]...)
			break
		default:
			break
		}
	}

	//p[lastslash] = '\0'
	ret := string(p[:lastslash])

	return ret
}

func strgetndirname(path string, depth int) string {

	var i = 0
	var idx = 0

	var sPath = []byte(path + "\x00")

	for idx = 0 ;; idx++ {

		if sPath[idx] == '/' {
			i++
		}

		if sPath[idx] == '\x00' {
			break
		}

		if i == depth {
			break
		}
	}

	/* If we ran out string return the whole string */
	if sPath[idx] == '\x00' {
		//return []byte(path)
		return path
	}

	return string(sPath[:idx])
}

func treedepth(node *Seltree) (int) {
	var r *Seltree = nil
	var depth int = 0

	for r = node; r != nil; r = r.Parent {
		depth++
	}

	return depth
}

func (node *Seltree) Copy_rule_ref(r *Rx_rule) {
	/*
	if( r != nil )
	{
		node->conf_lineno = r->conf_lineno;
		node->rx=strdup(r->rx);
	}
	else
	{
		node->conf_lineno = -1;
		node->rx=NULL;
	}
	*/
}

func isPathContain(containerPath, subPath string) bool {
	var lenC = len(containerPath)
	var lenS = len(subPath)

	if lenC < lenS {
		return false
	} else if lenC == lenS {
		if containerPath == subPath {
			return true
		} else {
			return false
		}
	} else {
		sContainerPath := []byte(containerPath)
		ls := bytes.LastIndexByte(sContainerPath, '/')

		sSubPath := []byte(subPath)

		return bytes.Equal(sContainerPath[:ls], sSubPath)
	}
}

/* This function returns a node with the same inode value as the 'file' */
/* The only place it is used is in add_file_to_tree() function */
func (tree *Seltree) get_seltree_inode(file *DBTree_Line, db uint64) (*Seltree) {
	var node *Seltree = nil
	//var tmp []byte = nil
	var r *list.Element = nil

	if tree == nil {
		return nil
	}

	/* found the match */
	if ((db == DB_NEW) && (tree.New_data != nil) && (file.Inode == tree.New_data.Inode)) ||
		((db == DB_OLD) && (tree.Old_data != nil) && (file.Inode == tree.Old_data.Inode)) {
		return tree
	}

	/* tmp is the directory of the file->filename */
	//tmp = strgetndirname(file.Filename,treedepth(tree)+1)
	treeDepth := treedepth(tree)
	pathDir := strgetndirname(file.Filename,  treeDepth + 1)
	for r = tree.Childs.Front(); r != nil; r = r.Next() {
		/* We are interested only in files with the same regexp specification */
		t, _ := r.Value.(*Seltree)

		if (len(pathDir) == len(file.Filename)) || isPathContain(t.Path, pathDir) {
			node = tree.get_seltree_inode(file, db)
			if node != nil {
				break
			}
		}
	}

	return node
}

func (tree *Seltree) get_seltree_node(path string) (node *Seltree) {

	node = nil
	//var r *list.List = nil
	var r *list.Element = nil

	//var tmp []byte = nil

	if tree == nil {
		return nil
	}

	if isPathContain(tree.Path, path) {
		return tree
	} else {
		treeDepth := treedepth(tree)
		pathDir := strgetndirname(path,  treeDepth + 1)
		for r = tree.Childs.Front(); r != nil ; r = r.Next() {
			t, _ := r.Value.(*Seltree)
			if isPathContain(t.Path, pathDir) {
				node = t.get_seltree_node(path)
				if node != nil {
					return node
				}
			}
		}
	}
	return nil
}

func (tree *Seltree) gen_seltree(rxlist *list.List, rxType byte) {

	var err error = nil
	var count = 0
	var r *list.Element = nil
	var rxtok = ""
	var curnode *Seltree = nil
	var rxc * Rx_rule = nil
	var rxtmp *regexp.Regexp = nil

	//fprintf(stdout, "[%s:%d:%s] === begin type:%c\n", __FILE__, __LINE__, __func__, type);

	for r = rxlist.Front(); r != nil; r = r.Next() {
		count++
		curr_rule, _ := r.Value.(*Rx_rule)

		rxtok = strrxtok(curr_rule.Rx)
		curnode = tree.get_seltree_node(rxtok)


		if curnode == nil {
			curnode = New_seltree_node(tree, rxtok,true, curr_rule)
			//var newNode = tree.get_seltree_node(rxtok)
			//fprintf(stdout, "[%s:%d:%s] rx:%s rxtok:%s newNode:%p \n", __FILE__, __LINE__, __func__, curr_rule->rx, rxtok, newNode);
			/*
			if(strcmp(rxtok,"/boot/grub") == 0)
			{
				newNode=get_seltree_node(tree,"/boot");
				fprintf(stdout, "[%s:%d:%s] bootNode:%p \n", __FILE__, __LINE__, __func__, newNode);
			}
			*/
		} else {
			//fprintf(stdout, "[%s:%d:%s] rx:%s rxtok:%s curnode:%p \n", __FILE__, __LINE__, __func__, curr_rule->rx, rxtok, curnode);
		}

		//error(240,"Handling %s with %c \"%s\" with node \"%s\"\n",rxtok,type,curr_rule->rx,curnode->path);

		/*
		if((rxtmp=pcre_compile(curr_rule->rx, PCRE_ANCHORED, &pcre_error, &pcre_erroffset, NULL)) == NULL)
		{
			error(0,_("Error in regexp '%s' at %i: %s\n"),curr_rule->rx, pcre_erroffset, pcre_error);
		}
		else
		*/
		rxtmp, err = regexp.CompilePOSIX(curr_rule.Rx)
		if err != nil {
			fmt.Printf("--- gen_seltree() compile curr_rule.Rx:%x err:%s\n", curr_rule.Rx, err.Error())
		} else {
			/* replace regexp text with regexp compiled */
			rxc = new(Rx_rule)

			/* and copy the rest */
			rxc.Rx = curr_rule.Rx
			rxc.Crx = rxtmp
			rxc.Attr = curr_rule.Attr
			rxc.Conf_lineno = curr_rule.Conf_lineno
			rxc.Restriction = curr_rule.Restriction

			switch rxType {
				//fprintf(stdout, "[%s:%d:%s] type:%c\n", __FILE__, __LINE__, __func__, type);
				case 's':
				{
					curnode.Sel_rx_lst.PushBack(rxc)
					break
				}
				case 'n':
				{
					curnode.Neg_rx_lst.PushBack(rxc)
					break
				}
				case 'e':{
					curnode.Equ_rx_lst.PushBack(rxc)
					break
				}
			}
		}
	}

	//fprintf(stdout, "[%s:%d:%s] === end type:%c count:%d\n", __FILE__, __LINE__, __func__, type, count);
}

func New_seltree_node(tree *Seltree, path string, isrx bool, r *Rx_rule) (*Seltree) {

	var node * Seltree = nil
	var parent *Seltree = nil
	var tmprxtok string = ""

	node = new(Seltree)
	node.Childs = list.New()
	node.Path = path
	node.Sel_rx_lst = list.New()
	node.Neg_rx_lst = list.New()
	node.Equ_rx_lst = list.New()
	node.Checked = 0
	node.Attr = 0
	node.New_data = nil
	node.Old_data = nil

	node.Copy_rule_ref(r)

	if tree != nil {
		tmprxtok = strrxtok(path)
		if isrx {
			parent = tree.get_seltree_node(tmprxtok)
		} else {
			dirn := strlastslash(path)
			parent = tree.get_seltree_node(dirn)
		}

		if parent == nil {
			if isrx {
				parent = New_seltree_node(tree, tmprxtok, isrx, r)
			} else {
				dirn := strlastslash(path)
				parent = New_seltree_node(tree, dirn,isrx,r)
			}
		}

		list_sorted_insert(parent.Childs, node, Compare_node_by_path)

		node.Parent = parent
	} else {
		node.Parent = nil
	}
	return node
}

func (tree *Seltree) Print_tree_rx(prefix string) {
	var r *list.Element = nil
	var rxc *Rx_rule = nil
	var newSet = true
	var inPrefix = ""

	fmt.Printf("%s--%s\n", prefix, tree.Path)

	newSet = true
	for r = tree.Sel_rx_lst.Front(); r != nil; r = r.Next() {
		rxc, _ = r.Value.(*Rx_rule)
		if newSet {
			inPrefix = prefix + "  " + "\t"
			newSet = false
		}
		fmt.Printf("%s [Sel_rx: %d %s]\n", inPrefix, rxc.Conf_lineno, rxc.Rx)
	}
	//fmt.Printf("%s\n", inPrefix)

	newSet = true
	for r = tree.Equ_rx_lst.Front(); r != nil; r = r.Next() {
		rxc, _ = r.Value.(*Rx_rule)
		if newSet {
			inPrefix = prefix + "  " + "\t"
			newSet = false
		}
		fmt.Printf("%s [Equ_rx: %d %s]\n", inPrefix, rxc.Conf_lineno, rxc.Rx)
	}
	//fmt.Printf("%s\n", inPrefix)

	newSet = true
	for r = tree.Neg_rx_lst.Front(); r != nil; r = r.Next() {
		rxc, _ = r.Value.(*Rx_rule)
		if newSet {
			inPrefix = prefix + "  " + "\t"
			newSet = false
		}
		fmt.Printf("%s [Neg_rx: %d %s]\n", inPrefix, rxc.Conf_lineno, rxc.Rx)
	}
	//fmt.Printf("%s\n", inPrefix)

	for r = tree.Childs.Front(); r != nil; r = r.Next() {
		t, _ := r.Value.(*Seltree)

		t.Print_tree_rx(prefix + "  " + prefix)
	}
}

func Gen_tree(srxlist, nrxlist, erxlist *list.List) (*Seltree) {

	var tree = New_seltree_node(nil, "/", false, nil)

	tree.gen_seltree(srxlist,'s')
	tree.gen_seltree(nrxlist,'n')
	//tree.gen_seltree(erxlist,'e')

	//tree.Print_tree_rx("\t|--")

	return tree
}

func get_file_type(mode mode_t) (RESTRICTION_TYPE) {

	switch mode & S_IFMT {
		case S_IFREG:
			return RESTRICTION_FT_REG
		case S_IFDIR:
			return RESTRICTION_FT_DIR
			/*
		#ifdef S_IFIFO
		case S_IFIFO: return RESTRICTION_FT_FIFO;
		#endif
			*/
		case S_IFLNK:
			return RESTRICTION_FT_LNK
		case S_IFBLK:
			return RESTRICTION_FT_BLK
		case S_IFCHR:
			return RESTRICTION_FT_CHR
		/*
		#ifdef S_IFSOCK
		case S_IFSOCK: return RESTRICTION_FT_SOCK;
		#endif
		#ifdef S_IFDOOR
		case S_IFDOOR: return RESTRICTION_FT_DOOR;
		#endif
		#ifdef S_IFDOOR
		case S_IFPORT: return RESTRICTION_FT_PORT;
		#endif
		*/
		default:
			return RESTRICTION_NULL
	}
}

func Check_list_for_match( rxrlist *list.List, text string, attr *DB_ATTR_TYPE, file_type RESTRICTION_TYPE) (int) {

	var retval = 1
	var isOk = false
	//var err error
	var r *list.Element = nil
	var rxc *Rx_rule = nil

	for r = rxrlist.Front(); r != nil; r = r.Next() {

		rxc, isOk = r.Value.(*Rx_rule)
		if !isOk {
			//fmt.Printf("--- Check_list_for_match() %s got incorrect rxc Type.\n", text)
			continue
		}

		ret := rxc.Crx.FindSubmatch([]byte(text))
		retLen := len(ret)

		if retLen > 0 {
			if rxc.Crx.MatchString(text) { // full match
				//fmt.Printf("--- %s matches rule:%s from line:%d: \n",text, rxc.Rx, rxc.Conf_lineno)
				if rxc.Restriction == 0 || (file_type & rxc.Restriction) != 0 {
					*attr = rxc.Attr
					//fmt.Printf("--- %s matches restriction (%d) for rule:%s from line:%d: \n",text, rxc.Restriction, rxc.Rx, rxc.Conf_lineno)
					return 0
				} else {
					//fmt.Printf("--- %s doesn't match restriction (%d) for rule:%s from line:%d: \n",text, rxc.Restriction, rxc.Rx, rxc.Conf_lineno)
					retval = -1
				}

			} else { //PCRE_ERROR_PARTIAL
				//fmt.Printf("--- %s PARTIAL match rule:%s from line:%d: \n",text, rxc.Rx, rxc.Conf_lineno)
				retval = -1
			}
		} else {
			//fmt.Printf("--- %s doesn't match rule:%s from line:%d: \n",text, rxc.Rx, rxc.Conf_lineno)
		}
	}
	return retval
}

/*
 * Function check_node_for_match()
 * calls itself recursively to go to the top and then back down.
 * uses check_list_for_match()
 * returns:
 * 0,  if a negative rule was matched
 * 1,  if a selective rule was matched
 * 2,  if a equals rule was matched
 * retval if no rule was matched.
 * retval&3 if no rule was matched and first in the recursion
 * to keep state revat is orred with:
 * 4,  matched deeper on equ rule
 * 8,  matched deeper on sel rule
 *16,  this is a recursed call
 */
func Check_node_for_match( node *Seltree, text string, perm mode_t, retval int, attr *DB_ATTR_TYPE) (int) {

	var top int = 0
	var file_type RESTRICTION_TYPE = 0

	if node == nil {
		return retval
	}

	file_type = get_file_type(perm)

	/*
	if text == "/file_a" {
		fmt.Printf("+++ Check_node_for_match() text:%s perm:%x attr:0x%x retval:0x%x\n", text, perm, *attr, retval)
	}
	*/

	/* if this call is not recursive we check the equals list and we set top *
	* and retval so we know following calls are recursive */
	if ( retval & 16 ) == 0 {
		top = 1
		retval |= 16

		cm := Check_list_for_match(node.Equ_rx_lst, text, attr, file_type)
		/*
		if text == "/file_a" {
			fmt.Printf("+++ Check_node_for_match() text:%s perm:%x attr:0x%x retval:0x%x cm:%d \n", text, perm, *attr, retval, cm)
		}
		*/

		switch cm {
		case 0:
			{
				//error(220, "check_node_for_match: equal match for '%s'\n", text);
				//fmt.Printf("--- Check_node_for_match(): equal match for '%s'\n", text)
				retval |= 2|4
				break
			}
		case -1:
			{
				if S_ISDIR(perm) && node.get_seltree_node(text) == nil {
				//error(220, "check_node_for_match: creating new seltree node for '%s'\n", text);
				//fmt.Printf("Check_node_for_match: creating new seltree node for '%s'\n", text)
				New_seltree_node(node, text, false, nil)
				}
				break
			}
		}
	}

	/*
	if text == "/file_a" {
		fmt.Printf("+++ Check_node_for_match() text:%s perm:%x attr:0x%x retval:0x%x\n", text, perm, *attr, retval)
	}
	*/

	/* We'll use retval to pass information on whether to recurse
	* the dir or not */


	/* If 4 and 8 are not set, we will check for matches */
	if (retval & (4|8)) == 0 {
		cm := Check_list_for_match(node.Sel_rx_lst, text, attr, file_type)
		/*
		if text == "/file_a" {
			fmt.Printf("+++ Check_node_for_match() text:%s perm:%x attr:0x%x retval:0x%x cm:%d \n", text, perm, *attr, retval, cm)
		}
		*/
		switch cm {
		case 0:
			{
				//error(220, "check_node_for_match: selective match for '%s'\n", text);
				//fmt.Printf("check_node_for_match: selective match for '%s'\n", text)
				retval |= 1|8
				break
			}
		case -1:
			{
				if S_ISDIR(perm) && node.get_seltree_node(text) == nil {
					//error(220, "check_node_for_match: creating new seltree node for '%s'\n", text);
					//fmt.Printf("check_node_for_match: creating new seltree node for '%s'\n", text)
					New_seltree_node(node, text, false, nil)
				}
				break
			}
		}
	}

	/*
	if text == "/file_a" {
		fmt.Printf("+++ Check_node_for_match() text:%s perm:%x attr:0x%x retval:0x%x\n", text, perm, *attr, retval)
	}
	*/
	/* Now let's check the ancestors */
	retval = Check_node_for_match(node.Parent,text, perm, retval,attr)

	/*
	if text == "/file_a" {
		fmt.Printf("+++ Check_node_for_match() text:%s perm:%x attr:0x%x retval:0x%x\n", text, perm, *attr, retval)
	}
	*/

	/* Negative regexps are the strongest so they are checked last */
	/* If this file is to be added */
	if retval != 0 {
		if Check_list_for_match(node.Neg_rx_lst, text, attr, file_type) == 0 {
			//error(220, "check_node_for_match: negative match for '%s'\n", text);
			//fmt.Printf("check_node_for_match: negative match for '%s'\n", text)
			retval = 0
		}
	}

	/*
	if text == "/file_a" {
		fmt.Printf("+++ Check_node_for_match() text:%s perm:%x attr:0x%x retval:0x%x\n", text, perm, *attr, retval)
	}
	*/
	/* Now we discard the info whether a match was made or not *
	* and just return 0,1 or 2 */
	if top != 0 {
		retval &= 3
	}
	return retval
}

func (tree *Seltree) Check_rxtree(filename string, attr *DB_ATTR_TYPE, perm mode_t) (int) {

	var idx = 0
	var retval = 0
	var pnode *Seltree = nil
	var parentname = []byte(filename)
	var strParentname string

	idx = bytes.LastIndexByte(parentname, '/')

	if idx != 0 {
		strParentname = string(parentname[:idx])
	} else {
		/*
		if parentname[1] != '\x00' {
			// we are in the root dir
			parentname[1] = '\x00'
		}
		*/
		strParentname = "/"
	}

	/*
	if(conf->limit!=NULL)
	{
		retval=pcre_exec(conf->limit_crx, NULL, filename, strlen(filename), 0, PCRE_PARTIAL_SOFT, NULL, 0);
		if (retval >= 0)
		{
		error(220, "check_rxtree: %s does match limit: %s\n", filename, conf->limit);
		}
		else if (retval == PCRE_ERROR_PARTIAL)
		{
		error(220, "check_rxtree: %s does PARTIAL match limit: %s\n", filename, conf->limit);
		if(S_ISDIR(perm) && get_seltree_node(tree,filename)==NULL)
		{
		error(220, "check_rxtree: creating new seltree node for '%s'\n", filename);
		new_seltree_node(tree,filename,0,NULL);
		}
		return -1;
		}
		else
		{
		error(220, "check_rxtree: %s does NOT match limit: %s\n", filename, conf->limit);
		return -2;
		}
	}
	*/

	if filename == "/folder_b/file_ba" {
		fmt.Printf("+++ Check_rxtree() filename:%s \n", filename)
	}
	pnode = tree.get_seltree_node(strParentname)

	*attr = 0
	retval = Check_node_for_match(pnode,filename, perm, 0,attr)

	return retval
}

func strip_dbline(line *DBTree_Line) {

	var attr DB_ATTR_TYPE = line.Attr

	/* filename is always needed, hence it is never stripped */
	if (attr & DB_LINKNAME) == 0 {
		line.Linkname = ""
	}
	/* permissions are always needed for file type detection, hence they are
	* never stripped */
	if (attr & DB_UID) == 0 {
		line.Uid = 0
	}
	if (attr & DB_GID) == 0 {
		line.Gid = 0
	}
	/*
	if (attr & DB_ATIME) == 0 {
		lineatime=0;
	}
	*/
	if (attr & DB_CTIME) == 0 {
		line.Ctime = ""
	}
	if (attr & DB_MTIME) == 0 {
		line.Mtime = ""
	}
	/* inode is always needed for ignoring changed filename, hence it is
	* never stripped */
	if (attr & DB_LNKCOUNT) == 0 {
		line.Nlink = 0
	}
	if (attr & DB_SIZE) == 0 && (attr & DB_SIZEG) == 0 {
		line.Size = 0
	}
	if (attr & DB_BCOUNT) == 0 {
		line.Bcount = 0
	}

	/*
		if (attr & DB_MD5) == 0 {
			checked_free(line->md5);
		}
		if(!(attr & DB_SHA1))
		{
		checked_free(line->sha1);
		}
		if(!(attr & DB_RMD160))
		{
		checked_free(line->rmd160);
		}
		if(!(attr & DB_TIGER))
		{
		checked_free(line->tiger);
		}
		if(!(attr & DB_HAVAL))
		{
		checked_free(line->haval);
		}
		if(!(attr & DB_CRC32))
		{
		checked_free(line->crc32);
		}
		#ifdef WITH_MHASH
		if(!(attr & DB_CRC32B))
		{
		checked_free(line->crc32b);
		}
		if(!(attr & DB_GOST))
		{
		checked_free(line->gost);
		}
		if(!(attr & DB_WHIRLPOOL))
		{
		checked_free(line->whirlpool);
		}
		#endif
	if(!(attr & DB_SHA256))
	{
	checked_free(line->sha256);
	}
	*/
	if (attr & DB_SHA512) == 0 {
		line.Sha512 = ""
	}
	/*
	#ifdef WITH_ACL
	if(!(attr & DB_ACL))
	{
	if (line->acl)
	{
	free(line->acl->acl_a);
	free(line->acl->acl_d);
	}
	checked_free(line->acl);
	}
	#endif
	#ifdef WITH_XATTR
	if(!(attr & DB_XATTRS))
	{
	if (line->xattrs)
	free(line->xattrs->ents);
	checked_free(line->xattrs);
	}
	#endif
	#ifdef WITH_SELINUX
	if(!(attr & DB_SELINUX))
	{
	checked_free(line->cntx);
	}
	#endif
	*/
	/* e2fsattrs is stripped within e2fsattrs2line in do_md */
}

/*
 * add_file_to_tree
 * db = which db this file belongs to
 * attr attributes to add
 */
func (tree *Seltree) add_file_to_tree(file *DBTree_Line, db uint64, attr DB_ATTR_TYPE, conf *DB_config) {

	var node *Seltree = nil
	var localignorelist DB_ATTR_TYPE = 0

	var ignored_added_attrs, ignored_removed_attrs, ignored_changed_attrs DB_ATTR_TYPE

	node = tree.get_seltree_node(file.Filename)

	if node == nil {
		node = New_seltree_node(tree,file.Filename,false, nil)
	}

	if file == nil {
		fmt.Printf("--- add_file_to_tree was called with NULL db_line\n")
	}

	/* add note to this node which db has modified it */
	node.Checked |= db

	node.Attr = attr

	//fprintf(stdout, "[%s:%d:%s] db:%d file->attr:%x \n", __FILE__, __LINE__, __func__, db, file->attr);
	strip_dbline(file)

	switch db {
		case DB_OLD:
		{
			node.Old_data = file
			break
		}
		case DB_NEW:
		{
			node.New_data = file
			break
		}
		case DB_OLD | DB_NEW:
		{
			node.New_data = file
			if (conf.Action & DO_INIT) != 0 {
				node.Checked |= NODE_FREE
			} else {
				//free_db_line(node->new_data);
				//free(node->new_data);
				//node->new_data=NULL;
				node.New_data = nil
			}
			return;
		}
	}
	/* We have a way to ignore some changes... */
	ignored_added_attrs = 0 //get_special_report_group("report_ignore_added_attrs");
	ignored_removed_attrs = 0 //get_special_report_group("report_ignore_removed_attrs");
	ignored_changed_attrs = 0 //get_special_report_group("report_ignore_changed_attrs");

	//fprintf(stdout, "[%s:%d:%s] +++ 0x%x 0x%x 0x%x \n", __FILE__, __LINE__, __func__, ignored_added_attrs, ignored_removed_attrs, ignored_changed_attrs);

	if (node.Checked & DB_OLD) != 0 && (node.Checked & DB_NEW) != 0 {
		//fprintf(stdout, "[%s:%d:%s] ---------------------------------- \n", __FILE__, __LINE__, __func__);

		if ((node.Old_data.Attr & (^(node.New_data.Attr)) & (^ignored_removed_attrs)) |
			((^(node.Old_data.Attr)) & node.New_data.Attr & (^ignored_added_attrs))) != 0 {
			fmt.Printf("Entry %s in databases has different attributes: %x %x\n",
				node.Old_data.Filename, node.Old_data.Attr, node.New_data.Attr)
		}

		node.Changed_attrs = get_changed_attributes(node.Old_data,node.New_data)
		/* Free the data if same else leave as is for report_tree */
		if ((^ignored_changed_attrs) & node.Changed_attrs) == DB_ATTR_TYPE(RETOK) {
			/* FIXME this messes up the tree on SunOS. Don't know why. Fix
			needed badly otherwise we leak memory like hell. */

			node.Changed_attrs = 0
			node.Old_data = nil

			/* Free new data if not needed for write_tree */
			if conf.Action & DO_INIT != 0 {
				node.Checked |= NODE_FREE
			} else {
				node.New_data = nil
			}
			return
		}
	}

	/* Do verification if file was moved only if we are asked for it.
	* old and new data are NULL only if file present in both DBs
	* and has not been changed.
	*/
	if ((node.Old_data != nil) || (node.New_data != nil)) && ((file.Attr & DB_CHECKINODE) != 0) {
		//fprintf(stdout, "[%s:%d:%s] ---------------------------------- \n", __FILE__, __LINE__, __func__);
		/* Check if file was moved (same inode, different name in the other DB)*/
		var oldData *DBTree_Line = nil
		var newData *DBTree_Line = nil
		var moved_node *Seltree = nil

		var dbv uint64 = 0
		if db == DB_OLD {
			dbv = DB_NEW
		} else {
			dbv = DB_OLD
		}

		moved_node = tree.get_seltree_inode(file, dbv)
		if !(moved_node == nil || moved_node == node) {
			/* There's mo match for inode or it matches the node with the same name.
			* In first case we don't have a match to compare with.
			* In the second - we already compared those files. */
			if db == DB_NEW {
				newData = node.New_data
				oldData = moved_node.Old_data
			} else {
				newData = moved_node.New_data
				oldData = node.Old_data
			}

			localignorelist = (oldData.Attr ^ newData.Attr) & (^(DB_NEWFILE|DB_RMFILE|DB_CHECKINODE))

			if localignorelist != 0 {
				fmt.Printf("Ignoring moved entry (\"%s\" [%x] => \"%s\" [%x]) due to different attributes: %x\n",
					oldData.Filename, oldData.Attr, newData.Filename, newData.Attr, localignorelist)
			} else {
				/* Free the data if same else leave as is for report_tree */
				if (get_changed_attributes(oldData, newData) & (^(ignored_changed_attrs|DB_CTIME))) == DB_ATTR_TYPE(RETOK) {
					//node->checked |= db==DB_NEW ? NODE_MOVED_IN : NODE_MOVED_OUT;
					//moved_node->checked |= db==DB_NEW ? NODE_MOVED_OUT : NODE_MOVED_IN;
					if db == DB_NEW {
						node.Checked |= NODE_MOVED_IN
						moved_node.Checked |= NODE_MOVED_OUT
					} else {
						node.Checked |= NODE_MOVED_OUT
						moved_node.Checked |= NODE_MOVED_IN
					}
					fmt.Printf("Entry was moved: %s [%x] => %s [%x]\n", oldData.Filename , oldData.Attr, newData.Filename, newData.Attr)
				} else {
					fmt.Printf("Ignoring moved entry (\"%s\" => \"%s\") because the entries mismatch\n", oldData.Filename, newData.Filename)
				}
			}
		}
	}

	if (db == DB_NEW) && (node.New_data != nil) && ((file.Attr & DB_NEWFILE) != 0) {
		//fprintf(stdout, "[%s:%d:%s] ---------------------------------- \n", __FILE__, __LINE__, __func__);
		node.Checked |= NODE_ALLOW_NEW
	}

	if (db == DB_OLD) && (node.Old_data != nil) && ((file.Attr & DB_RMFILE) != 0) {
		//fprintf(stdout, "[%s:%d:%s] ---------------------------------- \n", __FILE__, __LINE__, __func__);
		node.Checked |= NODE_ALLOW_RM
	}
}

func (tree * Seltree) Populate_tree(conf *DB_config) {

	var initdbwarningprinted = false
	var node *Seltree = nil
	var newTreeLine *DBTree_Line = nil
	var oldTreeLine *DBTree_Line = nil
	var add int  = 0
	var attr DB_ATTR_TYPE = 0

	/* With this we avoid unnecessary checking of removed files. */
	if (conf.Action & DO_INIT) != 0 {
		initdbwarningprinted = true
	}

	if (conf.Action & DO_DIFF) != 0 {
		for _, db_line := range conf.JdbNew.Jdb.FilesDB {
			/* FIXME add support config checking at this stage
			config check = add only those files that match config rxs
			make this configurable
			Only configurability is not implemented.
			*/
			/* This is needed because check_rxtree assumes there is a parent
			for the node for old->filename */
			newTreeLine = db_line.ToDBTreeLine()

			if db_line.Filename == "/folder_b/file_ba" {
				fmt.Printf("+++ Populate_tree() DB_NEW new.Filename:%s \n", newTreeLine.Filename)
			}

			node = tree.get_seltree_node(newTreeLine.Filename)

			if node == nil {
				node = New_seltree_node(tree, newTreeLine.Filename, false, nil)
			}

			add = tree.Check_rxtree(newTreeLine.Filename, &attr, newTreeLine.Perm)
			if add > 0 {
				tree.add_file_to_tree(newTreeLine, DB_NEW, attr, conf)
			}
		}
	}
	//tree.PrintTreeInfo(1, 0)

	if((conf.Action & DO_INIT) != 0) || ((conf.Action & DO_COMPARE) != 0) {
		/* FIXME  */
		newTreeLine = nil
		for _, db_line := range conf.JdbDisk.Jdb.FilesDB {
			newTreeLine = db_line.ToDBTreeLine()

			if db_line.Filename == "/folder_b/folder_ba" {
				fmt.Printf("DB_DISK filename:%s attr:0x%x\n", newTreeLine.Filename, newTreeLine.Attr)
			}

			tree.add_file_to_tree(newTreeLine, DB_NEW, attr, conf)

			{
				node = tree.get_seltree_node("/folder_b/folder_ba")
				if node == nil {
					fmt.Printf("-------------- get folder_ba fail\n")
				} else {
					fmt.Printf("DB_DISK new:%s tree %s checked:0x%x\n", newTreeLine.Filename, node.Path, node.Checked)
				}
			}
		}
	}

	if((conf.Action & DO_COMPARE) != 0) || ((conf.Action & DO_DIFF) != 0) {
		//while((old = db_readline(DB_OLD)) != NULL)
		for _, db_line := range conf.JdbOld.Jdb.FilesDB {
			/* This is needed because check_rxtree assumes there is a parent
			for the node for old->filename */
			oldTreeLine = db_line.ToDBTreeLine()

			node = tree.get_seltree_node(oldTreeLine.Filename)
			if node == nil {
				node = New_seltree_node(tree,oldTreeLine.Filename,false, nil)
			}

			add = tree.Check_rxtree(oldTreeLine.Filename, &attr, oldTreeLine.Perm)

			if add > 0 {
				tree.add_file_to_tree(oldTreeLine, DB_OLD, attr, conf)
			} else if (conf.Limit != nil) && (add < 0) {
				tree.add_file_to_tree(oldTreeLine, DB_OLD|DB_NEW , attr, conf)
			} else {
				if !initdbwarningprinted {
					fmt.Printf("WARNING: Old db contains a entry that shouldn\\'t be there, run --init or --update\n")
					initdbwarningprinted = true
				}
			}
		}
	}

	/*
	if(conf->action & DO_INIT)
	{
		write_tree(tree);
	}
	*/
}



