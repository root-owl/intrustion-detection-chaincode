package aide

import (
	"container/list"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	report_top_format = "\n\n---------------------------------------------------\n%s:\n---------------------------------------------------\n"
)


func report_attrs(attrs DB_ATTR_TYPE) string {

	var attrs_string = []string { "filename", "l", "p", "u", "g", "s", "a", "c", "m", "i", "b", "n",
		"md5", "sha1", "rmd160", "tiger", "crc32", "haval", "gost", "crc32b",
		"attr", "acl", "bsize", "rdev", "dev", "checkmask", "S", "I", "ANF",
		"ARF", "sha256", "sha512", "selinux", "xattrs", "whirlpool", "ftype",
		"e2fsattrs" }

	var indcator DB_ATTR_TYPE = 1
	var sRet string

	var j = 0
	for i, v := range attrs_string {
		if ((indcator << uint64(i)) & attrs) != 0 {
			if j != 0 {
				sRet += "+"
			}
			sRet += v
		}
	}

	return sRet
}

func get_file_type_char(mode mode_t) byte {

	switch mode & S_IFMT {
	case S_IFREG:
		return 'f'
	case S_IFDIR:
		return 'd'
		/*
	#ifdef S_IFIFO
	case S_IFIFO:
	return 'p';
	#endif
		*/
	case S_IFLNK:
		return 'l'
	case S_IFBLK:
		return 'b'
	case S_IFCHR:
		return 'c'
		/*
	#ifdef S_IFSOCK
	case S_IFSOCK:
	return 's';
	#endif
	#ifdef S_IFDOOR
	case S_IFDOOR:
	return 'D';
	#endif
	#ifdef S_IFPORT
	case S_IFPORT:
	return 'P';
	#endif
		*/
	default:
		return '?'
	}
}

func get_file_type_string(mode mode_t) string {
	switch (mode & S_IFMT) {
	case S_IFREG:
		return "File"
	case S_IFDIR:
		return "Directory"
		/*
	#ifdef S_IFIFO
	case S_IFIFO:
	return _("FIFO");
	#endif
		*/
	case S_IFLNK:
		return "Link"
	case S_IFBLK:
		return "Block device"
	case S_IFCHR:
		return "Character device"
		/*
	#ifdef S_IFSOCK
	case S_IFSOCK:
	return _("Socket");
	#endif
	#ifdef S_IFDOOR
	case S_IFDOOR:
	return _("Door");
	#endif
	#ifdef S_IFPORT
	case S_IFPORT:
	return _("Port");
	#endif
		*/
	case 0:
		return ""
	default:
		return "Unknown file type"
	}
}

func easy_string(s string) []byte {
	/*
		#define easy_string(s) \
	l = strlen(s)+1; \
	*values[0] = malloc(l * sizeof (char)); \
	snprintf(*values[0], l, "%s",s);
	 */
	return []byte(s + "\x00")
}

func easy_md(attr DB_ATTR_TYPE, line *DBTree_Line, conf *DB_config) []byte {
	/*

	#define easy_md(a,b,c) \
	} else if (a&attr) { \
	if (conf->report_base16) { \
	*values[0] = byte_to_base16(line->b, c); \
	} else { \
	*values[0] = encode_base64(line->b, c); \
	}

	 */

	var dst = []byte{}
	switch attr & line.Attr {
	case DB_sha512:
		{
			if conf.Report_base16 != 0 {
				var src = []byte(line.Sha512)
				dst = make([]byte, HASH_SHA512_LEN)
				hex.Encode(dst, src)
			} else {
				dst = encode_base64([]byte(line.Sha512), HASH_SHA512_LEN)
			}
			break
		}
	}
	return dst
}

func easy_number(attr DB_ATTR_TYPE, line *DBTree_Line) []byte {

	/*
		#define easy_number(a,b,c) \
	} else if (a&attr) { \
	l = 2+floor(line->b?log10(line->b):0); \
	*values[0] = malloc(l * sizeof (char)); \
	snprintf(*values[0], l, c,line->b);
	*/

	var kv = attr & line.Attr
	if kv == DB_BCOUNT {
		return []byte(fmt.Sprintf("%d", line.Bcount))
	} else if kv == DB_UID {
		return []byte(fmt.Sprintf("%d", line.Uid))
	} else if kv == DB_GID {
		return []byte(fmt.Sprintf("%d", line.Gid))
	} else if kv == DB_INODE {
		return []byte(fmt.Sprintf("%d", line.Inode))
	} else if kv == DB_LNKCOUNT {
		return []byte(fmt.Sprintf("%d", line.Nlink))
	} else if kv == DB_SIZE || kv == DB_SIZEG || (kv == (DB_SIZE|DB_SIZEG)) {
		return []byte(fmt.Sprintf("%d", line.Size))
	} else {
		return []byte{}
	}

}

func easy_time(attr DB_ATTR_TYPE, line *DBTree_Line) []byte {

	/*
	#define easy_time(a,b) \
	} else if (a&attr) { \
	*values[0] = malloc(time_string_len * sizeof (char));  \
	strftime(*values[0], time_string_len, time_format, localtime(&(line->b)));

	*/

	switch attr & line.Attr {
	case DB_MTIME:
		{
			return []byte(line.Mtime)
			break
		}
	case DB_CTIME:
		{
			return []byte(line.Ctime)
			break
		}
	}
	return []byte{}
}

func get_attribute_values(attr DB_ATTR_TYPE, line *DBTree_Line, conf *DB_config) (num int, values [][]byte) {
	//int l;

	if line == nil || (line.Attr & attr) == 0 {
		return 0, nil
		/*
		*values = NULL;
		return 0;
		#ifdef WITH_ACL
		} else if (DB_ACL&attr) {
		return acl2array(line->acl, &*values);
		#endif
		#ifdef WITH_XATTR
		} else if (DB_XATTRS&attr) {
		return xattrs2array(line->xattrs, &*values);
		#endif
		*/
	} else {
		//*values = malloc(1 * sizeof (char*));
		values := make([][]byte, 1)

		if (DB_FTYPE & attr) != 0 {
			values[0] = easy_string(get_file_type_string(line.Perm))
		} else if (DB_LINKNAME & attr) != 0 {
			//easy_string(line->linkname)
			values[0] = easy_string(line.Linkname)
		} else if ((DB_SIZE|DB_SIZEG) & attr) != 0 {
			values[0] = easy_number((DB_SIZE|DB_SIZEG), line)
		} else if (DB_PERM & attr) != 0 {
			values[0] = perm_to_char(line.Perm)
		} else if (DB_MTIME & attr) != 0 {

			//easy_time(DB_ATIME,atime)
			values[0] = easy_time(DB_MTIME, line)
		} else if (DB_CTIME & attr) != 0 {
			values[0] = easy_time(DB_CTIME, line)
		} else if (DB_BCOUNT & attr) != 0 {
			values[0] = easy_number(DB_BCOUNT, line)
		} else if (DB_UID & attr) != 0 {
			values[0] = easy_number(DB_UID, line)
		} else if (DB_GID & attr) != 0 {
			values[0] = easy_number(DB_GID, line)
		} else if (DB_INODE & attr) != 0 {
			values[0] = easy_number(DB_INODE, line)
		} else if (DB_LNKCOUNT & attr) != 0 {
			values[0] = easy_number(DB_LNKCOUNT, line)
		} else if (DB_sha512 & attr) != 0 {
			/*
			easy_md(DB_MD5,md5,HASH_MD5_LEN)
			easy_md(DB_SHA1,sha1,HASH_SHA1_LEN)
			easy_md(DB_RMD160,rmd160,HASH_RMD160_LEN)
			easy_md(DB_TIGER,tiger,HASH_TIGER_LEN)
			easy_md(DB_SHA256,sha256,HASH_SHA256_LEN)
			*/
			values[0] = easy_md(DB_SHA512, line, conf)
			/*
				#ifdef WITH_MHASH
				easy_md(DB_CRC32,crc32,HASH_CRC32_LEN)
				easy_md(DB_HAVAL,haval,HASH_HAVAL256_LEN)
				easy_md(DB_GOST,gost,HASH_GOST_LEN)
				easy_md(DB_CRC32B,crc32b,HASH_CRC32B_LEN)
				easy_md(DB_WHIRLPOOL,whirlpool,HASH_WHIRLPOOL_LEN)
				#endif
				#ifdef WITH_SELINUX
				} else if (DB_SELINUX&attr) {
				easy_string(line->cntx)
				#endif
				#ifdef WITH_E2FSATTRS
				} else if (DB_E2FSATTRS&attr) {
				*values[0]=e2fsattrs2string(line->e2fsattrs, 0);
				#endif
				*/
		} else {
			values[0] = easy_string("unknown attribute")
		}
		return 1, values
	}
}

func (node *Seltree) print_line(conf *DB_config) {

	var summary_attributes = []DB_ATTR_TYPE {
		DB_FTYPE,
		DB_LINKNAME,
		DB_SIZE|DB_SIZEG,
		DB_BCOUNT,
		DB_PERM,
		DB_UID,
		DB_GID,
		DB_ATIME,
		DB_MTIME,
		DB_CTIME,
		DB_INODE,
		DB_LNKCOUNT,
		DB_HASHES}

	var summary_char = []byte{ '!' ,'l', '>', 'b', 'p', 'u', 'g', 'a', 'm', 'c', 'i', 'n', 'C'}

	if conf.Summarize_changes == 1 {
		var i int
		var length = len(summary_attributes)
		var summary = make([]byte, length + 1)

		/*
		if node.Path == "/file_a" {
			fmt.Printf("\n[%s] checked:0x%x attr:0x%x ch_attr:0x%x fAttr:0x%x cAttr:0x%x rAttr:0x%x aAttr:0x%x",
				node.Path, node.Checked, node.Attr, node.Changed_attrs, conf.Forced_attrs, conf.Ignored_changed_attrs,
				conf.Ignored_removed_attrs, conf.Ignored_added_attrs)
			fmt.Printf("\n[%s - old] size:%d attr:0x%x\n ", node.Path, node.Old_data.Size, node.Old_data.Attr)
			fmt.Printf("\n[%s - new] size:%d attr:0x%x\n ", node.Path, node.New_data.Size, node.New_data.Attr)
		}
		*/


		if (node.Checked & (NODE_ADDED|NODE_REMOVED)) != 0 {
			var mt mode_t = 0
			if (node.Checked & NODE_REMOVED) != 0 {
				mt = node.Old_data.Perm
			} else {
				mt = node.New_data.Perm
			}
			summary[0] = get_file_type_char(mt)
			for i = 1; i < length; i++ {
				if (node.Checked & NODE_ADDED) != 0 {
					summary[i] = '+'
				} else {
					summary[i] = '-'
				}
			}
		} else if (node.Checked & NODE_CHANGED) != 0 {
			var c, u, a, r, g, s byte

			for i = 0; i < length; i++ {
				c = summary_char[i]
				r = '-'; a = '+'; g = ':'; u = '.'; s = ' '
				switch i {
				case 0:
					summary[i] = get_file_type_char(node.New_data.Perm)
					continue
				case 2:
					if (summary_attributes[i] & (node.Changed_attrs & (^(conf.Ignored_changed_attrs)))) != 0 &&
						(node.Old_data.Size > node.New_data.Size) {
						c = '<'
						}
					u = '='
					break
				}

				if (summary_attributes[i] & node.Changed_attrs & (conf.Forced_attrs|(^(conf.Ignored_changed_attrs)))) != 0 {
					summary[i] = c
				} else if (summary_attributes[i] & ((node.Old_data.Attr) & (^(node.New_data.Attr)) & ((conf.Forced_attrs) | (^(conf.Ignored_removed_attrs))))) != 0 {
					summary[i] = r
				} else if (summary_attributes[i] & (^(node.Old_data.Attr)) & node.New_data.Attr & (conf.Forced_attrs | (^(conf.Ignored_added_attrs)))) != 0 {
					summary[i] = a
				} else if (summary_attributes[i] & (
						(node.Old_data.Attr & (^(node.New_data.Attr)) & (conf.Ignored_removed_attrs)) |
						((^(node.Old_data.Attr)) & node.New_data.Attr & (conf.Ignored_added_attrs)) |
						((node.Old_data.Attr) & (node.New_data.Attr) & (conf.Ignored_changed_attrs) ) ) ) != 0 {
							summary[i] = g
				} else if (summary_attributes[i] & ((node.Old_data.Attr) & (node.New_data.Attr))) != 0 {
					summary[i] = u
				} else {
					summary[i] = s
				}
			}
		}
		summary[length] = '\x00'
		//error(2,"\n%s: %s", summary, (node->checked&NODE_REMOVED?node->old_data:node->new_data)->filename);
		var fn string = ""
		if (node.Checked & NODE_REMOVED) != 0 {
			fn = node.Old_data.Filename
		} else {
			fn = node.New_data.Filename
		}
		/*
		if node.Path == "/file_a" {
			fmt.Printf(" node.Checked:0x%x ", node.Checked)
		}
		*/
		fmt.Printf("\n%s: %s", summary, fn)
	} else {
		if (node.Checked & NODE_ADDED) != 0 {
			//error(2,"added: %s\n",(node->new_data)->filename);
			fmt.Printf("added: %s\n", node.New_data.Filename)
		} else if (node.Checked & NODE_REMOVED) != 0 {
			//error(2,"removed: %s\n",(node->old_data)->filename);
			fmt.Printf("removed: %s\n", node.Old_data.Filename)
		} else if (node.Checked & NODE_CHANGED) != 0 {
			//error(2,"changed: %s\n",(node->new_data)->filename);
			fmt.Printf("changed: %s\n", node.New_data.Filename)
		}
	}
}

func print_dbline_attributes(oline *DBTree_Line, nline *DBTree_Line, changed_attrs DB_ATTR_TYPE,
	force_attrs DB_ATTR_TYPE, conf *DB_config) {

	var details_attributes = []DB_ATTR_TYPE { DB_FTYPE, DB_LINKNAME, DB_SIZE, DB_SIZEG, DB_BCOUNT,
		DB_PERM, DB_UID, DB_GID, DB_ATIME, DB_MTIME, DB_CTIME, DB_INODE, DB_LNKCOUNT, DB_MD5,
		DB_SHA1, DB_RMD160, DB_TIGER, DB_SHA256, DB_SHA512 }
	var details_string = []string{ "File type" , "Lname", "Size", "Size (>)", "Bcount",
		"Perm", "Uid", "Gid", "Atime", "Mtime", "Ctime", "Inode", "Linkcount", "MD5",
		"SHA1", "RMD160", "TIGER", "SHA256", "SHA512" }


	var width_details = 80

	var ovalue [][]byte
	var nvalue [][]byte

	var onumber, nnumber, olen, nlen, i, j, k, c int
	var length = len(details_attributes)

	var p = 0

	if (width_details % 2) != 0 {
		p = (width_details - 13) / 2
	} else {
		p = (width_details - 14) / 2
	}

	var attrs DB_ATTR_TYPE
	//fmt.Printf("\n")
	var vPerm mode_t
	var vFileName string
	if nline == nil {
		vPerm = oline.Perm
		vFileName = oline.Filename
	} else {
		vPerm = nline.Perm
		vFileName = nline.Filename
	}
	var file_type = get_file_type_string(vPerm)
	if file_type != "" {
		fmt.Printf("print_dbline_attributes() %s: ", file_type)
	}
	fmt.Printf("%s\n", vFileName)

	attrs = force_attrs | ((^(conf.Ignored_changed_attrs)) & changed_attrs)

	for j = 0; j < length; j++ {
		if (details_attributes[j] & attrs) != 0 {
			onumber, ovalue = get_attribute_values(details_attributes[j], oline, conf)
			nnumber, nvalue = get_attribute_values(details_attributes[j], nline, conf)
			i = 0
			for ;i < onumber || i < nnumber; {
				//olen = i<onumber?strlen(ovalue[i]):0;
				//nlen = i<nnumber?strlen(nvalue[i]):0;
				if i < onumber {
					olen = len(ovalue[i])
				} else {
					olen = 0
				}
				if i < nnumber {
					nlen = len(nvalue)
				} else {
					nlen = 0
				}
				k = 0
				for ;(olen - p*k >= 0) || (nlen - p*k >= 0); {
					c = k*(p-1)
					if onumber == 0 {
						var v1,v2 string
						var v3 byte
						var v7 string
						if (width_details % 2) != 0 {
							v1 = ""
						} else {
							v1 = " "
						}
						if (i + k) != 0 {
							v2 = ""
							v3 = ' '
						} else {
							v2 = details_string[j]
							v3 = ':'
						}
						if nlen - c > 0 {
							v7 = string(nvalue[i][c:])
						} else {
							v7 = ""
						}
						//error(2," %s%-9s%c %-*c  %.*s\n", width_details%2?"":" ", i+k?"":details_string[j], i+k?' ':':', p, ' ', p-1, nlen-c>0?&nvalue[i][c]:"");
						fmt.Printf("%s %s %c %d %c %d %s", v1, v2, v3, p, ' ', p-1, v7)
					} else if nnumber == 0 {
						var v1,v2 string
						var v3 byte
						var v5 string
						if (width_details % 2) != 0 {
							v1 = ""
						} else {
							v1 = " "
						}
						if (i + k) != 0 {
							v2 = ""
							v3 = ' '
						} else {
							v2 = details_string[j]
							v3 = ':'
						}
						if olen - c > 0 {
							v5 = string(ovalue[i][c:])
						} else {
							v5 = ""
						}
						//error(2," %s%-9s%c %.*s\n", width_details%2?"":" ", i+k?"":details_string[j], i+k?' ':':', p-1, olen-c>0?&ovalue[i][c]:"");
						fmt.Printf("%s %s %c %d %s", v1, v2, v3, p-1, v5)
					} else {
						var v1,v2 string
						var v3 byte
						var v6, v8 string
						if (width_details % 2) != 0 {
							v1 = ""
						} else {
							v1 = " "
						}
						if (i + k) != 0 {
							v2 = ""
							v3 = ' '
						} else {
							v2 = details_string[j]
							v3 = ':'
						}
						if olen - c > 0 {
							v6 = string(ovalue[i][c:])
						} else {
							v6 = ""
						}
						if nlen - c > 0 {
							v8 = string(nvalue[i][c:])
						} else {
							v8 = ""
						}
						//error(2," %s%-9s%c %-*.*s| %.*s\n", width_details%2?"":" ", i+k?"":details_string[j], i+k?' ':':', p, p-1, olen-c>0?&ovalue[i][c]:"", p-1, nlen-c>0?&nvalue[i][c]:"");

						fmt.Printf("%s %s %c %d %d %s %d %s", v1, v2, v3, p, p-1, v6, p-1, v8)
					}
					k++
				}
				i++
			}
		}
	}
}

func print_attributes_added_node(line *DBTree_Line, conf *DB_config) {
	print_dbline_attributes(nil, line, 0, line.Attr, conf)
}

func print_attributes_removed_node(line *DBTree_Line, conf *DB_config) {
	print_dbline_attributes(line, nil, 0, line.Attr, conf)
}

const (
	NoteInfoHead = "|--%s"
	NoteMetaDataFmt = "Checked:0x%x Attr:0x%x Changed_attrs:0x%x Conf_lineno:0x%x Rx:%s"
	NoteLineInfoFmt = "[%s-Line] Perm:%o Attr:0x%x Uid:%d Gid:%d Inode:%d Nlink:%d Size:%d BCount:%d MT:%s CT:%s FileName:%s LinkName:%s sha512:%s"
)

func (node *Seltree) PrintTreeInfo(preSpaceCount, parentLastSlashIndex int) {

	var sPrefix = make([]byte, preSpaceCount)
	var sMSpaceCount = preSpaceCount + 3 + parentLastSlashIndex + 8
	var sMPrefix = make([]byte, sMSpaceCount)
	for i := 0; i < preSpaceCount; i++ {
		sPrefix[i] = ' '
	}
	for i := 0; i < sMSpaceCount; i++ {
		sMPrefix[i] = ' '
	}

	var strPrefix = string(sPrefix)
	var strSmPrefix = string(sMPrefix)

	//fmt.Printf( strPrefix + NoteInfoHead, node.Path)
	//fmt.Printf( strSmPrefix + NoteMetaDataFmt, node.Checked, node.Attr, node.Changed_attrs, node.Conf_lineno, node.Rx)

	fmt.Printf( strPrefix + NoteInfoHead + "\t" + NoteMetaDataFmt + "\n",
		node.Path, node.Checked, node.Attr, node.Changed_attrs, node.Conf_lineno, node.Rx)
	if node.Old_data != nil {
		ld := node.Old_data
		fmt.Printf( strSmPrefix + NoteLineInfoFmt + "\n", "old", ld.Perm, ld.Attr, ld.Uid, ld.Gid, ld.Inode, ld.Nlink, ld.Size, ld.Bcount, ld.Mtime, ld.Ctime, ld.Filename, ld.Linkname, ld.Sha512)
	}
	if node.New_data != nil {
		ld := node.New_data
		fmt.Printf( strSmPrefix + NoteLineInfoFmt + "\n", "new", ld.Perm, ld.Attr, ld.Uid, ld.Gid, ld.Inode, ld.Nlink, ld.Size, ld.Bcount, ld.Mtime, ld.Ctime, ld.Filename, ld.Linkname, ld.Sha512)
	}

	var cPreSpaceCount = preSpaceCount + 4 + strings.LastIndex(node.Path, "/") + 2
	var pLen = len(node.Path)
	for r := node.Childs.Front(); r != nil; r = r.Next() {
		cNode, _ := r.Value.(*Seltree)
		cNode.PrintTreeInfo(cPreSpaceCount, pLen)
	}
}


func (node *Seltree) terse_report(conf *DB_config) {

	if node.Path == "/folder_b/file_ba" {
		fmt.Printf("+++ terse_report() 0 %s added node.Checked:0x%x\n", "/folder_b/file_ba", node.Checked)
	}

	if (node.Checked & (DB_OLD|DB_NEW)) != 0 {

		if node.Checked & DB_NEW != 0 {
			conf.Ntotal++
		}

		if (node.Checked & DB_OLD) == 0 {
			/* File is in new db but not old. (ADDED) */
			/* unless it was moved in */
			if ((node.Checked & NODE_ALLOW_NEW) == 0) && ((node.Checked & NODE_MOVED_IN) == 0) {
				if node.Path == "/folder_b/folder_ba" {
					fmt.Printf("+++ terse_report() 1 %s added node.Checked:0x%x\n", "/folder_b/folder_ba", node.Checked)
				}
				conf.Nadd++
				node.Checked |= NODE_ADDED
				if node.Path == "/folder_b/folder_ba" {
					fmt.Printf("+++ terse_report() 1 %s added\n", "/folder_b/folder_ba")
				}
			}
		} else if (node.Checked & DB_NEW) == 0 {
			/* File is in old db but not new. (REMOVED) */
			/* unless it was moved out */
			if ((node.Checked & NODE_ALLOW_RM) == 0) && ((node.Checked & NODE_MOVED_OUT) == 0) {
				conf.Nrem++
				node.Checked |= NODE_REMOVED
			}
		} else if (node.Old_data != nil) && (node.New_data != nil) {
			/* File is in both db's and the data is still there. (CHANGED) */
			if (node.Checked & (NODE_MOVED_IN|NODE_MOVED_OUT)) == 0 {
				conf.Nchg++
				node.Checked |= NODE_CHANGED
			} else if (node.Checked & NODE_ALLOW_NEW) == 0 && (node.Checked & NODE_MOVED_IN) == 0 {
				conf.Nadd++
				if node.Path == "/folder_b/folder_ba" {
					fmt.Printf("+++ terse_report() 2 %s added\n", "/folder_b/folder_ba")
				}
				node.Checked |= NODE_ADDED
			} else if (node.Checked & NODE_ALLOW_RM) == 0 && (node.Checked & NODE_MOVED_OUT) == 0 {
				conf.Nrem++
				node.Checked |= NODE_REMOVED
			}
		}
	}

	for r := node.Childs.Front(); r != nil; r = r.Next() {
		cNode, _ := r.Value.(*Seltree)
		cNode.terse_report(conf)
	}
}

func (node *Seltree) print_report_list(node_status uint64, conf *DB_config) {

	if (node.Checked & node_status) != 0 {
		node.print_line(conf)
	}

	for r := node.Childs.Front(); r != nil ;r = r.Next() {
		//print_report_list((seltree*)r->data, node_status);
		cNode, _ := r.Value.(*Seltree)
		cNode.print_report_list(node_status, conf)
	}
}

func (node *Seltree) print_report_details(conf *DB_config) {

	if conf.Verbose_level >= 5 {
		if (node.Checked & NODE_CHANGED) != 0 {
			/*
			print_dbline_attributes(node->old_data, node->new_data, node->changed_attrs, (conf->verbose_level>=6?(
				((node->old_data)->attr&~((node->new_data)->attr)&~(ignored_removed_attrs))|(~((node->old_data)->attr)&(node->new_data)->attr&~(ignored_added_attrs))
			):0)|forced_attrs);
			*/

			var fAttrs DB_ATTR_TYPE = 0
			if conf.Verbose_level >= 6 {
				fAttrs = ( ((node.Old_data.Attr) & (^(node.New_data.Attr)) & (^(conf.Ignored_removed_attrs))) |
					((^(node.Old_data.Attr)) & (node.New_data.Attr) & (^(conf.Ignored_added_attrs))) ) | conf.Forced_attrs
			} else {
				fAttrs = 0 | conf.Forced_attrs
			}

			print_dbline_attributes(node.Old_data, node.New_data, node.Changed_attrs, fAttrs, conf)
		} else if conf.Verbose_level >= 7 {
			if (node.Checked & NODE_ADDED) != 0 {
				print_attributes_added_node(node.New_data, conf)
			}
			if (node.Checked & NODE_REMOVED) != 0 {
				print_attributes_removed_node(node.Old_data, conf)
			}
		}
	}

	var r *list.Element = nil
	for r = node.Childs.Front(); r != nil; r = r.Next() {
		cNode, _ := r.Value.(*Seltree)
		cNode.print_report_details(conf)
	}
}

func print_report_header(conf *DB_config) {

	fmt.Printf("\n\n +++++++ print_report_header() +++++++\n")

	/*
	char *time;
	int first = 1;

	time = malloc(time_string_len * sizeof (char));
	strftime(time, time_string_len, time_format, localtime(&(conf->start_time)));
	error(2,_("Start timestamp: %s (AIDE " AIDEVERSION ")\n"), time);
	free(time); time=NULL;

	error(0,_("AIDE"));
	*/
	if (conf.Action & (DO_COMPARE|DO_DIFF)) != 0 {
		var strDiff string
		var strRst string
		if conf.Nadd != 0 || conf.Nrem != 0 || conf.Nchg != 0 {
			strDiff = ""
			strRst = ""
		} else {
			strDiff = "NO"
			strRst = ". Looks okay"
		}

		var strCmp string
		if conf.Action & DO_COMPARE != 0 {
			strCmp = "database and filesystem"
		} else {
			strCmp = "the two databases"
		}

		//error(0,_(" found %sdifferences between %s%s!!\n"), (nadd||nrem||nchg) ? "" : "NO ", conf->action & DO_COMPARE ? _("database and filesystem") : _("the two databases"), (nadd||nrem||nchg) ? "" : _(". Looks okay"));
		fmt.Printf(" found %sdifferences between %s%s!!\n", strDiff, strCmp, strRst)

		if (conf.Action & (DO_INIT)) != 0 {
			fmt.Printf("New AIDE database written to %s\n", conf.JdbOld.FilePath)
		}
	} else {
		fmt.Printf(" initialized database at %s\n", conf.JdbOld.FilePath)
	}

	/*
	if(conf->config_version)
	error(2,_("Config version used: %s\n"),conf->config_version);

	if (conf->limit != NULL)
	{
		error (2,_("Limit: %s"), conf->limit);
		first = 0;
	}
	if (conf->action & (DO_INIT|DO_COMPARE) && conf->root_prefix_length > 0)
	{
	if (first)
	{
	first=0;
	}
	else
	{
	error (2," | ");
	}
	error (2,_("Root prefix: %s"),conf->root_prefix);
	}

	if (conf->verbose_level != 5)
	{
		if (first)
		{
		first=0;
		}
		else
		{
		error (2," | ");
		}
		error (2,_("Verbose level: %d"), conf->verbose_level);
	}
	if (!first)
	{
	error (2,"\n");
	}
	*/
	if conf.Ignored_added_attrs != 0 {
		fmt.Printf ("Ignored added attributes: %s\n", report_attrs(conf.Ignored_added_attrs))
	}

	if conf.Ignored_removed_attrs != 0 {
		fmt.Printf("Ignored removed attributes: %s\n", report_attrs(conf.Ignored_removed_attrs))
	}

	if conf.Ignored_changed_attrs != 0 {
		fmt.Printf("Ignored changed attributes: %s\n", report_attrs(conf.Ignored_changed_attrs))
	}

	if conf.Forced_attrs != 0 {
		fmt.Printf ("Forced attributes: %s\n", report_attrs(conf.Forced_attrs))
	}

	/*
	#ifdef WITH_E2FSATTRS
	if (conf->report_ignore_e2fsattrs)
	{
	error (2,_("Ignored e2fs attributes: %s\n"), e2fsattrs2string(conf->report_ignore_e2fsattrs, 1) );
	}
	#endif
	*/

	if (conf.Action & (DO_COMPARE|DO_DIFF)) != 0 && (conf.Nadd != 0 || conf.Nrem != 0 || conf.Nchg != 0) {
		fmt.Printf("\nSummary:\n  Total number of entries:\t%d\n  " +
			"Added entries:\t\t%d\n  " +
			"Removed entries:\t\t%d\n  " +
			"Changed entries:\t\t%d",
			conf.Ntotal, conf.Nadd, conf.Nrem, conf.Nchg)
	} else {
		fmt.Printf("\nNumber of entries:\t%d", conf.Ntotal)
	}
}

func (node * Seltree) Gen_report(conf *DB_config) int {
	/*
	forced_attrs = get_special_report_group("report_force_attrs");
	ignored_added_attrs = get_special_report_group("report_ignore_added_attrs");
	ignored_removed_attrs = get_special_report_group("report_ignore_removed_attrs");
	ignored_changed_attrs = get_special_report_group("report_ignore_changed_attrs");
	*/

	fmt.Printf("+++ Gen_report() fb nadd:%d nrem:%d nchg:%d \n", conf.Nadd, conf.Nrem, conf.Nchg)
	node.terse_report(conf)
	fmt.Printf("+++ Gen_report() af nadd:%d nrem:%d nchg:%d \n", conf.Nadd, conf.Nrem, conf.Nchg)
	/*
	#ifdef WITH_AUDIT
	send_audit_report();
	#endif
	*/
	if (conf.Nadd | conf.Nrem | conf.Nchg) > 0 || conf.Report_quiet == 0 {

		print_report_header(conf)

		if ((conf.Action & (DO_COMPARE|DO_DIFF)) != 0) || (((conf.Action & DO_INIT) != 0) && (conf.Report_detailed_init != 0)) {
			if conf.Grouped != 0 {
				if conf.Nadd != 0 {
					fmt.Printf(report_top_format,"Added entries")
					node.print_report_list(NODE_ADDED, conf)
				}
				if conf.Nrem != 0 {
					fmt.Printf(report_top_format,"Removed entries")
					node.print_report_list(NODE_REMOVED, conf)
				}
				if conf.Nchg != 0 {
					fmt.Printf(report_top_format,"Changed entries")
					node.print_report_list(NODE_CHANGED, conf)
				}
			} else if conf.Nadd != 0 || conf.Nrem != 0 || conf.Nchg != 0 {
				if (conf.Nadd != 0) && (conf.Nrem != 0) && (conf.Nchg != 0) {
					fmt.Printf(report_top_format,"Added, removed and changed entries")
				} else if conf.Nadd != 0 && conf.Nrem != 0 {
					fmt.Printf(report_top_format,"Added and removed entries")
				} else if conf.Nadd != 0 && conf.Nchg != 0 {
					fmt.Printf(report_top_format,"Added and changed entries")
				} else if conf.Nrem != 0 && conf.Nchg != 0 {
					fmt.Printf(report_top_format,"Removed and changed entries")
				} else if conf.Nadd != 0 {
					fmt.Printf(report_top_format,"Added entries")
				} else if conf.Nrem != 0 {
					fmt.Printf(report_top_format,"Removed entries")
				} else if conf.Nchg != 0 {
					fmt.Printf(report_top_format,"Changed entries")
				}
				node.print_report_list(NODE_ADDED|NODE_REMOVED|NODE_CHANGED, conf)
			}
			if conf.Nadd != 0 || conf.Nrem != 0 || conf.Nchg != 0 {
				//error(nchg?5:7,(char*)report_top_format,_("Detailed information about changes"));
				//fmt.Printf(report_top_format,"Detailed information about changes")
				//node.print_report_details(conf)
			}
		}
		/*
		print_report_databases();
		conf->end_time=time(&(conf->end_time));
		print_report_footer();
		*/
	}

	if (conf.Action & (DO_COMPARE|DO_DIFF)) != 0 {
		//(nadd!=0)*1+(nrem!=0)*2+(nchg!=0)*4 : 0;
		var ret = 0
		if conf.Nadd != 0 {
			ret += 1
		}
		if conf.Nrem != 0 {
			ret += 2
		}
		if conf.Nchg != 0 {
			ret += 4
		}
		return ret
	} else {
		return 0
	}
}


