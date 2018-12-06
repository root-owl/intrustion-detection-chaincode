package aide

import (
	"bytes"
	"container/list"
	"fmt"
	"strings"
)

type Rx_rule struct {
	//char* rx; /* Regular expression in text form */
	Rx string `json:"rx"`
	//pcre* crx; /* Compiled regexp */
	//DB_ATTR_TYPE attr; /* Which attributes to save */
	Attr uint64	`json:"attr"`
	//long  conf_lineno; /* line no. of rule definition*/
	Conf_lineno int64 `json:"cfgNo"`
	//RESTRICTION_TYPE restriction;
	Restriction uint64	`json:"restriction"`
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

func strlastslash(str string) ([]byte) {

	sPath := []byte(str)
	ldx := bytes.LastIndex(sPath, []byte("/"))

	return sPath[:ldx]
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

func strgetndirname(path string, depth int) ([]byte) {

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
		return []byte(path)
	}

	return sPath[:idx]
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


func (tree *Seltree) get_seltree_node(path string) (node *Seltree) {

	node = nil
	//var r *list.List = nil
	var r *list.Element = nil

	var tmp []byte = nil

	if tree == nil {
		return nil
	}

	sPath := []byte(path + "\x00")
	sTreePath := []byte(tree.Path + "\x00")

	if bytes.Equal(sTreePath, sPath) {
		return tree
	} else {
		tmp = strgetndirname(path, treedepth(tree) + 1)
		for r = tree.Childs.Front(); r != nil ; r = r.Next() {
			t, _ := r.Value.(*Seltree)
			sT := []byte(t.Path + "\x00")
			sTmp := []byte(string(tmp) + "\x00")
			//if(strncmp(((seltree*)r->data)->path,tmp,strlen(tmp)+1)==0) {
			if bytes.Equal(sT, sTmp) {
				node = t.get_seltree_node(path)
				if(node != nil) {
					return node
				}
			}
		}
	}
	return nil
}

func (tree *Seltree) gen_seltree(rxlist *list.List, rxType byte) {

	/*
	pcre*        rxtmp = NULL;
	const char*  pcre_error;
	int          pcre_erroffset;

	seltree*     curnode = NULL;
	list*        r       = NULL;
	rx_rule*     rxc     = NULL;
	*/

	var count = 0
	var r *list.Element = nil
	var rxtok = ""
	var curnode *Seltree = nil
	var rxc * Rx_rule = nil

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
		{
			/* replace regexp text with regexp compiled */
			rxc = new(Rx_rule)

			/* and copy the rest */
			rxc.Rx = curr_rule.Rx
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
			parent = tree.get_seltree_node(string(dirn))
		}

		if parent == nil {
			if isrx {
				parent = New_seltree_node(tree, tmprxtok, isrx, r)
			} else {
				dirn := strlastslash(path)
				parent = New_seltree_node(tree, string(dirn),isrx,r)
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

func (tree *Seltree) Check_rxtree(filename string, attr *uint64, perm uint64) (int) {
	int retval=0;
	char * tmp=NULL;
	char * parentname=NULL;
	seltree* pnode=NULL;

	parentname=strdup(filename);
	tmp=strrchr(parentname,'/');
	if(tmp!=parentname)
	{
	*tmp='\0';
	}
	else
	{
	if(parentname[1]!='\0')
	{
	/* we are in the root dir */
	parentname[1]='\0';
	}
	}

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

	pnode=get_seltree_node(tree,parentname);

	*attr=0;
	retval=check_node_for_match(pnode,filename, perm, 0,attr);

	free(parentname);

	return retval;
}

func (tree * Seltree) populate_tree(conf *DB_config) {


	var initdbwarningprinted = false
	var node *Seltree = nil
	////////////////////////
	int add=0;
	db_line* old=NULL;
	db_line* new=NULL;
	DB_ATTR_TYPE attr=0;
	seltree* node=NULL;

	/* With this we avoid unnecessary checking of removed files. */
	if (conf.Action & DO_INIT) != 0 {
		initdbwarningprinted = true
	}

	if (conf.Action & DO_DIFF) != 0 {
		for _, db_line := range conf.jsonDB.Jdb.FilesDB {
			/* FIXME add support config checking at this stage
			config check = add only those files that match config rxs
			make this configurable
			Only configurability is not implemented.
			*/
			/* This is needed because check_rxtree assumes there is a parent
			for the node for old->filename */
			treeLine := db_line.ToDBTreeLine()
			node = tree.get_seltree_node(treeLine.Filename)

			if node == nil {
				node = New_seltree_node(tree, treeLine.Filename, false, nil)
			}

		}
		while((new=db_readline(DB_NEW)) != NULL)
		{

			if((node=get_seltree_node(tree,new->filename)) == NULL)
			{
			node=new_seltree_node(tree,new->filename,0,NULL);
			}

			if((add=check_rxtree(new->filename,tree,&attr, new->perm))>0)
			{
			add_file_to_tree(tree,new,DB_NEW,attr);
			}
			else
			{
			free_db_line(new);
			free(new);
			new=NULL;
			}
		}
	}

	if((conf->action & DO_INIT) || (conf->action & DO_COMPARE))
	{
	/* FIXME  */
	new=NULL;
	while((new = db_readline(DB_DISK)) != NULL)
	{
	add_file_to_tree(tree,new,DB_NEW,attr);
	}
	}

	if((conf->action & DO_COMPARE) || (conf->action & DO_DIFF))
	{
	while((old = db_readline(DB_OLD)) != NULL)
	{
	/* This is needed because check_rxtree assumes there is a parent
	for the node for old->filename */
	if((node = get_seltree_node(tree,old->filename)) == NULL)
	{
	node = new_seltree_node(tree,old->filename,0,NULL);
	}

	add = check_rxtree(old->filename,tree, &attr, old->perm);

	if(add > 0)
	{
	add_file_to_tree(tree,old,DB_OLD,attr);
	}
	else if (conf->limit!=NULL && add < 0)
	{
	add_file_to_tree(tree,old,DB_OLD|DB_NEW,attr);
	}
	else
	{
	free_db_line(old);
	free(old);
	old = NULL;
	if(!initdbwarningprinted)
	{
	error(3,_("WARNING: Old db contains a entry that shouldn\'t be there, run --init or --update\n"));
	initdbwarningprinted=1;
	}
	}
	}
	}

	if(conf->action & DO_INIT)
	{
	write_tree(tree);
	}
}



