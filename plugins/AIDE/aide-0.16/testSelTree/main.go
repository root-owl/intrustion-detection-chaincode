package main

import (
	"fmt"

	"github.com/chainHero/heroes-service/plugins/aide"
)

const (
	//jdbPath = "/usr/local/etc/aideDB/aide.db.new.json"
	jdbPath = "./aide.db.new.json"
)

func main() {

	var err error
	var jdb *aide.JsonDB = nil
	jdb, err = aide.NewJDB(jdbPath)

	if err != nil {
		fmt.Printf("--- New jdb err:%s \n", err)
	} else {
		//var newStr []byte
		//fmt.Printf("+++ Jdb: %+v \n", jdb.Jdb)

		//newStr, err = json.Marshal(&jdb.Jdb)
		//newStr, err = json.MarshalIndent(&jdb.Jdb,"", "    ")
		//fmt.Printf("+++ newStr:\n%s \n", newStr)

		fmt.Printf("+++ New jdb from: %s success.\n", jdb.FilePath)
	}

	slist, nlist, elist := jdb.GetRxList()

	seltree := aide.Gen_tree(slist, nlist, elist)

	seltree.Print_tree_rx(" |")

}
