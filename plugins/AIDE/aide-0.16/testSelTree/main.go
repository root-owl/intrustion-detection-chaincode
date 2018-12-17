package main

import (
	"fmt"
	"github.com/chainHero/heroes-service/plugins/aide"
	"os"
)

const (
	jdbNewPath = "./testData/aide.db.new.json"
	jdbNewPathLocal = "/usr/local/etc/aideDB/aide.db.new.json"
	jdbOldPath = "./testData/aide.db.old.json"
	jdbOldPathLocal = "/usr/local/etc/aideDB/aide.db.old.json"
	jdbDiskPath = "./testData/aide.db.new.json"
)


func main() {

	var dbOldPath, dbNewPath string
	var envIDE = os.Getenv("IDE")

	if envIDE == "" {
		dbOldPath = jdbOldPathLocal
		dbNewPath = jdbNewPathLocal
	} else {
		dbOldPath = jdbOldPath
		dbNewPath = jdbNewPath
	}

	var dbCfg = aide.New_DB_confg(dbOldPath, dbNewPath, "")

	dbCfg.Action |= aide.DO_DIFF
	dbCfg.Grouped = 1
	dbCfg.Summarize_changes = 1
	dbCfg.Verbose_level = 5

	dbCfg.Load_JSON_DB(aide.DB_OLD)
	dbCfg.Load_JSON_DB(aide.DB_NEW)

	slist, nlist, elist := dbCfg.JdbOld.GetRxList()

	dbCfg.Tree = aide.Gen_tree(slist, nlist, elist)

	//dbCfg.Tree.Print_tree_rx(" |")

	dbCfg.Tree.Populate_tree(dbCfg)

	//dbCfg.Tree.PrintTreeInfo(1, 0)

	//dbCfg.Tree.Print_tree_rx(" |")

	fmt.Printf("\n\n---------------- Gen_report() start --------------------\n")
	dbCfg.Tree.Gen_report(dbCfg)
	fmt.Printf("\n---------------- Gen_report() end --------------------\n\n")

	dbCfg.Print_JDB_Hashes()

}
