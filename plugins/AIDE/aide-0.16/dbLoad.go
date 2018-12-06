package aide

import (
	"container/list"
	"encoding/json"
	aUtils "github.com/chainHero/heroes-service/plugins/utils"
)

func (jDB *JsonDB) loadJDB() (error){
	var err error
	err = json.Unmarshal(jDB.RawData, &jDB.Jdb)
	return err
}

func (jdb *JsonDB) GetRxList() ( sList, nList, eList *list.List) {
	sList = list.New()
	nList = list.New()
	eList = list.New()

	for _, v := range jdb.Jdb.RxLists.RxS {
		rx := new(Rx_rule)
		rx.Rx = v.Rx
		rx.Conf_lineno = v.Conf_lineno
		rx.Attr = v.Attr
		rx.Restriction = v.Restriction
		sList.PushBack(rx)
	}
	for _, v := range jdb.Jdb.RxLists.RxN {
		rx := new(Rx_rule)
		rx.Rx = v.Rx
		rx.Conf_lineno = v.Conf_lineno
		rx.Attr = v.Attr
		rx.Restriction = v.Restriction
		nList.PushBack(rx)
	}
	for _, v := range jdb.Jdb.RxLists.RxE {
		rx := new(Rx_rule)
		rx.Rx = v.Rx
		rx.Conf_lineno = v.Conf_lineno
		rx.Attr = v.Attr
		rx.Restriction = v.Restriction
		eList.PushBack(rx)
	}

	return sList, nList, eList
}

func NewJDB(dbPath string) (*JsonDB, error) {
	var err error
	var jDB = new(JsonDB)
	jDB.FilePath = dbPath
	jDB.RawData, err = aUtils.GetBufFromFile(jDB.FilePath)

	if err != nil {
		return jDB, err
	}

	err = jDB.loadJDB()
	return jDB, err
}
