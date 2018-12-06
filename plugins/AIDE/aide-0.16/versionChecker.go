package aide

import (
	"bytes"
	"errors"
	"fmt"
	seccUtils "github.com/chainHero/heroes-service/plugins/utils"
	"io"
	"regexp"
)

func GetVersion(result string) (string, error)  {



	//verRegexp := regexp.MustCompile(`\(AIDE ([\d]{1}).([\d]{2})\)`)
	verRegexp := regexp.MustCompile(`\(AIDE ([\w\d\.]+)\)`)
	params := verRegexp.FindStringSubmatch(result)


	/*
	for _,param :=range params {
		fmt.Println(param)
	}
	*/

	if len(params) < 2 {
		return "", errors.New("No version.")
	}

	return params[1], nil
}

func GetDetailInfos(result []byte) ([]string, error){

	var detailInfo []string
	var err error = nil
	var isPushInfo bool = false

	var splitString = "---------------------------------------------------\n"
	var splitStringCnt = 0
	var indexState = 0
	var indexString = "Detailed information about changes:\n"

	defer func() {
		fmt.Printf("+++ Got split string count:%d +++\n", splitStringCnt)
	}()

	rBuf := bytes.NewBuffer(result)
	for n := 1;; n++ {
		line, e := rBuf.ReadString('\n')
		if line == splitString {
			splitStringCnt++
		}
		if e != nil {
			if e != io.EOF {
				seccUtils.Check(e)
			} else {
				break
			}
		}
		//fmt.Printf("n:%d %s", n, line)
		if isPushInfo {
			if line == splitString {
				break
			} else {
				detailInfo = append(detailInfo, line)
			}
		} else if indexState == 0 {
			if line == splitString {
				indexState++
			} else {
				continue
			}
		} else if indexState == 1 {
			if line == indexString {
				indexState++
			} else {
				indexState = 0
			}
		} else if indexState == 2 {
			if line == splitString {
				indexState++
				isPushInfo = true
			} else {
				indexState = 0
			}
		}
	}

	if len(detailInfo) <= 0 {
		return nil, errors.New("No details.")
	}

	return detailInfo, err
}


