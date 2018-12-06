package main

import (
	"fmt"
	aideUtils "github.com/chainHero/heroes-service/plugins/aide"
	seccUtils "github.com/chainHero/heroes-service/plugins/utils"
)

func main() {

	var err error
	var resultFile string = "./aide.log"
	var result []byte
	var version string
	var details []string
	result, err = seccUtils.GetBufFromFile(resultFile)
	seccUtils.Check(err)


	/*
	rBuf := bytes.NewBuffer(result)
	for n := 1;; n++ {
		line, e := rBuf.ReadString('\n')
		if e != nil {
			if e != io.EOF {
				seccUtils.Check(e)
			} else {
				break
			}
		}
		fmt.Printf("n:%d %s", n, line)
	}
	*/

	version, err = aideUtils.GetVersion(string(result))
	seccUtils.Check(err)
	fmt.Printf("+++ AIDE version:%s +++\n", version)

	details, err = aideUtils.GetDetailInfos(result)
	fmt.Printf("+++ Datails contain %d lines +++\n", len(details))
	for n, line := range details {
		fmt.Printf("%d : %s", n, line)
	}

	folders, files := aideUtils.GetDetailEntries(details)
	fmt.Printf("+++ Got folders, total:%d +++\n", len(folders))
	for _, folder := range folders {
		fmt.Printf("%s", folder)
		fmt.Printf("=================================\n")
	}

	fmt.Printf("\n\n\n##################################\n")
	fmt.Printf("+++ Got files, total:%d +++\n", len(files))
	for _, file := range files {
		fmt.Printf("%s", file)
		fmt.Printf("=================================\n")
	}


	//fmt.Printf("+++ got result: +++\n %s \n",result)
}
