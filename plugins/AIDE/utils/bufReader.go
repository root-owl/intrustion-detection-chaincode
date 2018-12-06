package utils

import (
	"io/ioutil"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

func GetBufFromFile(filePath string) ([]byte, error) {

	var buf []byte
	var err error

	buf, err = ioutil.ReadFile(filePath)
	Check(err)
	//fmt.Print(string(dat))

	return buf, err
}

