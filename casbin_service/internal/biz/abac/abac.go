package abac

import (
	"encoding/json"
	"fmt"
	"strconv"
	"unicode"
)

const (
	Prefix = "ABAC::"
)

type AbacAttrList struct {
	V0      string
	V1      string
	V2      string
	V3      string
	V4      string
	V5      string
	NameMap map[string]string
}

// Resolve .
func Resolve(obj string) (AbacAttrList, error) {
	var jsonMap map[string]interface{}
	attrList := AbacAttrList{NameMap: map[string]string{}}

	err := json.Unmarshal([]byte(obj[len(Prefix):]), &jsonMap)
	if err != nil {
		return attrList, err
	}
	i := 0
	for k, v := range jsonMap {
		key := toUpperFirstChar(k)
		value := fmt.Sprintf("%v", v)
		attrList.NameMap[key] = "V" + strconv.Itoa(i)
		switch i {
		case 0:
			attrList.V0 = value
		case 1:
			attrList.V1 = value
		case 2:
			attrList.V2 = value
		case 3:
			attrList.V3 = value
		case 4:
			attrList.V4 = value
		case 5:
			attrList.V5 = value
		}
		i++
	}
	return attrList, nil
}

// GetCacheKey .
func (attr AbacAttrList) GetCacheKey() string {
	res, _ := MakeABAC(&attr)
	return res
}

// MakeABAC .
func MakeABAC(obj interface{}) (string, error) {
	data, err := json.Marshal(&obj)
	if err != nil {
		return "", err
	}
	return Prefix + string(data), nil
}

func toUpperFirstChar(str string) string {
	for i, v := range str {
		return string(unicode.ToUpper(v)) + str[i+1:]
	}
	return ""
}
