package policy_sdk_go

import (
	"fmt"
	"strings"
)

type Message string
type Code uint16

const (
	NoMessage Message = ""
	NoCode    Code    = 0
)

type keyValue struct {
	key   string
	value string
}

func (kv keyValue) String() string {
	return fmt.Sprintf(`"%s":%s`, kv.key, kv.value)
}

func AcceptRequest() ([]byte, error) {
	return []byte(`{"accepted":true}`), nil
}

func RejectRequest(message Message, code Code) ([]byte, error) {
	result := []keyValue{{key: "accepted", value: "false"}}
	if message != NoMessage {
		result = append(result, keyValue{key: "message", value: fmt.Sprintf(`"%s"`, string(message))})
	}
	if code != NoCode {
		result = append(result, keyValue{key: "code", value: fmt.Sprintf("%d", code)})
	}
	stringResult := []string{}
	for _, keyValue := range result {
		stringResult = append(stringResult, keyValue.String())
	}
	return []byte(fmt.Sprintf("{%s}", strings.Join(stringResult, ","))), nil
}
