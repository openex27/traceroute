package traceroute

import (
	"encoding/json"
	"fmt"
	"testing"
)

func makeTraceParam(domain string, maxttl, retry int) string {
	x := TraceParam{
		domain,
		maxttl,
		retry,
	}
	data, _ := json.Marshal(x)
	return string(data)
}

func TestTraceParam_Run(t *testing.T) {
	args := makeTraceParam("www.baidu.com", 30, 1)
	if tr, err := NewTrace(args); err != nil {
		t.Fatal()
	} else {
		if ret, err := tr.Run(); err != nil {
			fmt.Println("error: ", err.Error())
		} else {
			fmt.Println(ret)
		}
	}

}
