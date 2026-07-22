package pollinate

import "testing"

func TestExampleConfigLoads(t *testing.T) {
	c, err := LoadConfig("../config-example-pollinate.json")
	if err != nil {
		t.Fatal(err)
	}
	if c.PushDelayMS != 600000 {
		t.Fatalf("push_delay_ms = %d", c.PushDelayMS)
	}
}
