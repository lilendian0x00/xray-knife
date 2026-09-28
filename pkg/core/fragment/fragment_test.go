package fragment

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		spec    string
		want    string
		wantNil bool
		wantErr bool
	}{
		{spec: "", wantNil: true},
		{spec: "off", wantNil: true},
		{spec: "tlshello,100-200,10-20", want: "tlshello,100-200,10-20"},
		{spec: "TLSHello, 100-200 , 10", want: "tlshello,100-200,10"},
		{spec: "1-3,1-5", want: "1-3,1-5,0"},
		{spec: "0-3,1-5,1", wantErr: true},
		{spec: "tlshello,0,1", wantErr: true},
		{spec: "tlshello,200-100,1", wantErr: true},
		{spec: "tlshello", wantErr: true},
		{spec: "tlshello,1,2,3", wantErr: true},
		{spec: "tlshello,10,20000", wantErr: true},
	}
	for _, tc := range cases {
		o, err := Parse(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) = %v, want error", tc.spec, o)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q) error: %v", tc.spec, err)
			continue
		}
		if tc.wantNil {
			if o != nil {
				t.Errorf("Parse(%q) = %v, want nil", tc.spec, o)
			}
			continue
		}
		if got := o.String(); got != tc.want {
			t.Errorf("Parse(%q).String() = %q, want %q", tc.spec, got, tc.want)
		}
	}
}

func TestBuildNoise(t *testing.T) {
	o, err := Build("", []string{"rand:10-20:10-16", "str:hello"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.Enabled() || o.FragmentsTCP() {
		t.Fatalf("noise-only options: Enabled=%v FragmentsTCP=%v", o.Enabled(), o.FragmentsTCP())
	}
	if len(o.Noises) != 2 || o.Noises[0].String() != "rand:10-20:10-16" || o.Noises[1].Delay != (Range{}) {
		t.Fatalf("unexpected noises: %+v", o.Noises)
	}
	if _, err := Build("", []string{"bogus:1"}); err == nil {
		t.Fatal("unknown noise type accepted")
	}
	if _, err := Build("", []string{"rand:abc"}); err == nil {
		t.Fatal("non-range rand packet accepted")
	}
}

func TestNilOptions(t *testing.T) {
	var o *Options
	if o.Enabled() || o.FragmentsTCP() || o.String() != "" || o.Validate() != nil || o.Clone() != nil {
		t.Fatal("nil Options must behave as disabled")
	}
}
