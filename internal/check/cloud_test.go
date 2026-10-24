package check

import "testing"

func TestCloudVendor(t *testing.T) {
	line := func(vendor, product string) []string {
		return []string{"/sys/class/dmi/id/sys_vendor:" + vendor, "/sys/class/dmi/id/product_name:" + product}
	}
	for _, tc := range []struct {
		lines []string
		want  string
	}{
		{line("Google", "Google Compute Engine"), "Google Compute Engine"},
		{line("Amazon EC2", "t3.micro"), "Amazon EC2"},
		{line("DigitalOcean", "Droplet"), "DigitalOcean"},
		{line("Microsoft Corporation", "Virtual Machine"), "Azure or Hyper-V"},
		{line("Microsoft Corporation", "Surface Laptop"), ""},
		{line("QEMU", "Standard PC"), ""},
		{line("Google", "Pixelbook"), ""},
		{nil, ""},
		{[]string{"/sys/class/dmi/id/sys_vendor:[REDACTED:x:3 bytes]"}, ""},
	} {
		if got := CloudVendor(tc.lines); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.lines, got, tc.want)
		}
	}
	if s := dmiSummary(nil); s != "no DMI data; cloud platform not identified" {
		t.Error(s)
	}
	if s := dmiSummary(line("QEMU", "x")); s != "cloud platform not identified" {
		t.Error(s)
	}
}
