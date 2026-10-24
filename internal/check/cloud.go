package check

import "strings"

// CloudVendorsVersion identifies the DMI vendor table: a change to it
// changes what the host fact sheet calls a cloud VM
// (docs/spec/host-collector.md §3, G5).
const CloudVendorsVersion = "2026-10-24"

// cloudVendor is one DMI sys_vendor / product_name pair, matched exactly
// (case-insensitively), and the provider it names.
type cloudVendor struct{ vendor, product, name string }

var cloudVendors = []cloudVendor{
	{"Google", "Google Compute Engine", "Google Compute Engine"},
	{"Amazon EC2", "", "Amazon EC2"},
	{"DigitalOcean", "Droplet", "DigitalOcean"},
	{"Hetzner", "", "Hetzner Cloud"},
	{"OpenStack Foundation", "OpenStack Nova", "OpenStack"},
	{"Microsoft Corporation", "Virtual Machine", "Azure or Hyper-V"},
}

// CloudVendor reads the lines of `sys.dmi` (grep -H output: path:value) and
// names the cloud platform they show, or "" when they show none. An unknown
// vendor is "not identified", never "not a cloud VM": QEMU, Xen and every
// other value say nothing either way, and neither does a missing DMI tree.
// It reads a label; it proves nothing about the host's network.
func CloudVendor(lines []string) string {
	var vendor, product string
	for _, l := range lines {
		path, val, ok := strings.Cut(l, ":")
		if !ok || HasMarker(val) {
			continue
		}
		switch path {
		case "/sys/class/dmi/id/sys_vendor":
			vendor = strings.TrimSpace(val)
		case "/sys/class/dmi/id/product_name":
			product = strings.TrimSpace(val)
		}
	}
	for _, c := range cloudVendors {
		if strings.EqualFold(vendor, c.vendor) && (c.product == "" || strings.EqualFold(product, c.product)) {
			return c.name
		}
	}
	return ""
}

func dmiSummary(lines []string) string {
	if v := CloudVendor(lines); v != "" {
		return "cloud VM: " + v + " (from DMI)"
	}
	if len(lines) == 0 {
		return "no DMI data; cloud platform not identified"
	}
	return "cloud platform not identified"
}
