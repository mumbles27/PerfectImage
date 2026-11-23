// Package catalogdata embeds the built-in PerfectImage catalog: Packer image
// definitions (images/), app definitions (apps/) and bundles (bundles/).
// See docs/catalog.md.
package catalogdata

import "embed"

// FS holds images/, apps/ and bundles/.
//
//go:embed images apps bundles
var FS embed.FS
