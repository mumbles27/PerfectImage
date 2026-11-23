package main

// Domain packages register their app.Plugin and cli.Command implementations
// from init functions. Add one blank import per domain package here, e.g.:
//
//	_ "github.com/mumbles27/PerfectImage/internal/auth/authplugin"
//	_ "github.com/mumbles27/PerfectImage/internal/packer"
//
// Keep this list sorted; it is the only core file domain agents need to edit.
import (
	_ "github.com/mumbles27/PerfectImage/internal/audit/auditlog"
	_ "github.com/mumbles27/PerfectImage/internal/backup"
	_ "github.com/mumbles27/PerfectImage/internal/siem"
)
