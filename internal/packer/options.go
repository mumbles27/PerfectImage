package packer

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/mumbles27/PerfectImage/internal/catalog"
)

// OSSettings are guest settings applied during the build, before the apps
// are installed. Empty fields keep the installer defaults.
type OSSettings struct {
	// Timezone is an IANA zone (Europe/Berlin) on Linux and a Windows time
	// zone id (W. Europe Standard Time) on Windows.
	Timezone string `json:"timezone,omitempty"`
	// Locale is a language tag such as en-US or en_US; it is normalized per
	// OS (en_US.UTF-8 on Linux, en-US on Windows).
	Locale string `json:"locale,omitempty"`
	// Keyboard is an XKB layout (us, de, gb) on Linux and an input locale
	// (en-US or 0409:00000409) on Windows.
	Keyboard string `json:"keyboard,omitempty"`
	// Updates installs all available OS updates (apt/dnf upgrade, Windows
	// Update) before the apps.
	Updates bool `json:"updates,omitempty"`
	// WindowsEdition overrides the image's install.wim edition name
	// (windows_image_name), e.g. "Windows Server 2025 SERVERDATACENTER".
	WindowsEdition string `json:"windows_edition,omitempty"`
}

// PostScript is a user-supplied script run after the apps and before the
// image's cleanup and generalization. It runs as root (sudo) on Linux and
// as the build administrator on Windows. It is stored with the build record,
// so it must not contain secrets.
type PostScript struct {
	Script string `json:"script,omitempty"`
	// Reboot restarts the guest after the script.
	Reboot bool `json:"reboot,omitempty"`
}

// MaxPostScriptBytes caps a post-install script.
const MaxPostScriptBytes = 64 << 10

// windowsUpdatePasses is how many search/install/reboot rounds a build runs.
// Cumulative updates often unlock further updates only after a reboot.
const windowsUpdatePasses = 3

// Synthetic step ids (never valid catalog app ids, which cannot start with "_").
const (
	stepSettings   = "_os-settings"
	stepUpdates    = "_os-updates"
	stepPostScript = "_post-install"
)

var (
	ianaZoneRE  = regexp.MustCompile(`^(UTC|[A-Z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){1,2})$`)
	winZoneRE   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 .()+-]{1,63}$`)
	localeRE    = regexp.MustCompile(`^([a-z]{2,3})[-_]([A-Z]{2})(\.UTF-8|\.utf8)?$`)
	xkbLayoutRE = regexp.MustCompile(`^[a-z]{2,8}(-[a-z0-9]{1,16})?$`)
	winInputRE  = regexp.MustCompile(`^([a-z]{2,3}-[A-Z]{2}|[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8})$`)
	editionRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ().-]{0,79}$`)
)

// linuxLocale returns en_US.UTF-8 for en-US / en_US / en_US.UTF-8.
func linuxLocale(s string) string {
	m := localeRE.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1] + "_" + m[2] + ".UTF-8"
}

// windowsLocale returns en-US for en-US / en_US / en_US.UTF-8.
func windowsLocale(s string) string {
	m := localeRE.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1] + "-" + m[2]
}

// checkOptions validates the OS settings and the post-install script for
// the image's OS family.
func (r *BuildRequest) checkOptions(img *catalog.Image, fe FieldErrors) {
	s := r.Settings
	win := img != nil && img.OSFamily == catalog.Windows
	if s.Timezone != "" {
		if win && !winZoneRE.MatchString(s.Timezone) {
			fe["timezone"] = "Use a Windows time zone id, e.g. W. Europe Standard Time (tzutil /l)."
		}
		if !win && !ianaZoneRE.MatchString(s.Timezone) {
			fe["timezone"] = "Use an IANA time zone, e.g. Europe/Berlin or UTC."
		}
	}
	if s.Locale != "" && !localeRE.MatchString(s.Locale) {
		fe["locale"] = "Use a locale like en-US."
	}
	if s.Keyboard != "" {
		if win && !winInputRE.MatchString(s.Keyboard) {
			fe["keyboard"] = "Use an input locale like de-DE or 0407:00000407."
		}
		if !win && !xkbLayoutRE.MatchString(s.Keyboard) {
			fe["keyboard"] = "Use a keyboard layout like us, de or gb."
		}
	}
	if s.WindowsEdition != "" {
		if !win {
			fe["windows_edition"] = "Only Windows images have editions."
		} else if !editionRE.MatchString(s.WindowsEdition) {
			fe["windows_edition"] = "Use the edition name from install.wim, e.g. Windows Server 2025 SERVERSTANDARD."
		}
	}
	p := r.PostScript.Script
	switch {
	case len(p) > MaxPostScriptBytes:
		fe["post_script"] = fmt.Sprintf("The script is larger than %d KiB.", MaxPostScriptBytes>>10)
	case !utf8.ValidString(p) || strings.ContainsRune(p, 0):
		fe["post_script"] = "The script must be UTF-8 text."
	case r.PostScript.Reboot && strings.TrimSpace(p) == "":
		fe["post_script"] = "Add a script or untick the reboot option."
	}
}

// normalize trims fields and turns CRLF into LF so stored requests and
// rendered scripts are stable.
func (r *BuildRequest) normalizeOptions() {
	s := &r.Settings
	s.Timezone = strings.TrimSpace(s.Timezone)
	s.Locale = strings.TrimSpace(s.Locale)
	s.Keyboard = strings.TrimSpace(s.Keyboard)
	s.WindowsEdition = strings.TrimSpace(s.WindowsEdition)
	r.PostScript.Script = strings.ReplaceAll(r.PostScript.Script, "\r\n", "\n")
	if strings.TrimSpace(r.PostScript.Script) == "" {
		r.PostScript.Script = ""
	}
}

// Steps returns every provisioning step of the build in order: OS settings,
// OS updates, the resolved app steps, then the post-install script. All of
// them replace the image's apps marker, so they run after base provisioning
// and before cleanup / generalization.
func (r *BuildRequest) Steps(img *catalog.Image, apps []catalog.InstallStep) []catalog.InstallStep {
	var out []catalog.InstallStep
	if st, ok := settingsStep(img, r.Settings); ok {
		out = append(out, st)
	}
	if r.Settings.Updates {
		out = append(out, updateSteps(img)...)
	}
	out = append(out, apps...)
	if r.PostScript.Script != "" {
		st := catalog.InstallStep{AppID: stepPostScript, Name: "Post-install script", Script: r.PostScript.Script,
			RebootRequired: r.PostScript.Reboot, Shell: catalog.ShellBash}
		if img.OSFamily == catalog.Windows {
			st.Shell = catalog.ShellPowerShell
		}
		out = append(out, st)
	}
	return out
}

// isAppStep reports whether st installs a catalog app (rather than a
// generated settings/updates/post-install step).
func isAppStep(st catalog.InstallStep) bool { return !strings.HasPrefix(st.AppID, "_") }

func settingsStep(img *catalog.Image, s OSSettings) (catalog.InstallStep, bool) {
	if s.Timezone == "" && s.Locale == "" && s.Keyboard == "" {
		return catalog.InstallStep{}, false
	}
	st := catalog.InstallStep{AppID: stepSettings, Name: "OS settings"}
	if img.OSFamily == catalog.Windows {
		st.Shell = catalog.ShellPowerShell
		st.Script = windowsSettingsScript(s)
		// A new system locale takes effect after a restart.
		st.RebootRequired = s.Locale != ""
	} else {
		st.Shell = catalog.ShellBash
		st.Script = linuxSettingsScript(img.DistroFamily, s)
	}
	return st, true
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func psQuote(s string) string {
	r := strings.NewReplacer("'", "''", "‘", "‘‘", "’", "’’", "‚", "‚‚", "‛", "‛‛")
	return "'" + r.Replace(s) + "'"
}

func linuxSettingsScript(distro string, s OSSettings) string {
	var b strings.Builder
	b.WriteString("#!/bin/bash\n# Generated by PerfectImage: OS settings.\nset -euo pipefail\n")
	if s.Timezone != "" {
		fmt.Fprintf(&b, "tz=%s\n", shQuote(s.Timezone))
		b.WriteString(`test -e "/usr/share/zoneinfo/$tz" || { echo "unknown time zone $tz" >&2; exit 1; }
echo "==> time zone $tz"
timedatectl set-timezone "$tz" 2>/dev/null || ln -sf "/usr/share/zoneinfo/$tz" /etc/localtime
`)
		if distro == catalog.DistroDebian {
			b.WriteString("echo \"$tz\" > /etc/timezone\n")
		}
	}
	if s.Locale != "" {
		fmt.Fprintf(&b, "loc=%s\n", shQuote(linuxLocale(s.Locale)))
		b.WriteString("echo \"==> locale $loc\"\n")
		if distro == catalog.DistroDebian {
			b.WriteString(`export DEBIAN_FRONTEND=noninteractive
command -v locale-gen >/dev/null || { apt-get update -q; apt-get install -y -q locales; }
sed -i -E "s/^# *(${loc} UTF-8)/\1/" /etc/locale.gen
grep -q "^${loc} UTF-8" /etc/locale.gen || echo "${loc} UTF-8" >> /etc/locale.gen
locale-gen
update-locale LANG="$loc"
`)
		} else {
			b.WriteString(`dnf -y -q install "glibc-langpack-${loc%%_*}" || echo "WARNING: no langpack for $loc" >&2
localectl set-locale LANG="$loc" 2>/dev/null || echo "LANG=$loc" > /etc/locale.conf
`)
		}
	}
	if s.Keyboard != "" {
		layout, variant, _ := strings.Cut(s.Keyboard, "-")
		fmt.Fprintf(&b, "kb=%s\nkbv=%s\n", shQuote(layout), shQuote(variant))
		b.WriteString("echo \"==> keyboard $kb${kbv:+ ($kbv)}\"\n")
		if distro == catalog.DistroDebian {
			b.WriteString(`if [ -f /etc/default/keyboard ]; then
  sed -i -E "s/^XKBLAYOUT=.*/XKBLAYOUT=\"$kb\"/; s/^XKBVARIANT=.*/XKBVARIANT=\"$kbv\"/" /etc/default/keyboard
else
  printf 'XKBMODEL="pc105"\nXKBLAYOUT="%s"\nXKBVARIANT="%s"\nXKBOPTIONS=""\nBACKSPACE="guess"\n' "$kb" "$kbv" > /etc/default/keyboard
fi
command -v setupcon >/dev/null && setupcon --save-only || true
`)
		} else {
			b.WriteString(`localectl set-x11-keymap "$kb" pc105 "$kbv" 2>/dev/null || true
localectl set-keymap "$kb${kbv:+-$kbv}" 2>/dev/null || localectl set-keymap "$kb" 2>/dev/null || echo "WARNING: could not set console keymap $kb" >&2
`)
		}
	}
	return b.String()
}

// WindowsSettingsFile is read by the catalog's sysprep.ps1 so the settings
// survive generalization (they are written into the specialize/oobeSystem
// passes of the generalize answer file).
const WindowsSettingsFile = `C:\Windows\Panther\perfectimage-settings.json`

func windowsSettingsScript(s OSSettings) string {
	var b strings.Builder
	b.WriteString("# Generated by PerfectImage: OS settings.\n$ErrorActionPreference = 'Stop'\n$settings = [ordered]@{}\n")
	if s.Timezone != "" {
		fmt.Fprintf(&b, "$tz = %s\n", psQuote(s.Timezone))
		b.WriteString(`Write-Host "==> time zone $tz"
Set-TimeZone -Id $tz
$settings.timezone = $tz
`)
	}
	if s.Locale != "" {
		fmt.Fprintf(&b, "$loc = %s\n", psQuote(windowsLocale(s.Locale)))
		b.WriteString(`Write-Host "==> locale $loc"
Set-WinSystemLocale -SystemLocale $loc
# User locale and keyboard are per-user; sysprep.ps1 applies them to every
# account of the clones through the oobeSystem pass.
$settings.locale = $loc
`)
	}
	if s.Keyboard != "" {
		kb := s.Keyboard
		if m := localeRE.FindStringSubmatch(kb); m != nil {
			kb = m[1] + "-" + m[2]
		}
		fmt.Fprintf(&b, "$kb = %s\n", psQuote(kb))
		b.WriteString(`Write-Host "==> keyboard $kb"
$settings.keyboard = $kb
`)
	}
	fmt.Fprintf(&b, `New-Item -ItemType Directory -Force -Path (Split-Path %[1]s) | Out-Null
$settings | ConvertTo-Json | Set-Content -Path %[1]s -Encoding UTF8
Write-Host "    saved for sysprep: %[2]s"
`, psQuote(WindowsSettingsFile), WindowsSettingsFile)
	return b.String()
}

func updateSteps(img *catalog.Image) []catalog.InstallStep {
	if img.OSFamily == catalog.Windows {
		out := make([]catalog.InstallStep, windowsUpdatePasses)
		for i := range out {
			out[i] = catalog.InstallStep{
				AppID: fmt.Sprintf("%s-%d", stepUpdates, i+1), Name: fmt.Sprintf("Windows Update (pass %d of %d)", i+1, windowsUpdatePasses),
				Shell: catalog.ShellPowerShell, Script: windowsUpdateScript, RebootRequired: true,
				// The Windows Update API refuses to download or install from a
				// WinRM network logon; Packer's elevated mode runs the script
				// as a scheduled task instead.
				Elevated: true,
			}
		}
		return out
	}
	st := catalog.InstallStep{AppID: stepUpdates, Name: "OS updates", Shell: catalog.ShellBash, RebootRequired: true}
	if img.DistroFamily == catalog.DistroRHEL {
		st.Script = "#!/bin/bash\n# Generated by PerfectImage: OS updates.\nset -euo pipefail\necho '==> dnf upgrade'\ndnf -y upgrade --refresh\ndnf -y autoremove\ndnf clean all\n"
	} else {
		st.Script = `#!/bin/bash
# Generated by PerfectImage: OS updates.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
echo '==> apt-get dist-upgrade'
apt-get update -q
apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade
apt-get -y -q autoremove --purge
apt-get clean
`
	}
	return []catalog.InstallStep{st}
}

// windowsUpdateScript runs one Windows Update pass. Failed updates are
// reported but do not fail the build; the next pass (after a restart)
// retries them.
const windowsUpdateScript = `# Generated by PerfectImage: one Windows Update pass.
$ErrorActionPreference = 'Stop'
$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'PerfectImage'
Write-Host '==> searching for updates'
$found = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates
$batch = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $found) {
    if ($u.InstallationBehavior.CanRequestUserInput) { Write-Host "    skip (interactive): $($u.Title)"; continue }
    if (-not $u.EulaAccepted) { $u.AcceptEula() }
    [void]$batch.Add($u)
    Write-Host "    $($u.Title)"
}
if ($batch.Count -eq 0) { Write-Host '    no updates left'; exit 0 }
Write-Host "==> downloading $($batch.Count) update(s)"
$dl = $session.CreateUpdateDownloader()
$dl.Updates = $batch
[void]$dl.Download()
$ready = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $batch) { if ($u.IsDownloaded) { [void]$ready.Add($u) } }
if ($ready.Count -eq 0) { Write-Warning 'no update could be downloaded'; exit 0 }
Write-Host "==> installing $($ready.Count) update(s)"
$inst = $session.CreateUpdateInstaller()
$inst.Updates = $ready
$res = $inst.Install()
for ($i = 0; $i -lt $ready.Count; $i++) {
    $code = $res.GetUpdateResult($i).ResultCode
    if ($code -ge 4) { Write-Warning "failed (result $code): $($ready.Item($i).Title)" }
}
Write-Host "    result $($res.ResultCode), reboot required: $($res.RebootRequired)"
exit 0
`
