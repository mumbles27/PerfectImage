# Catalog

The built-in PerfectImage catalog, embedded into the binary (`embed.go`):

- `images/<id>/`: Packer image definitions (`image.yaml`, `*.pkr.hcl`,
  unattended-install files, scripts). Starters: windows-server-2022,
  windows-server-2025, windows-11, ubuntu-24.04, debian-13, rocky-9.
- `apps/<id>.yaml`: app install definitions with per-OS fallback methods.
- `bundles/<id>.yaml`: named app groups.

See [docs/catalog.md](../docs/catalog.md) for the schema and how to add
items, and [docs/packer.md](../docs/packer.md) for the image template
contract. Validate with `perfectimage catalog validate --no-embedded --dir catalog`.
