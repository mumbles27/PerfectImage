# Catalog

Image templates (Packer HCL) and application install definitions live here.
Owned by the packer agent; see `internal/catalog` and `internal/packer`.

CI runs `packer validate` on every `*.pkr.hcl` template under this directory
and skips the step when none exist.
