// Package packer drives HashiCorp Packer builds of Proxmox VE VM templates
// from the image catalog (see package catalog and docs/packer.md).
//
// A build (job type "packer.build") renders a per-build workdir under
// packer.work_dir/builds/<id>: a copy of the image directory, the generated
// app scripts (catalog.Resolve) wired in as provisioners where the image's
// build.pkr.hcl has the "# @perfectimage:apps" line, and a 0600
// perfectimage.auto.pkrvars.hcl with the non-secret variables. Proxmox
// credentials (from the ClusterCreds provider installed with
// SetClusterCreds) and the random per-build guest password are passed only
// through the environment (PROXMOX_URL, PROXMOX_USERNAME, PROXMOX_TOKEN,
// PKR_VAR_build_password) and are redacted from job logs.
//
// The job runs `packer init`, `packer validate` and
// `packer build -color=false -machine-readable`, turning machine-readable
// output into readable log lines. Cancellation interrupts packer (so it can
// delete the build VM) and kills it after packer.interrupt_grace. Build
// history is kept in the packer_builds table and shown at /build.
package packer
