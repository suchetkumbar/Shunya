// Package labtests holds tests that open real block devices. They are compiled only with
// -tags labtest, by `make lab-test`, into a token-bearing binary that lab/lab.sh runs as
// root inside the QEMU lab VM. On any other machine the backend's lab lock refuses every
// device they try to open.
package labtests
