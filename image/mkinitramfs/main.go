// Command mkinitramfs builds the Shunya live image's initramfs reproducibly. It runs in
// the lab VM (image/build.sh), never on the host:
//
//	mkinitramfs -root STAGING -modules lib/modules/VER -want nvme,ext4,… -epoch N -o initramfs.gz
//
// It packs every file under STAGING in sorted order, adds /dev/console and /dev/null
// (header-only cpio entries), resolves the wanted kernel modules and their dependencies
// from modules.dep, decompresses them, and writes their load order to
// etc/shunya/modules.order for init. Owners are root, times are -epoch, gzip has no
// timestamp: the same inputs give the same bytes.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"shunya/internal/cpio"
)

func main() {
	root := flag.String("root", "", "staging directory (the initramfs tree)")
	mods := flag.String("modules", "", "kernel module directory (lib/modules/VERSION from the kernel package)")
	want := flag.String("want", "", "comma-separated module names to include, with their dependencies")
	epoch := flag.Int64("epoch", -1, "modification time of every entry (SOURCE_DATE_EPOCH)")
	out := flag.String("o", "", "output file (gzip-compressed newc cpio)")
	list := flag.String("list", "", "optional: write the sha256 of every file here")
	flag.Parse()
	if *root == "" || *mods == "" || *out == "" || *epoch < 0 || *epoch > 1<<32-1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*root, *mods, splitList(*want), uint32(*epoch), *out, *list); err != nil {
		fmt.Fprintln(os.Stderr, "mkinitramfs:", err)
		os.Exit(1)
	}
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func run(root, modDir string, want []string, epoch uint32, out, list string) error {
	var arc bytes.Buffer
	sums, err := build(&arc, os.DirFS(root), os.DirFS(modDir), filepath.Base(modDir), want, epoch)
	if err != nil {
		return err
	}
	var gz bytes.Buffer
	zw, err := gzip.NewWriterLevel(&gz, gzip.BestCompression) // header: no name, no mtime
	if err != nil {
		return err
	}
	if _, err := zw.Write(arc.Bytes()); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(out, gz.Bytes(), 0o644); err != nil {
		return err
	}
	if list != "" {
		return os.WriteFile(list, []byte(strings.Join(sums, "\n")+"\n"), 0o644)
	}
	return nil
}

// build writes the archive and returns "sha256  name" lines for every regular file.
func build(w io.Writer, root, mods fs.FS, kver string, want []string, epoch uint32) ([]string, error) {
	order, err := resolveModules(mods, want)
	if err != nil {
		return nil, err
	}
	a := cpio.NewWriter(w, epoch)
	var sums []string
	dirs := map[string]bool{}
	mkdirs := func(p string) error {
		var parts []string
		for d := path.Dir(p); d != "."; d = path.Dir(d) {
			parts = append(parts, d)
		}
		for _, d := range slices.Backward(parts) {
			if !dirs[d] {
				dirs[d] = true
				if err := a.Dir(d); err != nil {
					return err
				}
			}
		}
		return nil
	}
	addFile := func(name string, perm uint32, data []byte) error {
		if err := mkdirs(name); err != nil {
			return err
		}
		sums = append(sums, fmt.Sprintf("%x  %s", sha256.Sum256(data), name))
		return a.File(name, perm, data)
	}

	// The staging tree, sorted (WalkDir visits in lexical order).
	err = fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := mkdirs(p); err != nil {
				return err
			}
			if !dirs[p] {
				dirs[p] = true
				return a.Dir(p)
			}
			return nil
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := fs.ReadLink(root, p)
			if err != nil {
				return err
			}
			if err := mkdirs(p); err != nil {
				return err
			}
			return a.Symlink(p, target)
		case info.Mode().IsRegular():
			b, err := fs.ReadFile(root, p)
			if err != nil {
				return err
			}
			perm := uint32(0o644)
			if info.Mode()&0o111 != 0 {
				perm = 0o755
			}
			return addFile(p, perm, b)
		}
		return fmt.Errorf("%s: unsupported file type %v (device nodes are added by mkinitramfs itself)", p, info.Mode().Type())
	})
	if err != nil {
		return nil, err
	}

	for _, n := range []struct {
		name         string
		perm, ma, mi uint32
	}{{"dev/console", 0o600, 5, 1}, {"dev/null", 0o666, 1, 3}} {
		if err := mkdirs(n.name); err != nil {
			return nil, err
		}
		if err := a.CharDev(n.name, n.perm, n.ma, n.mi); err != nil {
			return nil, err
		}
	}

	var loadOrder []string
	for _, m := range order {
		b, err := readModule(mods, m)
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(strings.TrimSuffix(m, ".gz"), ".zst")
		if err := addFile(path.Join("lib/modules", kver, name), 0o644, b); err != nil {
			return nil, err
		}
		loadOrder = append(loadOrder, path.Join(kver, name))
	}
	if err := addFile("etc/shunya/modules.order", 0o644, []byte(strings.Join(loadOrder, "\n")+"\n")); err != nil {
		return nil, err
	}
	return sums, a.Close()
}

func readModule(mods fs.FS, p string) ([]byte, error) {
	b, err := fs.ReadFile(mods, p)
	if err != nil {
		return nil, err
	}
	switch {
	case strings.HasSuffix(p, ".ko"):
		return b, nil
	case strings.HasSuffix(p, ".ko.gz"):
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		return io.ReadAll(io.LimitReader(zr, 64<<20))
	}
	return nil, fmt.Errorf("%s: unsupported module compression (want .ko or .ko.gz)", p)
}

// modName is a module's name as modprobe compares it: base name without .ko[.gz], with
// '-' and '_' equivalent.
func modName(p string) string {
	b := path.Base(p)
	b = strings.TrimSuffix(strings.TrimSuffix(b, ".gz"), ".ko")
	return strings.ReplaceAll(b, "-", "_")
}

// resolveModules reads modules.dep and returns the wanted modules with their
// dependencies, dependencies first. Modules built into the kernel (listed in
// modules.builtin) need nothing; a wanted name that is neither is an error.
func resolveModules(mods fs.FS, want []string) ([]string, error) {
	dep, err := fs.ReadFile(mods, "modules.dep")
	if err != nil {
		return nil, err
	}
	deps := map[string][]string{}
	byName := map[string]string{}
	for i, line := range strings.Split(string(dep), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		mod, rest, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("modules.dep line %d: no ':'", i+1)
		}
		deps[mod] = strings.Fields(rest)
		byName[modName(mod)] = mod
	}
	builtin := map[string]bool{}
	if b, err := fs.ReadFile(mods, "modules.builtin"); err == nil {
		for _, l := range strings.Fields(string(b)) {
			builtin[modName(l)] = true
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	var order []string
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(m string, chain []string) error
	visit = func(m string, chain []string) error {
		switch state[m] {
		case 1:
			return fmt.Errorf("module dependency cycle: %s", strings.Join(append(chain, m), " → "))
		case 2:
			return nil
		}
		state[m] = 1
		ds, ok := deps[m]
		if !ok {
			return fmt.Errorf("modules.dep names %s, which it does not list", m)
		}
		for _, d := range ds {
			if err := visit(d, append(chain, m)); err != nil {
				return err
			}
		}
		state[m] = 2
		order = append(order, m)
		return nil
	}
	for _, w := range want {
		n := strings.ReplaceAll(w, "-", "_")
		m, ok := byName[n]
		if !ok {
			if builtin[n] {
				continue
			}
			return nil, fmt.Errorf("module %s is neither in modules.dep nor built in", w)
		}
		if err := visit(m, nil); err != nil {
			return nil, err
		}
	}
	return order, nil
}
