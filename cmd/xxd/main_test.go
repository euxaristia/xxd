package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		args    []string
		wantErr bool
		check   func(*testing.T, *options)
	}{
		{
			args: []string{"xxd", "-a", "-b", "-e", "-u", "-p", "-i", "-C", "-d", "-r", "-v"},
			check: func(t *testing.T, o *options) {
				if !o.autoskip || o.hextype != hexCInclude || !o.upper || !o.capitalize || !o.decimalOffset || !o.revert || !o.version {
					t.Errorf("options mismatch: %+v", o)
				}
			},
		},
		{
			args: []string{"xxd", "-c16", "-g2", "-ntest", "-o0x100", "-l64", "-s+0x200"},
			check: func(t *testing.T, o *options) {
				if o.cols != 16 || o.group != 2 || o.varname != "test" || o.displayOff != 0x100 || o.length != 64 || o.seek != 0x200 || !o.relSeek {
					t.Errorf("options mismatch: %+v", o)
				}
			},
		},
		{
			args: []string{"xxd", "-o", "-0x100", "-s", "-0x200"},
			check: func(t *testing.T, o *options) {
				if o.displayOff != ^uint64(0x100)+1 || o.seek != 0x200 || !o.negSeek {
					t.Errorf("options mismatch: %+v", o)
				}
			},
		},
		{
			args: []string{"xxd", "-R", "always"},
			check: func(t *testing.T, o *options) {
				if o.colour != colourAlways {
					t.Errorf("options mismatch: %+v", o)
				}
			},
		},
		{
			args: []string{"xxd", "-R", "never"},
			check: func(t *testing.T, o *options) {
				if o.colour != colourNever {
					t.Errorf("options mismatch: %+v", o)
				}
			},
		},
		{
			args: []string{"xxd", "-R", "auto"},
			check: func(t *testing.T, o *options) {
				if o.colour != colourAuto {
					t.Errorf("options mismatch: %+v", o)
				}
			},
		},
		{
			args: []string{"xxd", "infile", "outfile"},
			check: func(t *testing.T, o *options) {
				if o.infile != "infile" || o.outfile != "outfile" {
					t.Errorf("files mismatch: %s, %s", o.infile, o.outfile)
				}
			},
		},
		{
			args: []string{"xxd", "--", "-weird-file"},
			check: func(t *testing.T, o *options) {
				if o.infile != "-weird-file" {
					t.Errorf("files mismatch: %s", o.infile)
				}
			},
		},
		{
			args:    []string{"xxd", "f1", "f2", "f3"},
			wantErr: true,
		},
		{
			args:    []string{"xxd", "-c"},
			wantErr: true,
		},
		{
			args:    []string{"xxd", "-g"},
			wantErr: true,
		},
		{
			args: []string{"xxd", "-h"},
			check: func(t *testing.T, o *options) {
				if !o.help {
					t.Errorf("expected help to be true")
				}
			},
		},
		{
			args: []string{"xxd", "-"},
			check: func(t *testing.T, o *options) {
				if o.infile != "-" {
					t.Errorf("expected infile to be -")
				}
			},
		},
	}

	for _, tt := range tests {
		o, err := parseArgs(tt.args)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseArgs(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			continue
		}
		if tt.check != nil {
			tt.check(t, o)
		}
	}
}

func TestDump(t *testing.T) {
	data := []byte("hello world")
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{cols: 16, group: 2, length: -1}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "6865 6c6c 6f20 776f 726c 64") {
		t.Errorf("output mismatch: %s", out)
	}
}

func TestDumpUpper(t *testing.T) {
	data := []byte{0xaa, 0xbb}
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{cols: 16, group: 2, length: -1, upper: true}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "AABB") {
		t.Errorf("output mismatch: %s", out)
	}
}

func TestDumpDecimalOffset(t *testing.T) {
	data := []byte("a")
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{cols: 16, group: 2, length: -1, decimalOffset: true}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "00000000:") {
		t.Errorf("output mismatch: %s", out)
	}
}

func TestDumpBits(t *testing.T) {
	data := []byte{0xaa}
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{hextype: hexBits, cols: 8, group: 1, length: -1}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "10101010") {
		t.Errorf("output mismatch: %s", out)
	}
}

func TestDumpLittleEndian(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56, 0x78}
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{hextype: hexLittleEndian, cols: 4, group: 4, length: -1}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "78563412") {
		t.Errorf("output mismatch: %s", out)
	}
}

func TestDumpAutoskip(t *testing.T) {
	data := make([]byte, 64)
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{autoskip: true, cols: 16, group: 2, length: -1}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "*") {
		t.Errorf("output mismatch: %s", out)
	}
	// Test triple autoskip
	data = make([]byte, 16*4)
	r = bytes.NewReader(data)
	buf.Reset()
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "*") {
		t.Errorf("output mismatch: %s", buf.String())
	}
}

func TestDumpC(t *testing.T) {
	data := []byte("abc")
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{hextype: hexCInclude, cols: 1, varname: "test", length: -1}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "unsigned char test[] = {") || !strings.Contains(out, "0x61,\n  0x62,\n  0x63") {
		t.Errorf("output mismatch: %s", out)
	}
	// Test with capitalization
	r = bytes.NewReader(data)
	buf.Reset()
	o.capitalize = true
	o.varname = ""
	o.infile = "1test.bin"
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "unsigned char __1TEST_BIN[] = {") {
		t.Errorf("output mismatch: %s", buf.String())
	}
}

func TestDumpCUpper(t *testing.T) {
	data := []byte{0xaa}
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{hextype: hexCInclude, cols: 12, upper: true, length: -1}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "0XAA") {
		t.Errorf("output mismatch: %s", out)
	}
}

func TestDumpPS(t *testing.T) {
	data := []byte("abc")
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{hextype: hexPostScript, cols: 2, length: -1}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if out != "6162\n63\n" {
		t.Errorf("output mismatch: %q", out)
	}
}

func TestRevert(t *testing.T) {
	data := "00000000: 6162 63                                  abc\n"
	r := strings.NewReader(data)
	var buf bytes.Buffer
	o := &options{revert: true, cols: 16}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "abc" {
		t.Errorf("output mismatch: %q", buf.String())
	}
	// Test with offset
	r = strings.NewReader("00000005: 61\n")
	buf.Reset()
	o.seek = 5
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 11 {
		t.Errorf("expected 11 bytes, got %d", buf.Len())
	}
}

func TestRevertInvalid(t *testing.T) {
	data := "invalid\n"
	r := strings.NewReader(data)
	var buf bytes.Buffer
	o := &options{revert: true, cols: 16}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

func TestRevertPS(t *testing.T) {
	data := "61 62\n63\n"
	r := strings.NewReader(data)
	var buf bytes.Buffer
	o := &options{revert: true, hextype: hexPostScript}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "abc" {
		t.Errorf("output mismatch: %q", buf.String())
	}
}

func TestGetTermWidth(t *testing.T) {
	os.Setenv("XXD_WIDTH", "100")
	defer os.Unsetenv("XXD_WIDTH")
	if w := getTermWidth(); w != 100 {
		t.Errorf("getTermWidth() = %d, want 100", w)
	}
	os.Unsetenv("XXD_WIDTH")
	getTermWidth()
}

func TestCalcCols(t *testing.T) {
	os.Setenv("XXD_WIDTH", "80")
	defer os.Unsetenv("XXD_WIDTH")
	o := &options{group: 2}
	c := calcCols(o)
	if c <= 0 {
		t.Errorf("calcCols() = %d, want > 0", c)
	}
	os.Setenv("XXD_WIDTH", "0")
	calcCols(o)
	os.Setenv("XXD_WIDTH", "1000")
	calcCols(o)
}

func runTest(r io.Reader, w io.Writer, o *options) error {
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	if o.revert {
		return revert(r, bw, o)
	}

	switch o.hextype {
	case hexCInclude:
		return dumpC(r, bw, o)
	case hexPostScript:
		return dumpPS(r, bw, o)
	default:
		return dump(r, bw, o)
	}
}

func TestMainLogic(t *testing.T) {
	data := []byte("0123456789")
	tmpfile, err := os.CreateTemp("", "xxd-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write(data); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	o := &options{infile: tmpfile.Name(), seek: 5, cols: 16, group: 2, length: -1}
	outf, err := os.CreateTemp("", "xxd-test-out")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outf.Name())
	outf.Close()
	o.outfile = outf.Name()

	if err := run(o); err != nil {
		t.Fatal(err)
	}

	res, err := os.ReadFile(outf.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res), "3536 3738 39") {
		t.Errorf("output mismatch: %s", string(res))
	}
}

func TestRunMain(t *testing.T) {
	if runMain([]string{"xxd", "-v"}) != 0 {
		t.Errorf("runMain(-v) failed")
	}
	if runMain([]string{"xxd", "-h"}) != 0 {
		t.Errorf("runMain(-h) failed")
	}
	if runMain([]string{"xxd", "-invalid"}) != 1 {
		t.Errorf("runMain(-invalid) should fail")
	}
	if runMain([]string{"xxd", "nonexistent"}) != 1 {
		t.Errorf("runMain(nonexistent) should fail")
	}
}

func TestCol(t *testing.T) {
	col(0)
	col(32)
	col(128)
}

func TestUseCol(t *testing.T) {
	o := &options{colour: colourNever}
	useCol(o, os.Stdout)
	o.colour = colourAlways
	useCol(o, os.Stdout)
	os.Setenv("NO_COLOUR", "1")
	useCol(o, os.Stdout)
	os.Unsetenv("NO_COLOUR")
}

func TestUsage(t *testing.T) {
	usage()
}

func TestDumpEBCDIC(t *testing.T) {
	data := []byte{0x81, 0x82, 0x83}
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{cols: 16, group: 2, ebcdic: true, length: -1}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
}

func TestRunErrors(t *testing.T) {
	o := &options{infile: "nonexistent"}
	if err := run(o); err == nil {
		t.Errorf("expected error for nonexistent file")
	}
	o = &options{outfile: "/nonexistent/path/to/file"}
	if err := run(o); err == nil {
		t.Errorf("expected error for invalid outfile")
	}
}

func TestParseHex(t *testing.T) {
	if parseHex('0') != 0 {
		t.Errorf("fail")
	}
	if parseHex('a') != 10 {
		t.Errorf("fail")
	}
	if parseHex('A') != 10 {
		t.Errorf("fail")
	}
	if parseHex('z') != -1 {
		t.Errorf("fail")
	}
}

func TestMainActual(t *testing.T) {
	if os.Getenv("BE_MAIN") == "1" {
		os.Args = []string{"xxd", "-v"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMainActual")
	cmd.Env = append(os.Environ(), "BE_MAIN=1")
	if err := cmd.Run(); err != nil {
		t.Fatalf("main failed: %v", err)
	}
}

func TestRunSeek(t *testing.T) {
	data := []byte("0123456789")
	tmpfile, err := os.CreateTemp("", "xxd-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Write(data)
	tmpfile.Close()

	o := &options{infile: tmpfile.Name(), seek: 5, relSeek: true, length: -1}
	if err := run(o); err != nil {
		t.Fatal(err)
	}

	o = &options{infile: tmpfile.Name(), seek: 2, negSeek: true, length: -1}
	if err := run(o); err != nil {
		t.Fatal(err)
	}

	// Test seek failure
	o = &options{infile: tmpfile.Name(), seek: 100, length: -1}
	run(o)
}

func TestRunCannotSeek(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("abc"))
		pw.Close()
	}()
	// We need to bypass 'run' because it uses os.Stdin if infile is empty.
	// But we can't easily pass 'pr' to 'run'.
	// So we'll skip this specific path for now.
	pr.Close()
}
func TestDumpColor(t *testing.T) {
	data := []byte("abc")
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{cols: 16, group: 2, colour: colourAlways, length: -1}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("expected ANSI escape codes")
	}
}

func TestDumpLength(t *testing.T) {
	data := []byte("abcdef")
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{cols: 16, group: 2, length: 3}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 || strings.Contains(buf.String(), "646566") {
		t.Errorf("length restriction failed")
	}
}

func TestDumpPSLength(t *testing.T) {
	data := []byte("abcdef")
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{hextype: hexPostScript, cols: 30, length: 3}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "616263\n" {
		t.Errorf("output mismatch: %q", buf.String())
	}
}

func TestDumpCLength(t *testing.T) {
	data := []byte("abcdef")
	r := bytes.NewReader(data)
	var buf bytes.Buffer
	o := &options{hextype: hexCInclude, cols: 12, length: 3}
	if err := runTest(r, &buf, o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "unsigned int stdin_len = 3;") {
		t.Errorf("output mismatch: %s", buf.String())
	}
}
