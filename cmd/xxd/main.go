package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unsafe"
)

type hexType int

const (
	hexNormal hexType = iota
	hexPostScript
	hexCInclude
	hexBits
	hexLittleEndian
)

type colourMode int

const (
	colourNever colourMode = iota
	colourAlways
	colourAuto
)

type options struct {
	autoskip      bool
	capitalize    bool
	cols          int
	colsgiven     bool
	ebcdic        bool
	hextype       hexType
	group         int
	varname       string
	length        int64
	displayOff    uint64
	revert        bool
	decimalOffset bool
	seek          int64
	relSeek       bool
	negSeek       bool
	upper         bool
	version       bool
	infile        string
	outfile       string
	colour        colourMode
}

var (
	versionStr = "xxd-go 2026-02-15 by Gemini CLI (Ken Thompson's simplicity style)"
	etoa64     = []byte{
		0040, 0240, 0241, 0242, 0243, 0244, 0245, 0246,
		0247, 0250, 0325, 0056, 0074, 0050, 0053, 0174,
		0046, 0251, 0252, 0253, 0254, 0255, 0256, 0257,
		0260, 0261, 0041, 0044, 0052, 0051, 0073, 0176,
		0055, 0057, 0262, 0263, 0264, 0265, 0266, 0267,
		0270, 0271, 0313, 0054, 0045, 0137, 0076, 0077,
		0272, 0273, 0274, 0275, 0276, 0277, 0300, 0301,
		0302, 0140, 0072, 0043, 0100, 0047, 0075, 0042,
		0303, 0141, 0142, 0143, 0144, 0145, 0146, 0147,
		0150, 0151, 0304, 0305, 0306, 0307, 0310, 0311,
		0312, 0152, 0153, 0154, 0155, 0156, 0157, 0160,
		0161, 0162, 0136, 0314, 0315, 0316, 0317, 0320,
		0321, 0345, 0163, 0164, 0165, 0166, 0167, 0170,
		0171, 0172, 0322, 0323, 0324, 0133, 0326, 0327,
		0330, 0331, 0332, 0333, 0334, 0335, 0336, 0337,
		0340, 0341, 0342, 0343, 0344, 0135, 0346, 0347,
		0173, 0101, 0102, 0103, 0104, 0105, 0106, 0107,
		0110, 0111, 0350, 0351, 0352, 0353, 0354, 0355,
		0175, 0112, 0113, 0114, 0115, 0116, 0117, 0120,
		0121, 0122, 0356, 0357, 0360, 0361, 0362, 0363,
		0134, 0237, 0123, 0124, 0125, 0126, 0127, 0130,
		0131, 0132, 0364, 0365, 0366, 0367, 0370, 0371,
		0060, 0061, 0062, 0063, 0064, 0065, 0066, 0067,
		0070, 0071, 0372, 0373, 0374, 0375, 0376, 0377,
	}
)

func getTermWidth() int {
	if w, err := strconv.Atoi(os.Getenv("XXD_WIDTH")); err == nil {
		return w
	}
	var sz struct {
		rows, cols, xpix, ypix uint16
	}
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(os.Stdout.Fd()),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&sz)))
	return int(sz.cols)
}

func main() {
	opts, err := parseArgs(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xxd:", err)
		os.Exit(1)
	}
	if opts.version {
		fmt.Fprintln(os.Stderr, versionStr)
		os.Exit(0)
	}
	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "xxd: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: xxd [options] [infile [outfile]]\nOptions:\n")
	fmt.Fprintf(os.Stderr, "  -a       autoskip\n  -b       bits\n  -c cols  columns\n  -e       little-endian\n")
	fmt.Fprintf(os.Stderr, "  -g bytes group size\n  -i       C include\n  -l len   length\n  -o off   offset\n")
	fmt.Fprintf(os.Stderr, "  -ps      postscript\n  -r       revert\n  -R when  colour (never, always, auto)\n")
	fmt.Fprintf(os.Stderr, "  -s seek  seek\n  -u       upper case\n  -v       version\n")
}

func calcCols(o *options) int {
	tw := getTermWidth()
	if tw <= 0 {
		return 16
	}
	c := 1
	for {
		w := 12 + 3*c + (c-1)/o.group
		if w > tw {
			c--
			break
		}
		if c >= 256 {
			break
		}
		c++
	}
	if c <= 0 {
		return 1
	}
	return c
}

func parseArgs(args []string) (*options, error) {
	o := &options{cols: 0, group: -1, length: -1, colour: colourAuto}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "" || a[0] != '-' || a == "-" {
			if o.infile == "" {
				o.infile = a
			} else if o.outfile == "" {
				o.outfile = a
			} else {
				return nil, fmt.Errorf("too many arguments")
			}
			continue
		}
		if a == "--" {
			for j := i + 1; j < len(args); j++ {
				if o.infile == "" {
					o.infile = args[j]
				} else if o.outfile == "" {
					o.outfile = args[j]
				}
			}
			break
		}
		p := a[1:]
		if strings.HasPrefix(p, "-") {
			p = p[1:]
		}
		switch {
		case p == "a":
			o.autoskip = !o.autoskip
		case p == "b":
			o.hextype = hexBits
		case p == "e":
			o.hextype = hexLittleEndian
		case p == "u":
			o.upper = true
		case p == "p" || p == "ps":
			o.hextype = hexPostScript
		case p == "i":
			o.hextype = hexCInclude
		case p == "C" || p == "capitalize":
			o.capitalize = true
		case p == "d":
			o.decimalOffset = true
		case p == "r":
			o.revert = true
		case p == "v":
			o.version = true
		case p == "h":
			usage()
			os.Exit(0)
		case strings.HasPrefix(p, "c"):
			v, err := getVal(p[1:], args, &i)
			if err != nil {
				return nil, err
			}
			o.cols, _ = strconv.Atoi(v)
			o.colsgiven = true
		case strings.HasPrefix(p, "g"):
			v, err := getVal(p[1:], args, &i)
			if err != nil {
				return nil, err
			}
			o.group, _ = strconv.Atoi(v)
		case strings.HasPrefix(p, "n"):
			o.varname, _ = getVal(p[1:], args, &i)
		case strings.HasPrefix(p, "o"):
			v, _ := getVal(p[1:], args, &i)
			neg := strings.HasPrefix(v, "-")
			if neg || strings.HasPrefix(v, "+") {
				v = v[1:]
			}
			u, _ := strconv.ParseUint(v, 0, 64)
			if neg {
				o.displayOff = ^u + 1
			} else {
				o.displayOff = u
			}
		case strings.HasPrefix(p, "l"):
			v, _ := getVal(p[1:], args, &i)
			o.length, _ = strconv.ParseInt(v, 0, 64)
		case strings.HasPrefix(p, "s"):
			v, _ := getVal(p[1:], args, &i)
			if strings.HasPrefix(v, "+") {
				o.relSeek = true
				v = v[1:]
			}
			if strings.HasPrefix(v, "-") {
				o.negSeek = true
				v = v[1:]
			}
			o.seek, _ = strconv.ParseInt(v, 0, 64)
		case p == "R":
			v, _ := getVal("", args, &i)
			switch v {
			case "never":
				o.colour = colourNever
			case "always":
				o.colour = colourAlways
			default:
				o.colour = colourAuto
			}
		}
	}

	if o.group == -1 {
		d := map[hexType]int{hexBits: 1, hexNormal: 2, hexLittleEndian: 4}
		o.group = d[o.hextype]
		if o.group == 0 {
			o.group = 1
		}
	}

	if !o.colsgiven && o.hextype != hexCInclude && o.hextype != hexPostScript {
		o.cols = calcCols(o)
	}

	if o.cols == 0 {
		d := map[hexType]int{hexPostScript: 30, hexCInclude: 12, hexBits: 6, hexNormal: 16, hexLittleEndian: 16}
		o.cols = d[o.hextype]
	}

	return o, nil
}

func getVal(rem string, args []string, i *int) (string, error) {
	if rem != "" {
		return rem, nil
	}
	if *i+1 < len(args) {
		*i++
		return args[*i], nil
	}
	return "", fmt.Errorf("missing argument")
}

func run(o *options) error {
	in := io.Reader(os.Stdin)
	if o.infile != "" && o.infile != "-" {
		f, err := os.Open(o.infile)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	out := io.Writer(os.Stdout)
	if o.outfile != "" && o.outfile != "-" {
		f, err := os.Create(o.outfile)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	bw := bufio.NewWriter(out)
	defer bw.Flush()

	if o.revert {
		return revert(in, bw, o)
	}

	if o.seek != 0 || o.negSeek {
		if rs, ok := in.(io.ReadSeeker); ok {
			wh := io.SeekStart
			if o.relSeek {
				wh = io.SeekCurrent
			} else if o.negSeek {
				wh = io.SeekEnd
			}
			off := o.seek
			if o.negSeek && !o.relSeek {
				off = -off
			}
			if _, err := rs.Seek(off, wh); err == nil {
				goto seekDone
			}
		}
		if o.seek > 0 && !o.negSeek {
			io.CopyN(io.Discard, in, o.seek)
		} else {
			return fmt.Errorf("cannot seek")
		}
	}
seekDone:

	switch o.hextype {
	case hexCInclude:
		return dumpC(in, bw, o)
	case hexPostScript:
		return dumpPS(in, bw, o)
	default:
		return dump(in, bw, o)
	}
}

func useCol(o *options, w io.Writer) bool {
	if o.colour == colourNever || os.Getenv("NO_COLOUR") != "" {
		return false
	}
	if o.colour == colourAlways {
		return true
	}
	s, _ := os.Stdout.Stat()
	return (s.Mode() & os.ModeCharDevice) != 0
}

func col(b byte) string {
	if b == 0 {
		return "\x1b[2m"
	}
	if b > 31 && b < 127 {
		return "\x1b[1;32m"
	}
	return "\x1b[1;33m"
}

func dump(r io.Reader, w *bufio.Writer, o *options) error {
	hx := "0123456789abcdef"
	if o.upper {
		hx = "0123456789ABCDEF"
	}
	clr := useCol(o, w)
	
	// Handle window resize
	winch := make(chan os.Signal, 1)
	if !o.colsgiven && o.hextype != hexCInclude && o.hextype != hexPostScript {
		signal.Notify(winch, syscall.SIGWINCH)
	}

	var total int64
	var zseen int
	var zline string
	for {
		if !o.colsgiven {
			select {
			case <-winch:
				o.cols = calcCols(o)
			default:
			}
		}
		b := make([]byte, o.cols)
		n, err := io.ReadFull(r, b)
		if n == 0 {
			break
		}
		if o.length != -1 && total+int64(n) > o.length {
			n = int(o.length - total)
			if n <= 0 {
				break
			}
		}
		isz := true
		for i := 0; i < n; i++ {
			if b[i] != 0 {
				isz = false
				break
			}
		}
		off := uint64(total) + uint64(o.seek) + o.displayOff
		as := fmt.Sprintf("%08x", off)
		if o.decimalOffset {
			as = fmt.Sprintf("%08d", off)
		}
		cn := ":"
		if clr {
			as = "\x1b[2m" + as + "\x1b[0m"
			cn = "\x1b[2m" + cn + "\x1b[0m"
		}
		var l strings.Builder
		l.WriteString(as + cn)
		for i := 0; i < o.cols; i++ {
			if i%o.group == 0 {
				l.WriteByte(' ')
			}
			if i < n {
				x := i
				if o.hextype == hexLittleEndian {
					x = i ^ (o.group - 1)
					if x >= n {
						l.WriteString("  ")
						continue
					}
				}
				if clr {
					l.WriteString(col(b[x]))
				}
				if o.hextype == hexBits {
					for j := 7; j >= 0; j-- {
						if b[x]&(1<<uint(j)) != 0 {
							l.WriteByte('1')
						} else {
							l.WriteByte('0')
						}
					}
				} else {
					l.WriteByte(hx[b[x]>>4])
					l.WriteByte(hx[b[x]&0xf])
				}
				if clr {
					l.WriteString("\x1b[0m")
				}
			} else {
				if o.hextype == hexBits {
					l.WriteString("        ")
				} else {
					l.WriteString("  ")
				}
			}
		}
		l.WriteString("  ")
		for i := 0; i < n; i++ {
			c := b[i]
			if o.ebcdic {
				if c < 64 {
					c = '.'
				} else {
					c = etoa64[c-64]
				}
			}
			if clr {
				l.WriteString(col(b[i]))
			}
			if c > 31 && c < 127 {
				l.WriteByte(c)
			} else {
				l.WriteByte('.')
			}
			if clr {
				l.WriteString("\x1b[0m")
			}
		}
		l.WriteByte('\n')
		line := l.String()
		if o.autoskip && isz && n == o.cols {
			if zseen == 1 {
				zline = line
			}
			zseen++
			total += int64(n)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			continue
		}
		if zseen > 1 {
			if zseen == 2 {
				w.WriteString(zline)
			} else {
				w.WriteString("*\n")
			}
		}
		zseen = 0
		w.WriteString(line)
		total += int64(n)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}
	if zseen > 1 {
		if zseen == 2 {
			w.WriteString(zline)
		} else {
			w.WriteString("*\n")
		}
	}
	return nil
}

func dumpPS(r io.Reader, w *bufio.Writer, o *options) error {
	hx := "0123456789abcdef"
	if o.upper {
		hx = "0123456789ABCDEF"
	}
	b := make([]byte, 1)
	var n int64
	c := 0
	for {
		if o.length != -1 && n >= o.length {
			break
		}
		if _, err := r.Read(b); err != nil {
			break
		}
		w.WriteByte(hx[b[0]>>4])
		w.WriteByte(hx[b[0]&0xf])
		n++
		c++
		if o.cols > 0 && c >= o.cols {
			w.WriteByte('\n')
			c = 0
		}
	}
	if c > 0 || o.cols == 0 {
		w.WriteByte('\n')
	}
	return nil
}

func dumpC(r io.Reader, w *bufio.Writer, o *options) error {
	vn := o.varname
	if vn == "" {
		vn = filepath.Base(o.infile)
		if vn == "." || vn == "-" {
			vn = "stdin"
		}
		var s strings.Builder
		for i, r := range vn {
			if i == 0 && unicode.IsDigit(r) {
				s.WriteString("__")
			}
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				if o.capitalize {
					s.WriteRune(unicode.ToUpper(r))
				} else {
					s.WriteRune(r)
				}
			} else {
				s.WriteByte('_')
			}
		}
		vn = s.String()
	}
	fmt.Fprintf(w, "unsigned char %s[] = {\n", vn)
	b := make([]byte, 1)
	var n int
	for {
		if o.length != -1 && int64(n) >= o.length {
			break
		}
		if _, err := r.Read(b); err != nil {
			break
		}
		if n > 0 {
			if n%o.cols == 0 {
				w.WriteString(",\n  ")
			} else {
				w.WriteString(", ")
			}
		} else {
			w.WriteString("  ")
		}
		if o.upper {
			fmt.Fprintf(w, "0X%02X", b[0])
		} else {
			fmt.Fprintf(w, "0x%02x", b[0])
		}
		n++
	}
	fmt.Fprintf(w, "\n};\nunsigned int %s_len = %d;\n", vn, n)
	return nil
}

func parseHex(c byte) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	if c >= 'a' && c <= 'f' {
		return int(c - 'a' + 10)
	}
	if c >= 'A' && c <= 'F' {
		return int(c - 'A' + 10)
	}
	return -1
}

func revert(r io.Reader, w *bufio.Writer, o *options) error {
	var n1 = -1
	var n2 = 0
	var p = o.cols
	var have, want int64
	base := o.seek
	if o.negSeek {
		base = -base
	}

	br := bufio.NewReader(r)
	for {
		c, err := br.ReadByte()
		if err != nil {
			break
		}
		if c == '\r' || (o.hextype == hexPostScript && (c == ' ' || c == '\n' || c == '\t')) {
			continue
		}
		n3 := n2
		n2 = n1
		n1 = parseHex(c)
		if n1 == -1 && n2 == -1 && n3 == -1 {
			// Skip line
			for c != '\n' && err == nil {
				c, err = br.ReadByte()
			}
			p, n1, n2 = o.cols, -1, 0
			continue
		}
		if o.hextype == hexNormal && p >= o.cols {
			if n1 >= 0 {
				want = (want << 4) | int64(n1)
			} else {
				p = 0
			}
			continue
		}
		if base+want != have {
			for have < base+want {
				w.WriteByte(0)
				have++
			}
		}
		if n2 >= 0 && n1 >= 0 {
			w.WriteByte(byte((n2 << 4) | n1))
			have++
			want++
			n1 = -1
			if o.hextype == hexNormal {
				p++
				if p >= o.cols {
					for c != '\n' && err == nil {
						c, err = br.ReadByte()
					}
				}
			}
		}
		if c == '\n' {
			if o.hextype == hexNormal {
				want = 0
			}
			p = o.cols
		}
	}
	return nil
}
