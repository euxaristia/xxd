# xxd

A hex-dump utility rewritten in Go, following Ken Thompson's philosophy of simplicity and efficiency.

## Features

- Normal, bits, little-endian, postscript, and C-include dump styles.
- Reversal operation (convert hexdump back to binary).
- Colour output support (printable vs non-printable characters).
- British spelling for all flags and messages.
- Efficient I/O using `bufio`.

## Build

Building `xxd` requires Go 1.16 or later.

```sh
go build -o xxd github.com/euxaristia/xxd/cmd/xxd
```

## Usage

```
Usage: xxd [options] [infile [outfile]]
Options:
  -a       autoskip
  -b       bits
  -c cols  columns
  -e       little-endian
  -g bytes group size
  -i       C include
  -l len   length
  -o off   offset
  -ps      postscript
  -r       revert
  -R when  colour (never, always, auto)
  -s seek  seek
  -u       upper case
  -v       version
```

## License

Original `xxd` licensed under GPL-2.0. This Go port retains the same compatibility.
Other parts licensed under BSL 1.0.
