# Quick Network Scanner

Quick Network Scanner project includes:

* [qscan](./qscan/README.md): a rust library for asynchronous network ports
  scanning (see [README](./qscan/README.md)).
* [qsc](./qsc/README.md): a command line utility built on top of qscan library
  for quick network scanning activities (see [README](./qsc/README.md)).

NOTE: in order to properly use the library and the command line utility provided
by this project you may need to increase the maximum allowed open files. E.g.:

```bash
ulimit -n 10000
```

## Quick Scan Example

Install `qsc` with:

```bash
cargo install qsc
```

run the scanner:

```bash
qsc --targets www.google.com --ports 1-1024
```

for more details, see the [qscan library](./qscan/README.md) and
[qsc utility](./qsc/README.md) READMEs.

## Related Projects

* [RustScan](https://github.com/RustScan/RustScan)
