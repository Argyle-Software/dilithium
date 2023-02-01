# Benchmarking

This library uses the criterion benchmarking suite. To use you must enable
`bench` in `RUSTFLAGS` eg.

```shell
RUSTFLAGS="--cfg bench" cargo bench
```