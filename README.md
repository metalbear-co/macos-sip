# macos-sip

This is a utility crate for [mirrord](https://github.com/metalbear-co/mirrord) to help it inject `mirrord-layer` into macOS' SIP protected binaries.
It is released as open source, licensed under MIT, and is not affiliated with Apple in any way.
This crate isn't developed for security/breach purposes, but to help developers debug their applications.
We don't publish it to crates.io, but you can still use it by adding the following to your `Cargo.toml`:

```toml
[dependencies]
macos-sip = { git = "https://github.com/metalbear-co/macos-sip" }
```

In case there will be a demand we'll start publishing it also to crates.io.


## CHANGELOG
[Here](./CHANGELOG.md)

## License
[MIT](./LICENSE)

