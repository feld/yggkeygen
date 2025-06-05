# Yggkeygen

This is a fork of [Yggdrasil's](https://github.com/yggdrasil-network/yggdrasil-go) code in the `cmd/genkeys` directory to provide a useful tool for generating Yggdrasil private keys and the associated IPv6 addresses.

## Usage

```
Usage: yggkeygen [options]

Yggkeygen generates Yggdrasil network keys. By default, it generates a single key
and outputs its details. The tool uses all available CPU cores to generate keys
as quickly as possible.

Options:
  -strong
        Generate the strongest possible key over 5 seconds
  -quiet
        Suppress all output except key information
  -json
        Output key information in JSON format
  -help
        Show this help message

Examples:
  yggkeygen              # Generate a single key
  yggkeygen -strong      # Search for 5 seconds to find the strongest key
  yggkeygen -quiet -json # Generate a single key, output only JSON
```

## License

This code is released under the terms of the LGPLv3, but with an added exception
that was shamelessly taken from [godeb](https://github.com/niemeyer/godeb).
Under certain circumstances, this exception permits distribution of binaries
that are (statically or dynamically) linked with this code, without requiring
the distribution of Minimal Corresponding Source or Minimal Application Code.
For more details, see: [LICENSE](LICENSE).
