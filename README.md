# ssurl

Convert SIP002 schema URI to a variable of configurations.

Usage

	ssurl 0.1.0
	bugnofree <pwnkeeper@gmail.com>
	Convert SIP002 schema URL to variable configuration files.

	USAGE:
		ssurl [OPTIONS] [uri]

	FLAGS:
		-h, --help       Prints help information
		-V, --version    Prints version information

	OPTIONS:
		-F, --format <FORMAT>    android for shadowsocks-android, rust shdowsocks-rust, sip002 for standard SIP002 URL
								 (valid for shadowsocksX-NG as well).
		-i, --input <FILE>       The path to sip002 file.
		-o, --output <OUTPUT>    The file path to save the converted result.

	ARGS:
		<uri>    Convert a single SIP002 URL, if passed as a command line parameter, put the URL in double quote.

Examples

	ssurl -i ~/Downloads/sip002.txt -F rust -o rust.json
	The result is saved into rust.json

# TODO

Item marked as `-` is to be done, `+` item has been implemented.

- [+] shadowsocks-xng configuration
- [+] shadowsocks-rust configuration
- [+] shadowsocks-android configuration

