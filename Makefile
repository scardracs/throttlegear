VERSION = $(shell grep '^version =' Cargo.toml | cut -d '"' -f 2)

all:
	PATH="/usr/bin" cargo build --release
	cp target/release/throttlegear ThrottleGear-$(VERSION)

clean:
	PATH="/usr/bin" cargo clean
	rm -f ThrottleGear-$(VERSION)
