# uuid6-zig

This is a prototype [UUIDv6](https://github.com/uuid6/uuid6-ietf-draft) draft 03 implementation in [Zig](https://github.com/ziglang/zig). It also includes versions 1 & 3-5 for comparison.

## Installation

The library is contained entirely in `src/Uuid.zig`. Feel free to copy and customize or clone it as a submodule.

It targets Zig `master` and may not work on the latest release.

### Adding to your build.zig

```zig
libOrExe.addPackagePath("uuid6", "path/to/uuid6-zig/src/Uuid.zig");
```

## Usage

There are namespaces for the various UUID versions, `v1`, `v3` - `v7`. Each has a `create(...)` method to create a single UUID, or a `Source` that can be used to create many with shared parameters and/or state.

Sources are not thread-safe and should be protected with a mutex.

### Example

```zig
const std = @import("std");
const Uuid = @import("uuid6");

pub fn main() anyerror!void {
    var rng = std.rand.DefaultPrng.init(0);
    const source = Uuid.v4.Source.init(&rng.random);

    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const uuid = source.create();
        std.debug.print("{}\n", .{uuid});
    }
}
```

See also `examples/bench`.

## Performance

The following tables were generated by [hyperfine](https://github.com/sharkdp/hyperfine) running `examples/bench`.

Note that the times are for 1e7 UUIDs, so for example each v4 takes ~12ns, and each v3 takes ~99ns.

### Thread-safe

| Command | Mean [ms] | Min [ms] | Max [ms] | Relative |
|:---|---:|---:|---:|---:|
| `bench -n 10000000 -v 1` | 232.4 ± 1.5 | 230.6 | 235.7 | 1.83 ± 0.02 |
| `bench -n 10000000 -v 3` | 998.9 ± 2.9 | 995.7 | 1004.7 | 7.88 ± 0.09 |
| `bench -n 10000000 -v 4` | 126.8 ± 1.3 | 123.7 | 129.7 | 1.00 |
| `bench -n 10000000 -v 5` | 740.7 ± 2.6 | 736.6 | 743.9 | 5.84 ± 0.06 |
| `bench -n 10000000 -v 6` | 189.1 ± 1.1 | 187.3 | 191.6 | 1.49 ± 0.02 |
| `bench -n 10000000 -v 7` | 206.7 ± 1.6 | 204.3 | 209.7 | 1.63 ± 0.02 |

### Single-threaded

| Command | Mean [ms] | Min [ms] | Max [ms] | Relative |
|:---|---:|---:|---:|---:|
| `bench -n 10000000 -v 1` | 229.7 ± 0.9 | 228.3 | 231.3 | 1.89 ± 0.02 |
| `bench -n 10000000 -v 3` | 1005.7 ± 17.4 | 998.5 | 1054.9 | 8.27 ± 0.17 |
| `bench -n 10000000 -v 4` | 121.7 ± 1.3 | 119.8 | 125.7 | 1.00 |
| `bench -n 10000000 -v 5` | 747.8 ± 8.9 | 737.0 | 760.2 | 6.15 ± 0.10 |
| `bench -n 10000000 -v 6` | 151.6 ± 1.0 | 150.0 | 153.9 | 1.25 ± 0.02 |
| `bench -n 10000000 -v 7` | 203.4 ± 1.4 | 201.4 | 206.4 | 1.67 ± 0.02 |

Environment:
- OS: Windows 10
- CPU: AMD Ryzen 5 5600X
- Build mode: `release-fast`
