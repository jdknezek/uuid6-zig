const std = @import("std");
const clap = @import("clap");
const Uuid = @import("uuid");

pub fn main() anyerror!void {
    const stderr = std.io.getStdErr().writer();
    const stdout = std.io.getStdOut().writer();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) std.fmt.format(stderr, "WARNING: memory leak!\n", .{}) catch unreachable;
    const allocator = gpa.allocator();

    const nanos = std.time.nanoTimestamp();

    var rng = std.rand.DefaultPrng.init(@bitCast(u64, @truncate(i64, nanos)));
    const random = rng.random();

    var clock = Uuid.Clock.init(random);
    var node_source = Uuid.v1.RandomNodeSource{ .random = random };

    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("-h, --help         Display this help and exit.") catch unreachable,
        clap.parseParam("-v, --version <v>  UUID version") catch unreachable,
        clap.parseParam("-d, --domain <d>   Domain (for v3 & v5)") catch unreachable,
        clap.parseParam("-n, --number <n>   Number of UUIDs to generate (default 1)") catch unreachable,
        clap.parseParam("-p, --print        Print generated UUIDs") catch unreachable,
    };

    var args = try clap.parse(clap.Help, &params, .{});
    defer args.deinit();

    if (args.flag("--help")) {
        try clap.help(stdout, &params);
        return;
    }

    const version_flag = args.option("--version") orelse {
        try std.fmt.format(stderr, "ERROR: version is required\n", .{});
        std.process.exit(1);
    };

    const version = std.fmt.parseUnsigned(u4, version_flag, 10) catch |err| {
        try std.fmt.format(stderr, "ERROR: error parsing version: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    var source: Source = switch (version) {
        1 => .{ .v1 = Uuid.v1.Source.init(&clock, node_source.nodeSource()) },
        3 => .{ .v3 = Uuid.v3.Source.init(Uuid.namespace.dns) },
        4 => .{ .v4 = Uuid.v4.Source.init(random) },
        5 => .{ .v5 = Uuid.v5.Source.init(Uuid.namespace.dns) },
        6 => .{ .v6 = Uuid.v6.Source.init(&clock, random) },
        7 => .{ .v7 = Uuid.v7.Source.init(random) },
        else => {
            try std.fmt.format(stderr, "ERROR: unsupported version\n", .{});
            std.process.exit(1);
        },
    };

    const domain = args.option("--domain") orelse "www.example.com";

    const number = if (args.option("--number")) |flag|
        try std.fmt.parseUnsigned(usize, flag, 10)
    else
        1;

    const print = args.flag("--print");

    var print_buffer = try allocator.alloc(Uuid, if (print) number else 0);
    defer allocator.free(print_buffer);

    var timer = try std.time.Timer.start();

    var i: usize = 0;
    while (i < number) : (i += 1) {
        const uuid = source.create(domain);
        if (print) {
            print_buffer[i] = uuid;
        }
    }

    const duration = timer.read();

    if (print) {
        for (print_buffer) |uuid| {
            try std.fmt.format(stdout, "{}\n", .{uuid});
        }
    } else {
        const duration_per_uuid = @floatToInt(u64, @intToFloat(f64, duration) / @intToFloat(f64, number));
        try std.fmt.format(stdout, "{d} UUIDs in {} = {}/UUID\n", .{ number, std.fmt.fmtDuration(duration), std.fmt.fmtDuration(duration_per_uuid) });
    }
}

pub const Source = union(enum) {
    v1: Uuid.v1.Source,
    v3: Uuid.v3.Source,
    v4: Uuid.v4.Source,
    v5: Uuid.v5.Source,
    v6: Uuid.v6.Source,
    v7: Uuid.v7.Source,

    pub fn create(self: *Source, name: []const u8) Uuid {
        return switch (self.*) {
            .v1 => |src| src.create(),
            .v3 => |src| src.create(name),
            .v4 => |src| src.create(),
            .v5 => |src| src.create(name),
            .v6 => |src| src.create(),
            .v7 => |src| src.create(),
        };
    }
};
