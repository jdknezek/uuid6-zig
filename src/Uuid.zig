const std = @import("std");
const hash = std.crypto.hash;
const mem = std.mem;
const rand = std.rand;
const testing = std.testing;
const time = std.time;

const log = std.log.scoped(.uuid);

const Uuid = @This();

bytes: [16]u8,

pub const nil = fromInt(0);

/// Creates a new UUID from a 16-byte slice. Only validates the slice length.
pub fn fromSlice(bytes: []const u8) error{InvalidSize}!Uuid {
    if (bytes.len < 16) return error.InvalidSize;

    var uuid: Uuid = undefined;
    std.mem.copy(u8, &uuid.bytes, bytes);
    return uuid;
}

/// Creates a new UUID from a u128. Performs no validation.
pub fn fromInt(value: u128) Uuid {
    var uuid: Uuid = undefined;
    std.mem.writeIntBig(u128, &uuid.bytes, value);
    return uuid;
}

fn formatHex(dst: []u8, src: []const u8) error{InvalidSize}!void {
    if (dst.len < 2 * src.len) return error.InvalidSize;

    const alphabet = "0123456789abcdef";

    var d: usize = 0;
    var s: usize = 0;
    while (d < dst.len and s < src.len) : ({
        d += 2;
        s += 1;
    }) {
        const byte = src[s];
        dst[d] = alphabet[byte >> 4];
        dst[d + 1] = alphabet[byte & 0xf];
    }
}

/// Formats the UUID to the buffer according to RFC-4122.
pub fn formatBuf(self: Uuid, buf: []u8) error{InvalidSize}!void {
    if (buf.len < 36) return error.InvalidSize;

    formatHex(buf[0..8], self.bytes[0..4]) catch unreachable;
    buf[8] = '-';
    formatHex(buf[9..13], self.bytes[4..6]) catch unreachable;
    buf[13] = '-';
    formatHex(buf[14..18], self.bytes[6..8]) catch unreachable;
    buf[18] = '-';
    formatHex(buf[19..23], self.bytes[8..10]) catch unreachable;
    buf[23] = '-';
    formatHex(buf[24..], self.bytes[10..]) catch unreachable;
}

/// Formats the UUID according to RFC-4122.
pub fn format(self: Uuid, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;
    var buf: [36]u8 = undefined;
    self.formatBuf(&buf) catch unreachable;
    try writer.writeAll(&buf);
}

test "format" {
    var buf: [36]u8 = undefined;

    _ = try std.fmt.bufPrint(&buf, "{}", .{nil});
    try testing.expectEqualStrings("00000000-0000-0000-0000-000000000000", &buf);

    _ = try std.fmt.bufPrint(&buf, "{}", .{fromInt(0x0123456789abcdef0123456789abcdef)});
    try testing.expectEqualStrings("01234567-89ab-cdef-0123-456789abcdef", &buf);
}

pub const ParseError = error{
    InvalidSize,
    InvalidCharacter,
};

fn parseHex(dst: []u8, src: []const u8) ParseError!void {
    if (src.len & 1 == 1 or dst.len < src.len / 2) return error.InvalidSize;

    var d: usize = 0;
    var s: usize = 0;
    while (d < dst.len and s < src.len) : ({
        d += 1;
        s += 2;
    }) {
        dst[d] = switch (src[s]) {
            '0'...'9' => |c| c - '0',
            'A'...'F' => |c| c - 'A' + 10,
            'a'...'f' => |c| c - 'a' + 10,
            else => return error.InvalidCharacter,
        } << 4 | switch (src[s + 1]) {
            '0'...'9' => |c| c - '0',
            'A'...'F' => |c| c - 'A' + 10,
            'a'...'f' => |c| c - 'a' + 10,
            else => return error.InvalidCharacter,
        };
    }
}

/// Parses a RFC-4122-format string, tolerant of separators.
pub fn parse(str: []const u8) ParseError!Uuid {
    if (str.len < 36) return error.InvalidSize;

    var uuid: Uuid = undefined;
    try parseHex(uuid.bytes[0..4], str[0..8]);
    try parseHex(uuid.bytes[4..6], str[9..13]);
    try parseHex(uuid.bytes[6..8], str[14..18]);
    try parseHex(uuid.bytes[8..10], str[19..23]);
    try parseHex(uuid.bytes[10..], str[24..]);

    return uuid;
}

test "parse" {
    const uuid = try parse("01234567-89ab-cdef-0123-456789abcdef");
    try testing.expectEqual(fromInt(0x0123456789abcdef0123456789abcdef).bytes, uuid.bytes);
}

pub fn setVersion(uuid: *Uuid, version: u4) void {
    uuid.bytes[6] = (@as(u8, version) << 4) | (uuid.bytes[6] & 0xf);
}

/// Returns the UUID version number.
pub fn getVersion(self: Uuid) u4 {
    return @truncate(u4, self.bytes[6] >> 4);
}

pub const Variant = enum {
    reserved_ncs,
    rfc4122,
    reserved_microsoft,
    reserved_future,
};

pub fn setVariant(uuid: *Uuid, variant: Uuid.Variant) void {
    uuid.bytes[8] = switch (variant) {
        .reserved_ncs => uuid.bytes[8] & 0b01111111,
        .rfc4122 => 0b10000000 | (uuid.bytes[8] & 0b00111111),
        .reserved_microsoft => 0b11000000 | (uuid.bytes[8] & 0b00011111),
        .reserved_future => 0b11100000 | (uuid.bytes[8] & 0b0001111),
    };
}

/// Returns the UUID variant. All UUIDs created by this library are RFC-4122 variants.
pub fn getVariant(self: Uuid) Variant {
    const byte = self.bytes[8];
    if (byte >> 7 == 0b0) {
        return .reserved_ncs;
    } else if (byte >> 6 == 0b10) {
        return .rfc4122;
    } else if (byte >> 5 == 0b110) {
        return .reserved_microsoft;
    } else {
        return .reserved_future;
    }
}

test "variant and version" {
    var uuid = try parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8");
    try testing.expectEqual(Variant.rfc4122, uuid.getVariant());
    try testing.expectEqual(@as(u4, 1), uuid.getVersion());

    uuid = try parse("3d813cbb-47fb-32ba-91df-831e1593ac29");
    try testing.expectEqual(Variant.rfc4122, uuid.getVariant());
    try testing.expectEqual(@as(u4, 3), uuid.getVersion());

    uuid = nil;
    uuid.setVariant(.rfc4122);
    uuid.setVersion(4);
    try testing.expectEqual(Variant.rfc4122, uuid.getVariant());
    try testing.expectEqual(@as(u4, 4), uuid.getVersion());
}

pub const namespace = struct {
    pub const dns = fromInt(0x6ba7b8109dad11d180b400c04fd430c8);
    pub const url = fromInt(0x6ba7b8119dad11d180b400c04fd430c8);
    pub const iso_oid = fromInt(0x6ba7b8129dad11d180b400c04fd430c8);
    pub const x500_dn = fromInt(0x6ba7b8149dad11d180b400c04fd430c8);
};

/// A UUIDv3 is created by combining a namespace UUID and name via MD5.
pub const v3 = struct {
    pub const Source = struct {
        md5: hash.Md5,

        pub fn init(ns: Uuid) Source {
            var md5 = hash.Md5.init(.{});
            md5.update(&ns.bytes);

            return .{ .md5 = md5 };
        }

        pub fn create(self: Source, name: []const u8) Uuid {
            var uuid: Uuid = undefined;

            // 128 bits of MD5
            var md5 = self.md5;
            md5.update(name);
            md5.final(&uuid.bytes);

            uuid.setVariant(.rfc4122);
            uuid.setVersion(3);
            return uuid;
        }
    };

    test "Source" {
        const source = Source.init(Uuid.namespace.dns);
        const uuid1 = source.create("www.example.com");
        try testing.expectEqual(Uuid.fromInt(0x5df418813aed351588a72f4a814cf09e), uuid1);
        const uuid2 = source.create("www.example.com");
        try testing.expectEqual(uuid1, uuid2);
    }

    pub fn create(ns: Uuid, name: []const u8) Uuid {
        return Source.init(ns).create(name);
    }

    test "create" {
        const uuid1 = create(Uuid.namespace.dns, "www.example.com");
        try testing.expectEqual(Uuid.fromInt(0x5df418813aed351588a72f4a814cf09e), uuid1);
        const uuid2 = create(Uuid.namespace.dns, "www.example.com");
        try testing.expectEqual(uuid1, uuid2);
    }
};

/// A UUIDv5 is created by combining a namespace UUID and name via SHA-1.
pub const v5 = struct {
    pub const Source = struct {
        sha1: hash.Sha1,

        pub fn init(ns: Uuid) Source {
            var sha1 = hash.Sha1.init(.{});
            sha1.update(&ns.bytes);

            return .{ .sha1 = sha1 };
        }

        pub fn create(self: Source, name: []const u8) Uuid {
            var uuid: Uuid = undefined;

            // 128 out of 160 bits of SHA-1
            var sha1 = self.sha1;
            sha1.update(name);
            var buf: [20]u8 = undefined;
            sha1.final(&buf);
            std.mem.copy(u8, &uuid.bytes, buf[0..16]);

            uuid.setVariant(.rfc4122);
            uuid.setVersion(5);
            return uuid;
        }
    };

    test "Source" {
        const source = Source.init(Uuid.namespace.dns);
        const uuid1 = source.create("www.example.com");
        try testing.expectEqual(Uuid.fromInt(0x2ed6657de927568b95e12665a8aea6a2), uuid1);
        const uuid2 = source.create("www.example.com");
        try testing.expectEqual(uuid1, uuid2);
    }

    pub fn create(ns: Uuid, name: []const u8) Uuid {
        return Source.init(ns).create(name);
    }

    test "create" {
        const uuid1 = create(Uuid.namespace.dns, "www.example.com");
        try testing.expectEqual(Uuid.fromInt(0x2ed6657de927568b95e12665a8aea6a2), uuid1);
        const uuid2 = create(Uuid.namespace.dns, "www.example.com");
        try testing.expectEqual(uuid1, uuid2);
    }
};

/// A UUIDv4 is created from an entropy source.
pub const v4 = struct {
    pub fn create(random: rand.Random) Uuid {
        var uuid: Uuid = undefined;

        // 128 bits of entropy
        random.bytes(&uuid.bytes);

        uuid.setVariant(.rfc4122);
        uuid.setVersion(4);
        return uuid;
    }

    test "create" {
        var rng = rand.DefaultPrng.init(0);

        const uuid1 = create(rng.random());
        const uuid2 = create(rng.random());
        try testing.expect(!mem.eql(u8, &uuid1.bytes, &uuid2.bytes));
    }

    pub const Source = struct {
        random: rand.Random,

        pub fn init(random: rand.Random) Source {
            return .{ .random = random };
        }

        pub fn create(self: Source) Uuid {
            return v4.create(self.random);
        }
    };

    test "Source" {
        var rng = rand.DefaultPrng.init(0);
        var source = Source.init(rng.random());

        const uuid1 = source.create();
        const uuid2 = source.create();
        try testing.expect(!mem.eql(u8, &uuid1.bytes, &uuid2.bytes));
    }
};

/// Used for UUIDv1 & v6.
/// A 14-bit clock sequence that increments monotonically within each 100-ns timestamp interval, and is randomized between intervals.
/// It is thread-safe as one instance is intended to be shared by the whole application to prevent duplicate clock sequences.
pub const Clock = struct {
    mutex: std.Thread.Mutex = .{},
    timestamp: u60 = 0,
    sequence: u14 = 0,
    random: rand.Random,

    pub fn init(random: rand.Random) Clock {
        return .{ .random = random };
    }

    fn next(self: *Clock, timestamp: u60) u14 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (timestamp > self.timestamp) {
            self.sequence = self.random.int(u14);
            self.timestamp = timestamp;
        }

        const sequence = self.sequence;
        self.sequence +%= 1;
        return sequence;
    }
};

/// A UUIDv1 is created from a timestamp and node ID. The node ID is traditionally a MAC address but may randomized.
pub const v1 = struct {
    /// Generates a random node ID suitable for a UUIDv1. This is basically a random MAC address with the multicast bit set.
    pub fn randomNode(random: rand.Random) [6]u8 {
        var buf: [6]u8 = undefined;
        random.bytes(&buf);
        buf[0] |= 1;
        return buf;
    }

    /// Number of 100-ns intervals from Gregorian epoch (1582-10-15T00:00:00Z) to Unix epoch (1970-01-01T00:00:00Z)
    const epoch_intervals = 12219292800 * (time.ns_per_s / 100);

    /// Converts a nanosecond timestamp to a UUID timestamp.
    pub fn nanosToTimestamp(nanos: i128) u60 {
        const intervals = @divTrunc(nanos, 100);
        const from_epoch = intervals + epoch_intervals;
        return @truncate(u60, @bitCast(u128, from_epoch));
    }

    fn setTimestamp(uuid: *Uuid, timestamp: u60) void {
        // time-low
        mem.writeIntBig(u32, @ptrCast(*[4]u8, &uuid.bytes[0]), @truncate(u32, timestamp));
        // time-mid
        mem.writeIntBig(u16, @ptrCast(*[2]u8, &uuid.bytes[4]), @truncate(u16, timestamp >> 32));
        // time-high
        mem.writeIntBig(u16, @ptrCast(*[2]u8, &uuid.bytes[6]), @truncate(u16, timestamp >> 48));
    }

    pub fn getTimestamp(uuid: Uuid) u60 {
        const lo = mem.readIntBig(u32, @ptrCast(*const [4]u8, &uuid.bytes[0]));
        const md = mem.readIntBig(u16, @ptrCast(*const [2]u8, &uuid.bytes[4]));
        const hi = mem.readIntBig(u16, @ptrCast(*const [2]u8, &uuid.bytes[6])) & 0xfff;
        return @as(u60, hi) << 48 | @as(u60, md) << 32 | @as(u60, lo);
    }

    pub fn create(timestamp: u60, clock: *Clock, node: [6]u8) Uuid {
        var uuid: Uuid = undefined;

        const sequence = clock.next(timestamp);

        // 60 bits of timestamp
        setTimestamp(&uuid, timestamp);
        // 14 bits of clock sequence
        mem.writeIntBig(u16, @ptrCast(*[2]u8, &uuid.bytes[8]), sequence);
        // 48 bits of node ID
        mem.copy(u8, uuid.bytes[10..], &node);

        uuid.setVariant(.rfc4122);
        uuid.setVersion(1);
        return uuid;
    }

    test "create" {
        var rng = rand.DefaultPrng.init(0);
        var clock = Clock.init(rng.random());
        const node = randomNode(rng.random());

        const uuid1 = create(nanosToTimestamp(time.nanoTimestamp()), &clock, node);
        const uuid2 = create(nanosToTimestamp(time.nanoTimestamp()), &clock, node);
        log.debug("{}\n{}\n", .{ uuid1, uuid2 });
        try testing.expect(!mem.eql(u8, &uuid1.bytes, &uuid2.bytes));
    }

    /// Interface to generate a node ID.
    pub const NodeSource = struct {
        ptr: *anyopaque,
        nodeFn: std.meta.FnPtr(fn (*anyopaque) [6]u8),

        pub fn init(pointer: anytype, comptime nodeFn: fn (ptr: @TypeOf(pointer)) [6]u8) NodeSource {
            const Ptr = @TypeOf(pointer);
            std.debug.assert(@typeInfo(Ptr) == .Pointer); // Must be a pointer
            std.debug.assert(@typeInfo(Ptr).Pointer.size == .One); // Must be a single-item pointer
            std.debug.assert(@typeInfo(@typeInfo(Ptr).Pointer.child) == .Struct); // Must point to a struct
            const gen = struct {
                fn node(ptr: *anyopaque) [6]u8 {
                    const alignment = @typeInfo(Ptr).Pointer.alignment;
                    const self = @ptrCast(Ptr, @alignCast(alignment, ptr));
                    return nodeFn(self);
                }
            };

            return .{
                .ptr = pointer,
                .nodeFn = gen.node,
            };
        }

        pub fn node(self: NodeSource) [6]u8 {
            return self.nodeFn(self.ptr);
        }
    };

    /// Re-use a fixed node ID. You should probably not use this except for compatibility.
    pub const FixedNodeSource = struct {
        node: [6]u8,

        fn nodeFn(self: *FixedNodeSource) [6]u8 {
            return self.node;
        }

        pub fn nodeSource(self: *FixedNodeSource) NodeSource {
            return NodeSource.init(self, nodeFn);
        }
    };

    test "FixedNodeSource" {
        var rng = rand.DefaultPrng.init(0);
        var source = FixedNodeSource{ .node = randomNode(rng.random()) };
        const node_source = source.nodeSource();

        const node1 = node_source.node();
        const node2 = node_source.node();
        try testing.expect(mem.eql(u8, &node1, &node2));
    }

    /// Generate a new random node ID per UUID.
    pub const RandomNodeSource = struct {
        random: rand.Random,

        fn nodeFn(self: *RandomNodeSource) [6]u8 {
            return randomNode(self.random);
        }

        pub fn nodeSource(self: *RandomNodeSource) NodeSource {
            return NodeSource.init(self, nodeFn);
        }
    };

    test "RandomNodeSource" {
        var rng = rand.DefaultPrng.init(0);
        var source = RandomNodeSource{ .random = rng.random() };
        const node_source = source.nodeSource();

        const node1 = node_source.node();
        const node2 = node_source.node();
        try testing.expect(!mem.eql(u8, &node1, &node2));
    }

    pub const Source = struct {
        clock: *Clock,
        node_source: NodeSource,

        pub fn init(clock: *Clock, node_source: NodeSource) Source {
            return .{
                .clock = clock,
                .node_source = node_source,
            };
        }

        pub fn create(self: Source) Uuid {
            const nanos = time.nanoTimestamp();
            const timestamp = nanosToTimestamp(nanos);
            const node = self.node_source.node();
            return v1.create(timestamp, self.clock, node);
        }
    };

    test "Source" {
        var rng = rand.DefaultPrng.init(0);
        var clock = Clock.init(rng.random());
        var node_source = RandomNodeSource{ .random = rng.random() };
        const source = Source.init(&clock, node_source.nodeSource());

        const uuid1 = source.create();
        const uuid2 = source.create();
        log.debug("{}\n{}\n", .{ uuid1, uuid2 });
        try testing.expect(!mem.eql(u8, &uuid1.bytes, &uuid2.bytes));
        try testing.expect(!mem.eql(u8, uuid1.bytes[10..], uuid2.bytes[10..]));
    }

    pub fn fromV6(uuidV6: Uuid) Uuid {
        var uuidV1 = uuidV6;
        setTimestamp(&uuidV1, v6.getTimestamp(uuidV6));
        uuidV1.setVersion(1);
        return uuidV1;
    }

    test "fromV6" {
        var rng = rand.DefaultPrng.init(0);
        var clock = Clock.init(rng.random());
        const source = v6.Source.init(&clock, rng.random());

        const uuidV6 = source.create();
        const uuidV1 = fromV6(uuidV6);
        try testing.expectEqual(uuidV6.getVariant(), uuidV1.getVariant());
        try testing.expectEqual(@as(u4, 1), uuidV1.getVersion());
        try testing.expectEqualSlices(u8, uuidV6.bytes[10..], uuidV1.bytes[10..]);
    }
};

/// A UUIDv6 is created from a timestamp and entropy source. It sorts lexicographically by timestamp.
pub const v6 = struct {
    pub const nanosToTimestamp = v1.nanosToTimestamp;

    fn setTimestamp(uuid: *Uuid, timestamp: u60) void {
        // time-high
        mem.writeIntBig(u48, @ptrCast(*[6]u8, &uuid.bytes[0]), @truncate(u48, timestamp >> 12));
        // time-low
        mem.writeIntBig(u16, @ptrCast(*[2]u8, &uuid.bytes[6]), @truncate(u16, timestamp & 0xfff));
    }

    pub fn getTimestamp(uuid: Uuid) u60 {
        const hi = mem.readIntBig(u48, @ptrCast(*const [6]u8, &uuid.bytes[0]));
        const lo = mem.readIntBig(u16, @ptrCast(*const [2]u8, &uuid.bytes[6])) & 0xfff;
        return @as(u60, hi) << 12 | @as(u60, lo);
    }

    pub fn create(timestamp: u60, clock: *Clock, random: rand.Random) Uuid {
        var uuid: Uuid = Uuid.nil;

        const sequence = clock.next(timestamp);

        // 60 bits of timestamp
        setTimestamp(&uuid, timestamp);
        // 14 bits of clock sequence
        mem.writeIntBig(u16, @ptrCast(*[2]u8, &uuid.bytes[8]), sequence);
        // 48 bits of entropy
        random.bytes(uuid.bytes[10..]);

        uuid.setVariant(.rfc4122);
        uuid.setVersion(6);
        return uuid;
    }

    test "create" {
        var rng = rand.DefaultPrng.init(0);
        var clock = Clock.init(rng.random());

        const uuid1 = create(nanosToTimestamp(time.nanoTimestamp()), &clock, rng.random());
        const uuid2 = create(nanosToTimestamp(time.nanoTimestamp()), &clock, rng.random());
        log.debug("{}\n{}\n", .{ uuid1, uuid2 });
        try testing.expect(!mem.eql(u8, &uuid1.bytes, &uuid2.bytes));
    }

    pub const Source = struct {
        clock: *Clock,
        random: rand.Random,

        pub fn init(clock: *Clock, random: rand.Random) Source {
            return .{
                .clock = clock,
                .random = random,
            };
        }

        pub fn create(self: Source) Uuid {
            const nanos = time.nanoTimestamp();
            const timestamp = nanosToTimestamp(nanos);
            return v6.create(timestamp, self.clock, self.random);
        }
    };

    test "Source" {
        var rng = rand.DefaultPrng.init(0);
        var clock = Clock.init(rng.random());
        const source = Source.init(&clock, rng.random());

        const uuid1 = source.create();
        const uuid2 = source.create();
        log.debug("{}\n{}\n", .{ uuid1, uuid2 });
        try testing.expect(!std.mem.eql(u8, &uuid1.bytes, &uuid2.bytes));
    }

    pub fn fromV1(uuidV1: Uuid) Uuid {
        var uuidV6 = uuidV1;
        setTimestamp(&uuidV6, v1.getTimestamp(uuidV1));
        uuidV6.setVersion(6);
        return uuidV6;
    }

    test "fromV6" {
        var rng = rand.DefaultPrng.init(0);
        var clock = Clock.init(rng.random());
        var node_source = v1.RandomNodeSource{ .random = rng.random() };
        const source = v1.Source.init(&clock, node_source.nodeSource());

        const uuidV1 = source.create();
        const uuidV6 = fromV1(uuidV1);
        try testing.expectEqual(uuidV1.getVariant(), uuidV6.getVariant());
        try testing.expectEqual(@as(u4, 6), uuidV6.getVersion());
    }
};

/// A UUIDv7 is created from a timestamp and entropy source. It uses UNIX millisecond timestamps and sorts lexicographically between milliseconds.
pub const v7 = struct {
    pub fn create(millis: i64, random: rand.Random) Uuid {
        var uuid: Uuid = nil;
        // 48 bits of Unix milliseconds
        mem.writeIntBig(u48, @ptrCast(*[6]u8, &uuid.bytes[0]), @truncate(u48, @bitCast(u64, millis)));
        // 80 bits of entropy (74 of which we'll keep)
        random.bytes(uuid.bytes[6..]);

        uuid.setVariant(.rfc4122);
        uuid.setVersion(7);
        return uuid;
    }

    test "create" {
        var rng = rand.DefaultPrng.init(0);

        const uuid1 = create(time.milliTimestamp(), rng.random());
        const uuid2 = create(time.milliTimestamp(), rng.random());
        log.debug("{}\n{}\n", .{ uuid1, uuid2 });
        try testing.expect(!mem.eql(u8, &uuid1.bytes, &uuid2.bytes));
    }

    pub const Source = struct {
        random: rand.Random,

        pub fn init(random: rand.Random) Source {
            return .{ .random = random };
        }

        pub fn create(self: Source) Uuid {
            return v7.create(time.milliTimestamp(), self.random);
        }
    };

    test "Source" {
        var rng = rand.DefaultPrng.init(0);
        const source = Source.init(rng.random());

        const uuid1 = source.create();
        const uuid2 = source.create();
        log.debug("{}\n{}\n", .{ uuid1, uuid2 });
        try testing.expect(!mem.eql(u8, &uuid1.bytes, &uuid2.bytes));
    }
};

test {
    std.testing.refAllDecls(Uuid);
}
