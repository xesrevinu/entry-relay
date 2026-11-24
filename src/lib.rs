// Cross-compiling static musl binaries with `cargo zigbuild` (Zig 0.16) links
// Zig's `std.heap.SmpAllocator` as libc malloc, which never returns <=32 KiB
// chunks to the OS and accumulates unbounded RSS under Tokio's cross-thread
// producer/consumer Vec drops. Use mimalloc so freed pages are reclaimed across
// threads and purged back to the OS via madvise(MADV_DONTNEED).
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod api;
pub mod auth;
pub mod balance;
pub mod mux;
pub mod copy;
pub mod reload;
pub mod relay;
pub mod schedule;
pub mod socks;
pub mod tlsutil;
pub mod usage;
