//! Test fixture: a small program whose DWARF line table the bridge reads.
//! Built for x86_64-linux (self-hosted backend) so the test covers the DWARF
//! that libdw rejects.

fn add(a: u32, b: u32) u32 {
    return a + b;
}

pub fn main() void {
    _ = add(1, 2);
}
