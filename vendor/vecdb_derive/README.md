# vecdb_derive

Derive macros for [`vecdb`](../vecdb/) to enable custom types in compressed and uncompressed vectors.

Provides two derive macros:
- `#[derive(Bytes)]` - For use with `BytesVec`, `LZ4Vec`, `ZstdVec`
- `#[derive(Pco)]` - For use with `PcoVec` (compressed numeric vectors)

## Install

```bash
cargo add vecdb --features derive
```

## Usage

### Bytes Derive

Use `#[derive(Bytes)]` to enable custom wrapper types with uncompressed or general-purpose compressed vectors:

```rust
use vecdb::{Bytes, BytesVec, Database, Importable, Version};

#[derive(Debug, Clone, Copy, PartialEq, Bytes)]
struct UserId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Bytes)]
struct Timestamp(i64);

fn main() -> vecdb::Result<()> {
    let db = Database::open("data")?;

    // Works with BytesVec
    let mut users: BytesVec<usize, UserId> =
        BytesVec::import(&db, "users", Version::TWO)?;
    users.push(UserId(12345));
    users.flush()?;

    // Also works with LZ4Vec and ZstdVec
    let mut timestamps: vecdb::LZ4Vec<usize, Timestamp> =
        vecdb::LZ4Vec::import(&db, "timestamps", Version::TWO)?;
    timestamps.push(Timestamp(1700000000));
    timestamps.flush()?;

    Ok(())
}
```

**Requirements:**
- Must be a tuple struct with exactly one field
- Inner type must implement `Bytes`
- Works with generic types

### Pco Derive

Use `#[derive(Pco)]` for numeric wrapper types to enable Pcodec compression:

```rust
use vecdb::{Pco, PcoVec, Database, Importable, Version};

#[derive(Debug, Clone, Copy, PartialEq, Pco)]
struct Price(f64);

#[derive(Debug, Clone, Copy, PartialEq, Pco)]
struct Quantity(u32);

fn main() -> vecdb::Result<()> {
    let db = Database::open("data")?;

    let mut prices: PcoVec<usize, Price> =
        PcoVec::import(&db, "prices", Version::TWO)?;
    prices.push(Price(99.99));
    prices.flush()?;

    Ok(())
}
```

**Requirements:**
- Must be a tuple struct with exactly one field
- Inner type must implement `Pco` (numeric types only: u16-u64, i16-i64, f32, f64)
- The derive automatically implements both `Bytes` and `Pco` traits
- Works with generic types

### Generic Types

Both derives support generic type parameters:

```rust
use vecdb::{Bytes, Pco};

// Generic wrapper with Bytes
#[derive(Debug, Clone, Copy, PartialEq, Bytes)]
struct Wrapper<T>(T);

// Generic wrapper with Pco
#[derive(Debug, Clone, Copy, PartialEq, Pco)]
struct NumericWrapper<T>(T);

// Nested generics
#[derive(Debug, Clone, Copy, PartialEq, Pco)]
struct Container<T>(Wrapper<T>);

// Use with concrete types
let value = Wrapper(42u64);
let numeric = NumericWrapper(3.14f64);
let nested = Container(Wrapper(100u32));
```

The derives automatically add appropriate trait bounds (`T: Bytes` or `T: Pco`) to the generated implementations.

## How It Works

Both derives implement traits by delegating to the inner type:

```rust
// #[derive(Bytes)] generates:
impl Bytes for Wrapper<T> where T: Bytes {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(T::from_bytes(bytes)?))
    }
}

// #[derive(Pco)] generates:
// - Bytes implementation (same as above)
// - Pco implementation with NumberType from inner type
// - TransparentPco marker trait
```

This allows wrapper types to have the same serialization and compression characteristics as their inner type.
