Deprecated formatting helpers must still be diagnosed on ordinary enums.

```compile_fail
#![deny(deprecated)]
use n0_error::stack_error;

#[deprecated]
fn old_formatter() -> &'static str { "old" }

#[stack_error(derive)]
enum Error {
    #[error("{}", old_formatter())]
    Failure,
}
```

Allowing generated code to handle a deprecated variant must not allow user code
to construct it without a diagnostic.

```compile_fail
#![deny(deprecated)]
use n0_error::stack_error;

#[stack_error(derive)]
enum Error {
    #[deprecated]
    Old,
}

let _ = Error::Old;
```
