# Convenience targets for the EasyCrypt simulator-property spec.
#
# Pre-requisites: opam switch `easycrypt` with easycrypt + alt-ergo.
# See README.md for one-time install steps.

EC      = easycrypt compile
EC_OPTS = -I .

# Files in dependency order.
SOURCES = Common.ec Leakage.ec Protocol.ec Simulator.ec Theorem.ec

.PHONY: all check verbose clean

all: check

# Typecheck the full spec. The top-level Theorem.ec require-imports the
# rest, so checking it checks everything.
check:
	$(EC) $(EC_OPTS) Theorem.ec

# Verbose typecheck (prints each successful proof step, not just errors).
verbose:
	$(EC) $(EC_OPTS) -p alt-ergo -p z3 Theorem.ec

# Per-file typecheck (useful when iterating on a specific module).
%.check: %.ec
	$(EC) $(EC_OPTS) $<

clean:
	rm -f *.ecpc *.eco
