# OpenGameVCS protocol v1 C++ types

Generated, standard-library-only type models and immutable assignment constants
for `@opengamevcs/protocol-contract-v1@1.0.0-rc.1`.

This package deliberately contains no JSON/JCS, JSONL, HTTP, TLS, MAC,
authorization, cursor, transfer, or storage runtime. Consumers must use a
bounded implementation and validate against the normative schemas.

Smoke command: `cmake -S . -B build -DOGVCS_PROTOCOL_BUILD_TESTS=ON && cmake --build build && ctest --test-dir build`.

License: MIT.
