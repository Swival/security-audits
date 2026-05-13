# Hash mismatches equality for integral float JSON numbers

## Classification
- Severity: medium
- Type: data integrity bug
- Confidence: certain

## Affected Locations
- `std/json.d:1001`
- `std/json.d:1071`
- `std/json.d:1640`

## Summary
`JSONValue.opEquals` treats an integral `float_` value as equal to the same numeric `integer` value, but `JSONValue.toHash` hashes `float_` values by raw `double` bits. As a result, numerically equal keys such as `JSONValue(5)` and `JSONValue(5.0)` compare equal yet land in different associative-array buckets, causing missed lookups.

## Provenance
- Reproduced from the verified finding and patch workflow against `std/json.d`
- Reference: https://swival.dev

## Preconditions
- `JSONValue` is used as an associative-array key
- At least one key is a numeric `JSONValue`
- Equality is exercised across `JSONType.integer` and an integral-valued `JSONType.float_`

## Proof
- `opEquals` in `std/json.d:1001` returns true for cross-type numeric equality when a `float_` holds an integral value equal to the compared integer.
- `toHash` in `std/json.d:1071` hashes `float_` using the stored `double` representation, so `5.0` hashes to its IEEE-754 bit pattern rather than the integer hash for `5`.
- `parseJSON("5.0")` in `std/json.d:1640` produces `JSONType.float_`, making the issue reachable from parsed input.
- Runtime reproduction confirmed:
  - `JSONValue(int(5)) == JSONValue(5.0)` is `true`
  - `JSONValue(int(5)).toHash()` is `5`
  - `JSONValue(5.0).toHash()` is `4617315517961601024`
  - after inserting `aa[JSONValue(int(5))] = true`, both `JSONValue(5.0) in aa` and `parseJSON("5.0") in aa` are `false`

## Why This Is A Real Bug
Associative arrays require equal keys to produce identical hashes. Here, the implementation breaks that contract for integral float-vs-integer equality, so lookups, membership checks, and updates can fail for values that `JSONValue` itself says are equal. This is externally observable and reachable from normal constructors and parsed JSON.

## Fix Requirement
Canonicalize numeric hashing so every pair of numerically equal `JSONValue` numbers that compare equal also produce the same hash, specifically for integral-valued `float_` numbers equal to stored integers.

## Patch Rationale
The patch narrows the fix to the actually reproduced case: when hashing a `JSONType.float_`, detect whether the `double` is finite and exactly integral within the signed integer domain used by `opEquals`; if so, hash it using the same integer canonical form instead of raw floating bits. Non-integral floats continue to hash by their floating representation, preserving distinct hashes where equality is false.

## Residual Risk
None

## Patch
- Patched in `047-hash-violates-equality-for-numerically-equal-values.patch`
- The change updates numeric hashing in `std/json.d` so integral `float_` values hash compatibly with equal `integer` values while leaving non-integral float hashing unchanged.
- This restores the equality/hash contract for the reproduced associative-array key case involving constructor-created and `parseJSON`-created values.