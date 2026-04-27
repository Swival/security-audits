# Unsynchronized Global Pointer Dereference

## Classification

Race condition, medium severity.

Confidence: certain.

## Affected Locations

- `library/std/src/sys/env/sgx.rs:21`
- `library/std/src/sys/env/sgx.rs:26`

## Summary

The SGX environment store publishes a heap-allocated `EnvStore` through the global atomic `ENV` using relaxed ordering. Concurrent readers also load `ENV` with relaxed ordering and immediately dereference the resulting raw pointer.

Because relaxed atomics do not establish a happens-before relationship for the boxed `Mutex<HashMap<...>>` initialization, a reader can observe a non-null pointer before the initialized contents are guaranteed visible. Subsequent `env`, `getenv`, or `unsetenv` operations may lock or access an `EnvStore` whose initialization is not synchronized with the reading thread.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and reproducer evidence.

## Preconditions

- One thread initializes the SGX environment store through `create_env_store`.
- Another thread concurrently reads the store through `get_env_store`.
- The reader observes the global `ENV` pointer before the initialized object contents are guaranteed visible.

## Proof

`create_env_store` allocates and initializes `EnvStore::default()` inside a `Box`, converts it into a raw pointer, and stores that pointer in `ENV`.

Before the patch:

```rust
ENV.store(Box::into_raw(Box::new(EnvStore::default())) as _, Ordering::Relaxed)
```

Readers then load the pointer with relaxed ordering and dereference it:

```rust
unsafe { (ENV.load(Ordering::Relaxed) as *const EnvStore).as_ref() }
```

The reproduced behavior confirms:

- `ENV` stores a raw `EnvStore` pointer after allocation.
- `get_env_store` loads `ENV` with `Ordering::Relaxed`, casts it to `*const EnvStore`, and dereferences it at `library/std/src/sys/env/sgx.rs:21`.
- Readers do not acquire synchronization from `ENV_INIT`.
- The relaxed store/load pair does not make the non-atomic initialization writes for the boxed `Mutex<HashMap<...>>` visible to the reader.
- After observing a non-null pointer, the reader calls `env.lock()` or accesses the protected `HashMap` at `library/std/src/sys/env/sgx.rs:36` and `library/std/src/sys/env/sgx.rs:41`.

## Why This Is A Real Bug

The raw pointer value and the initialized object contents are separate concerns. Atomic relaxed ordering can make the pointer value visible without guaranteeing visibility of prior non-atomic writes that initialized the object behind the pointer.

The code relies on the reader seeing a fully initialized `EnvStore` after observing a non-null `ENV` value. That guarantee is absent with `Ordering::Relaxed`.

Dereferencing and locking a `Mutex<HashMap<...>>` whose initialization is not synchronized with the current thread is a memory-safety risk under the Rust memory model.

## Fix Requirement

The pointer publication must synchronize object initialization with all readers.

Required behavior:

- Store the initialized `EnvStore` pointer with release semantics.
- Load the pointer with acquire semantics before dereferencing.
- Ensure all dereference paths use the acquire-loaded pointer.

An equivalent `OnceLock` or `OnceCell`-based initialization would also satisfy the requirement.

## Patch Rationale

The patch changes the global pointer publication from relaxed to release/acquire ordering.

The initializing thread now publishes the pointer with `Ordering::Release`:

```rust
ENV.store(Box::into_raw(Box::new(EnvStore::default())) as _, Ordering::Release)
```

Readers now load the pointer with `Ordering::Acquire` before dereferencing:

```rust
unsafe { (ENV.load(Ordering::Acquire) as *const EnvStore).as_ref() }
```

`create_env_store` also reloads `ENV` with acquire ordering before returning the shared reference.

This establishes the required synchronization edge: all writes that initialize the boxed `EnvStore` before the release store become visible to a thread that observes the pointer through an acquire load.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/env/sgx.rs b/library/std/src/sys/env/sgx.rs
index 09090ec7cf0..d080883ebca 100644
--- a/library/std/src/sys/env/sgx.rs
+++ b/library/std/src/sys/env/sgx.rs
@@ -18,14 +18,14 @@
 type EnvStore = Mutex<HashMap<OsString, OsString>>;
 
 fn get_env_store() -> Option<&'static EnvStore> {
-    unsafe { (ENV.load(Ordering::Relaxed) as *const EnvStore).as_ref() }
+    unsafe { (ENV.load(Ordering::Acquire) as *const EnvStore).as_ref() }
 }
 
 fn create_env_store() -> &'static EnvStore {
     ENV_INIT.call_once(|| {
-        ENV.store(Box::into_raw(Box::new(EnvStore::default())) as _, Ordering::Relaxed)
+        ENV.store(Box::into_raw(Box::new(EnvStore::default())) as _, Ordering::Release)
     });
-    unsafe { &*(ENV.load(Ordering::Relaxed) as *const EnvStore) }
+    unsafe { &*(ENV.load(Ordering::Acquire) as *const EnvStore) }
 }
 
 pub fn env() -> Env {
```