//! Session Initiation
//!
//! This module implements the `dbus-broker-session` functionality, which
//! initiates new D-Bus sessions together with a session controller.

use clap;
use libc;

use std::ffi::{OsStr, OsString};

/// Command-line Interface
///
/// This structure provides all command-line handling, which currently means
/// parsing command-line arguments, providing process termination, and dealing
/// with diagnostics.
pub struct Cli {
    cmd: clap::Command,
}

/// Session Configuration
///
/// This encapsulates all parameters required to initiate a new session.
/// Preferably, no ambient resources are needed for the session, yet for
/// legacy compatibility to dbus-daemon this is not true if dbus-daemon is used
/// as broker for the session.
#[derive(Debug)]
pub struct Config {
    pub config_file: Option<OsString>,
    pub dbus_broker: Option<OsString>,
    pub dbus_daemon: Option<OsString>,
    pub arg0: OsString,
    pub args: Vec<OsString>,
}

/// Session Runtime
///
/// This tracks the different resources that make up a session. It currently
/// keeps track of the spawned processes and ensures they are torn down when
/// the object is dropped.
pub struct Session {
    listener: Option<String>,
    bus: Option<std::process::Child>,
    ctrl: Option<std::process::Child>,
}

impl Cli {
    /// Exit code for internal errors
    ///
    /// This is the exit code used by this program when the error originated in
    /// this program itself. It usually denotes errors spawning the different
    /// programs that make up the session.
    pub const ERROR_SELF: u8 = 127;

    /// Base exit code for signal termination
    ///
    /// This is the base exit code used by this program when the session
    /// controller is terminated by a signal. The signal number is added to
    /// this base exit code before it is returned.
    pub const ERROR_SIGNAL: u8 = 128;

    /// Print diagnostics
    ///
    /// Print a diagnostics message to the standard error stream. The message
    /// is prefixed with the name of the program, and a sentinal new-line is
    /// appended.
    pub fn message(args: std::fmt::Arguments) {
        <std::io::Stderr as std::io::Write>::write_fmt(
            &mut std::io::stderr(),
            format_args!("dbus-broker-session: {}\n", args),
        ).expect("Cannot write to STDERR");
    }

    /// Print warning
    ///
    /// Print a warning message via `Self::message()`.
    pub fn warning(args: std::fmt::Arguments) {
        Self::message(format_args!("WARNING: {}", args));
    }

    /// Print error
    ///
    /// Print an error message via `Self::message()` and return the specified
    /// error code.
    pub fn error(args: std::fmt::Arguments, code: u8) -> u8 {
        Self::message(format_args!("ERROR: {}", args));
        code
    }

    /// Print error
    ///
    /// Print an error message via `Self::message()` and return
    /// `Self::ERROR_SELF`.
    pub fn error_self(args: std::fmt::Arguments) -> u8 {
        Self::error(args, Self::ERROR_SELF)
    }

    /// Create new Cli controller
    ///
    /// Create a new Cli controller with the default parameters. This sets up
    /// the entire command-line argument parser, but does not parse any values,
    /// yet.
    pub fn new() -> Self {
        let mut cmd = clap::Command::new("dbus-broker-session")
            .about("D-Bus Session Initiation")
            .long_about("Initiate a D-Bus session with a new session controller.")
            .version(std::env!("DBRK_VERSION"));

        cmd = cmd.arg(
            clap::Arg::new("config-file")
                .help("Path to the config-file to use for the message broker")
                .long("config-file")
                .value_name("PATH")
                .value_parser(clap::builder::ValueParser::os_string())
        );

        cmd = cmd.arg(
            clap::Arg::new("dbus-broker")
                .help("Name or path of the dbus-broker launcher executable")
                .long("dbus-broker")
                .value_name("BINARY")
                .value_parser(clap::builder::ValueParser::os_string())
        );

        cmd = cmd.arg(
            clap::Arg::new("dbus-daemon")
                .help("Name or path of the dbus-daemon executable")
                .long("dbus-daemon")
                .value_name("BINARY")
                .value_parser(clap::builder::ValueParser::os_string())
        );

        cmd = cmd.arg(
            clap::Arg::new("args")
                .help("Session controller to spawn in the new session")
                .num_args(1..)
                .required(true)
                .trailing_var_arg(true)
                .value_name("PROGRAM")
                .value_parser(clap::builder::ValueParser::os_string())
        );

        Self {
            cmd: cmd,
        }
    }

    /// Parse command-line arguments
    ///
    /// Take the Cli controller and a set of command-line arguments and parse
    /// them into a new configuration object. The Cli controller is completely
    /// consumed and will not consume stack space during execution.
    pub fn parse(
        mut self,
        args: &[*const u8],
    ) -> Result<Option<Config>, u8> {
        // Perform argument matching via Clap. In case of `--help` and similar
        // early exits, return without a configuration to let the caller know
        // that no program execution is desired.
        let r = self.cmd.try_get_matches_from_mut(
            args.iter().map(
                |v| {
                    unsafe {
                        <OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(
                            std::ffi::CStr::from_ptr(
                                *v as *const i8,
                            ).to_bytes(),
                        )
                    }
                },
            ),
        );
        let matches = match r {
            Ok(v) => v,
            Err(e) => {
                match e.kind() {
                    clap::error::ErrorKind::DisplayHelp |
                    clap::error::ErrorKind::DisplayVersion => {
                        e.print().expect("Cannot write to STDERR");
                        return Ok(None);
                    },
                    clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand |
                    _ => {
                        e.print().expect("Cannot write to STDERR");
                        return Err(Cli::ERROR_SELF);
                    },
                }
            }
        };

        // Extract the values from Clap to avoid keeping the Cli controller
        // alive for the entire runtime.
        let v_config_file = matches.get_one("config-file").map(|v: &OsString| v.clone());
        let v_dbus_broker = matches.get_one("dbus-broker").map(|v: &OsString| v.clone());
        let v_dbus_daemon = matches.get_one("dbus-daemon").map(|v: &OsString| v.clone());
        let mut iter = matches.get_many("args").map(
            |v| v.map(|v: &OsString| v.clone())
        ).expect("Program name is missing");
        let v_arg0 = iter.next().expect("Program name is missing");
        let v_args = iter.collect::<Vec<OsString>>();

        Ok(Some(Config {
            config_file: v_config_file,
            dbus_broker: v_dbus_broker,
            dbus_daemon: v_dbus_daemon,
            arg0: v_arg0,
            args: v_args,
        }))
    }
}

impl Config {
    // Wrapper around `pipe2(2)` via `libc`.
    fn pipe2() -> Result<[std::os::fd::OwnedFd; 2], std::io::Error> {
        let pipe_read;
        let pipe_write;

        unsafe {
            let mut pipe_raw: [libc::c_int; 2] = [-1; 2];

            let r = libc::pipe2(
                &mut pipe_raw as *mut libc::c_int,
                libc::O_CLOEXEC,
            );
            if r < 0 {
                return Err(std::io::Error::last_os_error());
            }

            pipe_read = <
                std::os::fd::OwnedFd as std::os::fd::FromRawFd
            >::from_raw_fd(pipe_raw[0]);

            pipe_write = <
                std::os::fd::OwnedFd as std::os::fd::FromRawFd
            >::from_raw_fd(pipe_raw[1]);
        }

        Ok([pipe_read, pipe_write])
    }

    // Wrapper around `fcntl(2)` via `libc` to clear `FD_CLOEXEC`.
    fn clear_cloexec(fd: std::os::fd::RawFd) -> Result<(), std::io::Error> {
        let mut r: libc::c_int;

        unsafe {
            r = libc::fcntl(fd, libc::F_GETFD);
            if r >= 0 {
                r = libc::fcntl(fd, libc::F_SETFD, r & !libc::FD_CLOEXEC);
            }
        }
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    // Wrapper around `PR_SET_PDEATHSIG` as `pre_exec()` hook.
    fn pdeathsig_sigterm(cmd: &mut std::process::Command) {
        unsafe {
            <
                std::process::Command as std::os::unix::process::CommandExt
            >::pre_exec(
                cmd,
                || match libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) {
                    r if r < 0 => {
                        let e = std::io::Error::last_os_error();
                        Cli::error_self(format_args!("Cannot set PDEATHSIG: {}", e));
                        Err(e)
                    },
                    _ => Ok(()),
                },
            );
        }
    }

    // Create pipe for `--print-address` and clear `FD_CLOEXEC`.
    fn dd_pipe() -> Result<[std::os::fd::OwnedFd; 2], u8> {
        let [pipe_read, pipe_write] = Self::pipe2().map_err(
            |v| Cli::error_self(format_args!("Cannot create pipe: {}", v)),
        )?;

        Self::clear_cloexec(
            <
                std::os::fd::OwnedFd as std::os::fd::AsRawFd
            >::as_raw_fd(&pipe_write),
        ).map_err(
            |v| Cli::error_self(format_args!("Cannot clear FD_CLOEXEC on pipe: {}", v)),
        )?;

        Ok([pipe_read, pipe_write])
    }

    // Read bus address from pipe passed to `--print-address`.
    fn dd_address(
        pipe: std::os::fd::OwnedFd,
    ) -> Result<std::ffi::OsString, u8> {
        let mut f: std::fs::File = pipe.into();
        let mut address = Vec::new();

        match <std::fs::File as std::io::Read>::read_to_end(
            &mut f,
            &mut address,
        ) {
            Ok(v) => {
                if v > 0 && address[v - 1] == b'\n' {
                    address.truncate(v - 1);
                } else {
                    address.truncate(v);
                }
            },
            Err(v) => return Err(Cli::error_self(
                format_args!("Cannot read bus address from dbus-daemon: {}", v),
            )),
        };

        Ok(<
            std::ffi::OsString as std::os::unix::ffi::OsStringExt
        >::from_vec(address))
    }

    // Spawn dbus-daemon and perform initial setup routines.
    fn dd_spawn(&self) -> Result<(std::process::Child, Option<String>), u8> {
        // Create pipe for `--print-address`.
        let [pipe_read, pipe_write] = Self::dd_pipe()?;

        // Assemble the dbus-daemon cmdline.
        let arg0_default: OsString = "dbus-daemon".to_string().into();
        let arg0 = self.dbus_daemon.as_ref().unwrap_or(&arg0_default);
        let mut cmd = std::process::Command::new(arg0);

        cmd.arg("--nofork");
        cmd.arg("--print-address");
        cmd.arg(
            <std::os::fd::OwnedFd as std::os::fd::AsRawFd>::as_raw_fd(&pipe_write).to_string(),
        );

        if let Some(config_file) = self.config_file.as_ref() {
            cmd.arg("--config-file");
            cmd.arg(config_file);
        } else {
            cmd.arg("--session");
        }

        // Ensure the message broker is terminated on failure.
        Self::pdeathsig_sigterm(&mut cmd);

        // Spawn dbus-daemon.
        let mut handle = cmd.spawn().map_err(
            |v| Cli::error_self(format_args!("Cannot execute dbus-daemon: {}", v)),
        )?;

        // With dbus-daemon running, we wait for it to print the full address
        // of its newly created bus. Hence, we first drop the write-end so the
        // daemon is the only one keeping it open. We then read until EOF. If
        // any of this fails, we terminate the process.
        drop(pipe_write);
        let addr = match Self::dd_address(pipe_read) {
            Ok(v) => v,
            Err(v) => {
                // Tear down the message broker, given that we could not parse
                // the bus address. We ignore errors, given that it might have
                // already exited.
                let _ = handle.kill();
                return Err(v);
            },
        };
        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", addr);

        Ok((handle, None))
    }

    // Create a random bus address for dbus-broker.
    fn db_address() -> String {
        let random: &[u8; 16] = unsafe {
            let p = libc::getauxval(libc::AT_RANDOM) as *const [u8; 16];
            assert!(!p.is_null());
            &*p
        };

        format!(
            "/tmp/dbus-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            random[0],
            random[1],
            random[2],
            random[3],
            random[4],
            random[5],
            random[6],
            random[7],
        )
    }

    // Create the listener socket for dbus-broker, using a random bus address.
    fn db_listener(addr: &String) -> Result<std::os::fd::OwnedFd, u8> {
        let listener = std::os::unix::net::UnixListener::bind(&addr).map_err(
            |v| Cli::error_self(format_args!("Cannot create listener socket {}: {}", &addr, v)),
        )?;

        let fd = unsafe {
            <
                    std::os::fd::OwnedFd as std::os::fd::FromRawFd
            >::from_raw_fd(
                <
                    std::os::unix::net::UnixListener as std::os::fd::IntoRawFd
                >::into_raw_fd(listener),
            )
        };

        Self::clear_cloexec(
            <
                std::os::fd::OwnedFd as std::os::fd::AsRawFd
            >::as_raw_fd(&fd),
        ).map_err(
            |v| Cli::error_self(format_args!("Cannot clear FD_CLOEXEC on listener: {}", v)),
        )?;

        Ok(fd)
    }

    // Spawn dbus-broker and perform initial setup routines.
    fn db_spawn(&self) -> Result<(std::process::Child, Option<String>), u8> {
        // Assemble the dbus-broker-launch cmdline.
        let arg0_default: OsString = "dbus-broker-launch".to_string().into();
        let arg0 = self.dbus_broker.as_ref().unwrap_or(&arg0_default);
        let mut cmd = std::process::Command::new(arg0);

        cmd.arg("--audit");
        cmd.arg("--scope=user");

        if let Some(config_file) = self.config_file.as_ref() {
            cmd.arg("--config-file");
            cmd.arg(config_file);
        }

        // Ensure the message broker is terminated on failure.
        Self::pdeathsig_sigterm(&mut cmd);

        // Create the listener socket and clear FD_CLOEXEC.
        let addr = Self::db_address();
        let listener_fd = Self::db_listener(&addr)?;

        // Ensure `LISTEN_PID` is set to the child pid. This requires
        // allocations and `libc::setenv()` calls after `fork(2)`, but there
        // is really no way around it with the `LISTEN_PID` API of systemd.
        //
        // Then set `LISTEN_FDS` to `1`. We have to do that in the pre-exec
        // hook, because otherwise the `setenv()` would be ignored by the
        // rust exec-implementation.
        //
        // Finally, ensure the listener-fd is available as FD 3, as
        // specified by `SD_LISTEN_FDS_START`.
        unsafe {
            <
                std::process::Command as std::os::unix::process::CommandExt
            >::pre_exec(
                &mut cmd,
                move || {
                    let pidstr = std::ffi::CString::new(
                        libc::getpid().to_string()
                    ).expect("Internal 0-byte in PID string");

                    match libc::setenv(
                        b"LISTEN_PID\0".as_ptr() as *const i8,
                        pidstr.as_ptr() as *const i8,
                        1,
                    ) {
                        r if r < 0 => {
                            let e = std::io::Error::last_os_error();
                            Cli::error_self(format_args!("Cannot set LISTEN_PID: {}", e));
                            Err(e)
                        },
                        _ => Ok(()),
                    }?;

                    match libc::setenv(
                        b"LISTEN_FDS\0".as_ptr() as *const i8,
                        b"1\0".as_ptr() as *const i8,
                        1,
                    ) {
                        r if r < 0 => {
                            let e = std::io::Error::last_os_error();
                            Cli::error_self(format_args!("Cannot set LISTEN_FDS: {}", e));
                            Err(e)
                        },
                        _ => Ok(()),
                    }?;

                    match libc::dup2(
                        <
                            std::os::fd::OwnedFd as std::os::fd::AsRawFd
                        >::as_raw_fd(&listener_fd),
                        3,
                    ) {
                        r if r < 0 => {
                            let e = std::io::Error::last_os_error();
                            Cli::error_self(format_args!("Cannot dup listener fd: {}", e));
                            Err(e)
                        },
                        _ => Ok(()),
                    }?;

                    Ok(())
                },
            );
        }

        // Spawn dbus-broker launcher.
        let handle = cmd.spawn().map_err(
            |v| Cli::error_self(format_args!("Cannot execute dbus-broker launcher: {}", v)),
        )?;

        // Set bus address for all following processes.
        std::env::set_var(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", addr),
        );

        Ok((handle, Some(addr)))
    }

    // Spawn the session controller.
    fn ctrl_spawn(&self) -> Result<std::process::Child, u8> {
        let mut cmd = std::process::Command::new(&self.arg0);
        cmd.args(&self.args);
        Self::pdeathsig_sigterm(&mut cmd);
        let handle = cmd.spawn().map_err(
            |v| Cli::error_self(format_args!("Cannot execute session controller: {}", v)),
        )?;

        Ok(handle)
    }

    /// Initiate a new session
    ///
    /// Spawn the broker and the session controller as specified in the
    /// configuration and return the session information as a new object.
    pub fn initiate(&self) -> Result<Session, u8> {
        let mut session = Session::new();

        let (bus, listener) =
            if self.dbus_broker.is_none() && self.dbus_daemon.is_some() {
                self.dd_spawn()?
            } else {
                self.db_spawn()?
            };
        session.listener = listener;
        session.bus = Some(bus);
        session.ctrl = Some(self.ctrl_spawn()?);

        Ok(session)
    }
}

impl Session {
    fn new() -> Self {
        Self {
            listener: None,
            bus: None,
            ctrl: None,
        }
    }

    /// Wait for session controller to exit
    ///
    /// Wait for the session controller process to exit. Then tear down the
    /// message broker and forward the exit code of the session controller to
    /// the caller.
    ///
    /// If the message broker exits before the session controller, a warning
    /// is triggered but the session controller is still monitored.
    ///
    /// Both the message broker and the session controller will receive SIGTERM
    /// if the session object is destroyed.
    pub fn wait(mut self) -> Result<(), u8> {
        let mut bus_id = self.bus.as_ref().map(|v| v.id());
        let ctrl_id = self.ctrl.as_ref().map(|v| v.id());

        loop {
            let mut status: libc::c_int = 0;
            let r: libc::pid_t;

            unsafe {
                r = libc::wait(&mut status);
                if r < 0 {
                    // There is no valid reason for `wait(2)` to fail. Log the
                    // error and abort the entire session.

                    return Err(Cli::error_self(format_args!(
                        "waiting for sub-processes failed: {}",
                        std::io::Error::last_os_error(),
                    )));

                } else if matches!(bus_id, Some(id) if id == r as u32) {
                    // If the message broker exits, we continue tracking the
                    // session controller and allow the session to exit
                    // gracefully. In most cases, the session controller will
                    // notice the missing bus and initiate termination itself.

                    bus_id = None;
                    self.bus = None;

                    if libc::WIFEXITED(status) {
                        Cli::warning(format_args!(
                            "message broker exited unexpectedly with {}",
                            libc::WEXITSTATUS(status),
                        ));
                    } else if libc::WIFSIGNALED(status) {
                        Cli::warning(format_args!(
                            "message broker was terminated by signal {}",
                            libc::WTERMSIG(status),
                        ));
                    } else {
                        Cli::warning(format_args!(
                            "message broker was terminated unexpectedly",
                        ));
                    }

                } else if matches!(ctrl_id, Some(id) if id == r as u32) {
                    // If the session controller exits, we immediately
                    // termiante the message broker and forward the exit
                    // condition to the caller.

                    self.ctrl = None;

                    let r = if libc::WIFEXITED(status) {
                        Err(libc::WEXITSTATUS(status) as u8)
                    } else if libc::WIFSIGNALED(status) {
                        Err(Cli::ERROR_SIGNAL + (libc::WTERMSIG(status) as u8))
                    } else {
                        Err(Cli::error_self(format_args!(
                            "session controller was terminated unexpectedly",
                        )))
                    };

                    return r;

                } else {
                    // If, for whatever reason, we have PR_SET_CHILD_SUBREAPER
                    // set for us, ignore any other exiting sub-processes.
                }
            }
        }
    }
}

// Implement process and file cleanup on drop
//
// The session object tracks the message broker and the session controller, and
// we want to ensure they are properly terminated when the caller exits for any
// unexpected reason.
//
// We send `SIGTERM` to either process and expect them to handle any further
// termination gracefully. We do not await termination or perform any other
// elaborate tracking on drop, since we do not want to incur any delays.
//
// Note that both processes have `PDEATHSIG` set to `SIGTERM`, so they should
// be cleaned up if this process crashes. That is, this drop-handler is only
// required if the session is controlled in a long-running process that might
// drop sessions but continue running.
//
// Lastly, we drop the listener socket from the file-system if there is one.
// This ensures we do not leave them around in `/tmp` and pollute the tmpfs.
impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            if let Some(proc) = self.ctrl.as_ref() {
                let _ = libc::kill(proc.id() as i32, libc::SIGTERM);
            }
            if let Some(proc) = self.bus.as_ref() {
                let _ = libc::kill(proc.id() as i32, libc::SIGTERM);
            }
            if let Some(path) = self.listener.as_ref() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// Session Initiation Main Entry
///
/// This is the main entry point of the `dbus-broker-session` program. It is
/// wrapped by a C stub that directly wraps this function from `int main()`.
#[export_name = "dbrk_session_main"]
pub extern "C" fn main(
    argc: i32,
    argv: *const *const u8,
) -> i32 {
    // Create slice from raw argc+argv passed to us through the C ABI.
    let args: &[*const u8];
    unsafe {
        args = std::slice::from_raw_parts(
            argv,
            argc.try_into().expect("Cannot parse program argument length"),
        );
    }

    // Clear possible leftovers from other sessions.
    std::env::remove_var("DBUS_SESSION_BUS_PID");
    std::env::remove_var("DBUS_SESSION_BUS_WINDOWID");
    std::env::remove_var("DBUS_STARTER_ADDRESS");
    std::env::remove_var("DBUS_STARTER_BUS_TYPE");

    // Create the CLI manager and use it to parse the command-line into the
    // configuration type.
    let cli = Cli::new();
    let config = match cli.parse(args) {
        Err(v) => return v.into(),
        Ok(None) => return 0.into(),
        Ok(Some(v)) => v,
    };

    // Spawn the message bus and the session controller as specified in the
    // configuration.
    let session = match config.initiate() {
        Ok(v) => v,
        Err(v) => return v.into(),
    };

    // Wait for the session controller to exit.
    match session.wait() {
        Ok(_) => {},
        Err(v) => return v.into(),
    }

    0
}
