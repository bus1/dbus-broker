//! Session Initiation
//!
//! This module implements the `dbus-broker-session` functionality, which
//! initiates new D-Bus sessions together with a session controller.

use libc;

/// Command-line Interface
///
/// This structure provides all command-line handling, which currently means
/// parsing command-line arguments, providing process termination, and dealing
/// with diagnostics.
pub struct Cli {
}

/// Session Configuration
///
/// This encapsulates all parameters required to initiate a new session.
/// Preferably, no ambient resources are needed for the session, yet for
/// legacy compatibility to dbus-daemon this is not true if dbus-daemon is used
/// as broker for the session.
#[derive(Debug)]
pub struct Config {
    pub config_file: Option<std::ffi::OsString>,
    pub dbus_broker: Option<std::ffi::OsString>,
    pub dbus_daemon: Option<std::ffi::OsString>,
    pub arg0: std::ffi::OsString,
    pub args: Vec<std::ffi::OsString>,
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
        ).expect("STDERR must be writable");
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
        Self {
        }
    }

    /// Parse command-line arguments
    ///
    /// Take the Cli controller and a set of command-line arguments and parse
    /// them into a new configuration object. The Cli controller is completely
    /// consumed and will not consume stack space during execution.
    pub fn parse(
        mut self,
        args: &[*mut u8],
    ) -> Result<Option<Config>, u8> {
        use osi::args;

        let help = args::help::Help::with(
            "dbus-broker-session",
            "Initiate a D-Bus session with a new session controller.",
        );

        let mut root_params: Option<Vec<&osi::compat::OsStr>> = None;
        let mut root_flag_config_file: Option<&osi::compat::OsStr> = None;
        let mut root_flag_dbus_broker: Option<&osi::compat::OsStr> = None;
        let mut root_flag_dbus_daemon: Option<&osi::compat::OsStr> = None;
        let mut root_flag_help = help.flag();

        let mut root_flags = args::FlagSet::with([
            args::Flag::with("config-file", args::FlagMode::Parse, &mut root_flag_config_file, Some("Path to the config file of the message broker")),
            args::Flag::with("dbus-broker", args::FlagMode::Parse, &mut root_flag_dbus_broker, Some("Name or path of the dbus-broker executable")),
            args::Flag::with("dbus-daemon", args::FlagMode::Parse, &mut root_flag_dbus_daemon, Some("Name or path of the dbus-daemon executable")),
            args::Flag::with("help", args::FlagMode::Set, &mut root_flag_help, Some("Show usage information and exit")),
        ]);
        let mut commands = args::CommandSet::with([
            args::Command::with(&[], &mut root_params, &mut root_flags, None),
        ]);
        let mut schema = args::Schema::<()>::with(&mut commands);

        let mut errors = Vec::new();
        let mut arg_iter = &mut args.iter().skip(1).map(
            |v| {
                let cstr = unsafe {
                    std::ffi::CStr::from_ptr(*v as *mut std::ffi::c_char)
                };
                <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(cstr.to_bytes()).into()
            },
        );

        let _ = args::parse(&mut errors, &mut schema, &mut arg_iter);

        if !errors.is_empty() {
            for e in errors {
                std::eprintln!("PARSE: {:?}", e);
            }

            return Err(Self::ERROR_SELF);
        }

        match help.try_help(&mut self, &schema) {
            Err(()) => return Err(Self::ERROR_SELF),
            Ok(true) => return Ok(None),
            Ok(false) => {},
        }

        let v_config_file = root_flag_config_file.map(|v| v.as_osstr().to_owned());
        let v_dbus_broker = root_flag_dbus_broker.map(|v| v.as_osstr().to_owned());
        let v_dbus_daemon = root_flag_dbus_daemon.map(|v| v.as_osstr().to_owned());
        let (v_arg0, v_args) = match root_params {
            None => return Err(Cli::error_self(format_args!("Session controller executable must be specified on the command-line"))),
            Some(mut v) => {
                if v.is_empty() {
                    return Err(Cli::error_self(format_args!("Session controller executable must be specified on the command-line")));
                } else {
                    let first = v.remove(0).into();
                    let rem = v.iter().map(|v| v.as_osstr().to_owned()).collect();
                    (first, rem)
                }
            },
        };

        Ok(Some(Config {
            config_file: v_config_file,
            dbus_broker: v_dbus_broker,
            dbus_daemon: v_dbus_daemon,
            arg0: v_arg0,
            args: v_args,
        }))
    }
}

impl osi::args::help::Write<()> for Cli {
    fn write_info(
        &mut self,
        info: &str,
    ) -> core::ops::ControlFlow<()> {
        <std::io::Stderr as std::io::Write>::write_fmt(
            &mut std::io::stderr(),
            format_args!("{}\n", info),
        ).expect("STDERR must be writable");

        core::ops::ControlFlow::Continue(())
    }

    fn write_section(
        &mut self,
        section: &str,
    ) -> core::ops::ControlFlow<()> {
        <std::io::Stderr as std::io::Write>::write_fmt(
            &mut std::io::stderr(),
            format_args!("\n{}:\n", section),
        ).expect("STDERR must be writable");

        core::ops::ControlFlow::Continue(())
    }

    fn write_usage(
        &mut self,
        entry: &str,
        path: &[&str],
    ) -> core::ops::ControlFlow<()> {
        let str_path = (!path.is_empty()).then_some(std::format!(" {}", path.join(" ")));

        <std::io::Stderr as std::io::Write>::write_fmt(
            &mut std::io::stderr(),
            format_args!("        {}{} [FLAGS] -- EXECUTABLE [ARGS..]\n", entry, str_path.as_deref().unwrap_or("")),
        ).expect("STDERR must be writable");

        core::ops::ControlFlow::Continue(())
    }

    fn write_flag(
        &mut self,
        flag: &str,
        mode: osi::args::FlagMode,
        info: Option<&str>,
        width: usize,
    ) -> core::ops::ControlFlow<()> {
        const TOGGLE: &str = "[no-]";
        const VALUE: &str = " <VALUE>";

        let (toggle, value) = match mode {
            osi::args::FlagMode::Set => ("", ""),
            osi::args::FlagMode::Toggle => (TOGGLE, ""),
            osi::args::FlagMode::Parse => ("", VALUE),
        };

        let max_width = width + usize::max(TOGGLE.len(), VALUE.len()) + 2;
        let cur_width = flag.len() + toggle.len() + value.len();

        <std::io::Stderr as std::io::Write>::write_fmt(
            &mut std::io::stderr(),
            format_args!(
                "      --{}{}{}{3:4$}{5}\n",
                toggle,
                flag,
                value,
                "",
                max_width - cur_width,
                info.unwrap_or(""),
            ),
        ).expect("STDERR must be writable");

        core::ops::ControlFlow::Continue(())
    }

    fn write_command(
        &mut self,
        command: &str,
        info: Option<&str>,
        width: usize,
    ) -> core::ops::ControlFlow<()> {
        let max_width = width + 2;
        let cur_width = command.len();

        <std::io::Stderr as std::io::Write>::write_fmt(
            &mut std::io::stderr(),
            format_args!(
                "        {}{1:2$}{3}\n",
                command,
                "",
                max_width - cur_width,
                info.unwrap_or(""),
            ),
        ).expect("STDERR must be writable");

        core::ops::ControlFlow::Continue(())
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
        let arg0_default: std::ffi::OsString = "dbus-daemon".to_string().into();
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
        let listener = std::os::unix::net::UnixListener::bind(addr).map_err(
            |v| Cli::error_self(format_args!("Cannot create listener socket {}: {}", addr, v)),
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
        let arg0_default: std::ffi::OsString = "dbus-broker-launch".to_string().into();
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
                        c"LISTEN_PID".as_ptr(),
                        pidstr.as_ptr() as *const std::ffi::c_char,
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
                        c"LISTEN_FDS".as_ptr(),
                        c"1".as_ptr(),
                        1,
                    ) {
                        r if r < 0 => {
                            let e = std::io::Error::last_os_error();
                            Cli::error_self(format_args!("Cannot set LISTEN_FDS: {}", e));
                            Err(e)
                        },
                        _ => Ok(()),
                    }?;

                    match libc::setenv(
                        c"LISTEN_FDNAMES".as_ptr(),
                        c"dbus.socket".as_ptr(),
                        1,
                    ) {
                        r if r < 0 => {
                            let e = std::io::Error::last_os_error();
                            Cli::error_self(format_args!("Cannot set LISTEN_FDNAMES: {}", e));
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
/// wrapped by a C stub that directly calls this function from `int main()`.
pub fn run(args: &[*mut u8]) -> i32 {
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
        Ok(None) => return 0,
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
