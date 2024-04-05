use std::{ffi::CStr, os::unix::net::SocketAddr};

macro_rules! export_libc {
    ($name:ident($( $arg:ident : $type:ty ),*) -> $ret:ty) => {
        #[export_name = concat!("unix_", stringify!($name))]
        #[no_mangle]
        pub unsafe extern "C" fn $name($( $arg : $type),*) -> $ret {
            libc::$name($( $arg ),*)
        }
    };
}

macro_rules! dummy_libc {
    ($name:ident($( $arg:ident : $type:ty ),*) -> $ret:ty) => {
        #[export_name = concat!("unix_", stringify!($name))]
        #[no_mangle]
        pub unsafe extern "C" fn $name($( $arg : $type),*) -> $ret {
            panic!("unimplemented {}", stringify!($name))
        }
    };
}
macro_rules! dummy_caml {
    ($name:ident($( $arg:ident : $type:ty ),*) -> $ret:ty) => {
        #[export_name = concat!("caml_", stringify!($name))]
        #[no_mangle]
        pub unsafe extern "C" fn $name($( $arg : $type),*) -> $ret {
            panic!("unimplemented {}", stringify!($name))
        }
    };
}
macro_rules! dummy_re {
    ($name:ident($( $arg:ident : $type:ty ),*) -> $ret:ty) => {
        #[export_name = concat!("re_", stringify!($name))]
        #[no_mangle]
        pub unsafe extern "C" fn $name($( $arg : $type),*) -> $ret {
            panic!("unimplemented {}", stringify!($name))
        }
    };
}
//caml_condition_broadcast
dummy_caml!(condition_broadcast(cond: *mut libc::pthread_cond_t) -> libc::c_int);
//caml_condition_new
dummy_caml!(condition_new() -> *mut libc::pthread_cond_t);
//caml_condition_signal
dummy_caml!(condition_signal(cond: *mut libc::pthread_cond_t) -> libc::c_int);
//caml_condition_wait
dummy_caml!(condition_wait(cond: *mut libc::pthread_cond_t, mutex: *mut libc::pthread_mutex_t) -> libc::c_int);
//caml_mutex_lock
dummy_caml!(mutex_lock(mutex: *mut libc::pthread_mutex_t) -> libc::c_int);
//caml_mutex_new
#[export_name = "caml_mutex_new"]
#[no_mangle]
pub unsafe extern "C" fn mutex_new() -> *mut libc::pthread_mutex_t {
    let mutex = libc::PTHREAD_MUTEX_INITIALIZER;
    let mutex = Box::new(mutex);
    let ptr = Box::into_raw(mutex);
    ptr
}
//caml_mutex_try_lock
dummy_caml!(mutex_try_lock(mutex: *mut libc::pthread_mutex_t) -> libc::c_int);
//caml_mutex_unlock
dummy_caml!(mutex_unlock(mutex: *mut libc::pthread_mutex_t) -> libc::c_int);
//caml_thread_cleanup
dummy_caml!(thread_cleanup() -> ());
//caml_thread_exit
dummy_caml!(thread_exit() -> ());
//caml_thread_id
dummy_caml!(thread_id() -> libc::pthread_t);
//caml_thread_initialize
#[export_name = "caml_thread_initialize"]
#[no_mangle]
pub unsafe extern "C" fn thread_initialize() {}
//caml_thread_join
dummy_caml!(thread_join(thread: libc::pthread_t) -> ());
//caml_thread_new
dummy_caml!(thread_new() -> libc::pthread_t);
//caml_thread_self
dummy_caml!(thread_self() -> libc::pthread_t);
//caml_thread_sigmask
dummy_caml!(thread_sigmask(how: libc::c_int, set: *const libc::sigset_t, oldset: *mut libc::sigset_t) -> libc::c_int);
//caml_thread_uncaught_exception
dummy_caml!(thread_uncaught_exception() -> libc::c_int);
//caml_thread_yield
dummy_caml!(thread_yield() -> libc::c_int);
//caml_unix_map_file
dummy_caml!(unix_map_file(fd: libc::c_int, shared: libc::c_int, len: libc::size_t) -> *mut libc::c_void);
//caml_wait_signal
dummy_caml!(wait_signal() -> libc::c_int);
//re_partial_match
dummy_re!(partial_match(re: *mut libc::regex_t, buf: *const libc::c_char, len: libc::size_t, start: libc::size_t, eflags: libc::c_int, pmatch: *mut libc::regmatch_t, nmatch: libc::size_t) -> libc::c_int);
//re_replacement_text
dummy_re!(replacement_text(re: *mut libc::regex_t, source: *const libc::c_char, dest: *mut libc::c_char, n: libc::size_t) -> libc::c_int);
//re_search_backward
dummy_re!(search_backward(re: *mut libc::regex_t, buf: *const libc::c_char, len: libc::size_t, start: libc::size_t, eflags: libc::c_int, pmatch: *mut libc::regmatch_t, nmatch: libc::size_t) -> libc::c_int);
//re_search_forward
dummy_re!(search_forward(re: *mut libc::regex_t, buf: *const libc::c_char, len: libc::size_t, start: libc::size_t, eflags: libc::c_int, pmatch: *mut libc::regmatch_t, nmatch: libc::size_t) -> libc::c_int);
//re_string_match
dummy_re!(string_match(re: *mut libc::regex_t, buf: *const libc::c_char, eflags: libc::c_int) -> libc::c_int);
//unix_accept
export_libc!(accept(sockfd: libc::c_int, addr: *mut libc::sockaddr, addrlen: *mut libc::socklen_t) -> libc::c_int);
//unix_access
export_libc!(access(path: *const libc::c_char, amode: libc::c_int) -> libc::c_int);
//unix_alarm
export_libc!(alarm(seconds: libc::c_uint) -> libc::c_uint);
//unix_bind
export_libc!(bind(sockfd: libc::c_int, addr: *const libc::sockaddr, addrlen: libc::socklen_t) -> libc::c_int);
//unix_chdir
export_libc!(chdir(path: *const libc::c_char) -> libc::c_int);
//unix_chmod
export_libc!(chmod(path: *const libc::c_char, mode: libc::mode_t) -> libc::c_int);
//unix_chown
export_libc!(chown(path: *const libc::c_char, owner: libc::uid_t, group: libc::gid_t) -> libc::c_int);
//unix_chroot
export_libc!(chroot(path: *const libc::c_char) -> libc::c_int);
//unix_clear_close_on_exec
dummy_libc!(clear_close_on_exec(fd: libc::c_int) -> libc::c_int);
//unix_clear_nonblock
dummy_libc!(clear_nonblock(fd: libc::c_int) -> libc::c_int);
//unix_close
export_libc!(close(fd: libc::c_int) -> libc::c_int);
//unix_closedir
export_libc!(closedir(dirp: *mut libc::DIR) -> libc::c_int);
//unix_connect
export_libc!(connect(sockfd: libc::c_int, addr: *const libc::sockaddr, addrlen: libc::socklen_t) -> libc::c_int);
//unix_dup
export_libc!(dup(fd: libc::c_int) -> libc::c_int);
//unix_dup2
export_libc!(dup2(oldfd: libc::c_int, newfd: libc::c_int) -> libc::c_int);
//unix_environment
dummy_libc!(environment() -> *mut *mut libc::c_char);
//unix_environment_unsafe
dummy_libc!(environment_unsafe() -> *mut *mut libc::c_char);
//unix_error_message
dummy_libc!(error_message() -> *mut libc::c_char);
//unix_execv
export_libc!(execv(path: *const libc::c_char, argv: *const *const libc::c_char) -> libc::c_int);
//unix_execve
export_libc!(execve(path: *const libc::c_char, argv: *const *const libc::c_char, envp: *const *const libc::c_char) -> libc::c_int);
//unix_execvp
export_libc!(execvp(file: *const libc::c_char, argv: *const *const libc::c_char) -> libc::c_int);
//unix_execvpe
dummy_libc!(execvpe(file: *const libc::c_char, argv: *const *const libc::c_char, envp: *const *const libc::c_char) -> libc::c_int);
//unix_exit
export_libc!(exit(status: libc::c_int) -> !);
//unix_fchmod
export_libc!(fchmod(fd: libc::c_int, mode: libc::mode_t) -> libc::c_int);
//unix_fchown
export_libc!(fchown(fd: libc::c_int, owner: libc::uid_t, group: libc::gid_t) -> libc::c_int);
//unix_fork
export_libc!(fork() -> libc::c_int);
//unix_fstat
export_libc!(fstat(fd: libc::c_int, buf: *mut libc::stat) -> libc::c_int);
//unix_fstat_64
dummy_libc!(fstat_64(fd: libc::c_int, buf: *mut libc::stat) -> libc::c_int);
//unix_fsync
export_libc!(fsync(fd: libc::c_int) -> libc::c_int);
//unix_ftruncate
export_libc!(ftruncate(fd: libc::c_int, length: libc::off_t) -> libc::c_int);
//unix_ftruncate_64
dummy_libc!(ftruncate_64(fd: libc::c_int, length: libc::off_t) -> libc::c_int);
//unix_getaddrinfo
export_libc!(getaddrinfo(node: *const libc::c_char, service: *const libc::c_char, hints: *const libc::addrinfo, res: *mut *mut libc::addrinfo) -> libc::c_int);
//unix_getcwd
export_libc!(getcwd(buf: *mut libc::c_char, size: libc::size_t) -> *mut libc::c_char);
//unix_getegid
export_libc!(getegid() -> libc::gid_t);
//unix_geteuid
export_libc!(geteuid() -> libc::uid_t);
//unix_getgid
export_libc!(getgid() -> libc::gid_t);
//unix_getgrgid
export_libc!(getgrgid(gid: libc::gid_t) -> *mut libc::group);
//unix_getgrnam
export_libc!(getgrnam(name: *const libc::c_char) -> *mut libc::group);
//unix_getgroups
export_libc!(getgroups(size: libc::c_int, list: *mut libc::gid_t) -> libc::c_int);
//unix_gethostbyaddr
dummy_libc!(gethostbyaddr(addr: *const libc::c_void, len: libc::socklen_t, type_: libc::c_int) -> *mut libc::hostent);
//unix_gethostbyname
dummy_libc!(gethostbyname(name: *const libc::c_char) -> *mut libc::hostent);
//unix_gethostname
export_libc!(gethostname(name: *mut libc::c_char, len: libc::size_t) -> libc::c_int);
//unix_getitimer
export_libc!(getitimer(which: libc::c_int, value: *mut libc::itimerval) -> libc::c_int);
//unix_getlogin
export_libc!(getlogin() -> *mut libc::c_char);
//unix_getnameinfo
export_libc!(getnameinfo(sa: *const libc::sockaddr, salen: libc::socklen_t, host: *mut libc::c_char, hostlen: libc::socklen_t, serv: *mut libc::c_char, servlen: libc::socklen_t, flags: libc::c_int) -> libc::c_int);
//unix_getpeername
export_libc!(getpeername(sockfd: libc::c_int, addr: *mut libc::sockaddr, addrlen: *mut libc::socklen_t) -> libc::c_int);
//unix_getpid
export_libc!(getpid() -> libc::c_int);
//unix_getppid
export_libc!(getppid() -> libc::c_int);
//unix_getprotobyname
export_libc!(getprotobyname(name: *const libc::c_char) -> *mut libc::protoent);
//unix_getprotobynumber
export_libc!(getprotobynumber(proto: libc::c_int) -> *mut libc::protoent);
//unix_getpwnam
export_libc!(getpwnam(name: *const libc::c_char) -> *mut libc::passwd);
//unix_getpwuid
export_libc!(getpwuid(uid: libc::uid_t) -> *mut libc::passwd);
//unix_getservbyname
export_libc!(getservbyname(name: *const libc::c_char, proto: *const libc::c_char) -> *mut libc::servent);
//unix_getservbyport
export_libc!(getservbyport(port: libc::c_int, proto: *const libc::c_char) -> *mut libc::servent);
//unix_getsockname
export_libc!(getsockname(sockfd: libc::c_int, addr: *mut libc::sockaddr, addrlen: *mut libc::socklen_t) -> libc::c_int);
//unix_getsockopt
export_libc!(getsockopt(sockfd: libc::c_int, level: libc::c_int, optname: libc::c_int, optval: *mut libc::c_void, optlen: *mut libc::socklen_t) -> libc::c_int);
//unix_gettimeofday_unboxed
dummy_libc!(gettimeofday_unboxed(tv: *mut libc::timeval) -> libc::c_int);
//unix_getuid
export_libc!(getuid() -> libc::uid_t);
//unix_gmtime
export_libc!(gmtime(timep: *const libc::time_t) -> *mut libc::tm);
//unix_has_symlink
dummy_libc!(has_symlink() -> libc::c_int);
//unix_inchannel_of_filedescr
dummy_libc!(inchannel_of_filedescr(fd: libc::c_int) -> *mut libc::FILE);
//unix_inet_addr_of_string
#[export_name = "unix_inet_addr_of_string"]
#[no_mangle]
pub unsafe extern "C" fn inet_addr_of_string(s: *const libc::c_char) -> libc::c_uint {
    1
}
//unix_initgroups
export_libc!(initgroups(user: *const libc::c_char, group: libc::c_int) -> libc::c_int);
//unix_isatty
export_libc!(isatty(fd: libc::c_int) -> libc::c_int);
//unix_kill
export_libc!(kill(pid: libc::c_int, sig: libc::c_int) -> libc::c_int);
//unix_link
export_libc!(link(oldpath: *const libc::c_char, newpath: *const libc::c_char) -> libc::c_int);
//unix_listen
export_libc!(listen(sockfd: libc::c_int, backlog: libc::c_int) -> libc::c_int);
//unix_localtime
export_libc!(localtime(timep: *const libc::time_t) -> *mut libc::tm);
//unix_lockf
export_libc!(lockf(fd: libc::c_int, cmd: libc::c_int, len: libc::off_t) -> libc::c_int);
//unix_lseek
export_libc!(lseek(fd: libc::c_int, offset: libc::off_t, whence: libc::c_int) -> libc::off_t);
//unix_lseek_64
dummy_libc!(lseek_64(fd: libc::c_int, offset: libc::off_t, whence: libc::c_int) -> libc::off_t);
//unix_lstat
export_libc!(lstat(path: *const libc::c_char, buf: *mut libc::stat) -> libc::c_int);
//unix_lstat_64
dummy_libc!(lstat_64(path: *const libc::c_char, buf: *mut libc::stat) -> libc::c_int);
//unix_mkdir
export_libc!(mkdir(path: *const libc::c_char, mode: libc::mode_t) -> libc::c_int);
//unix_mkfifo
export_libc!(mkfifo(path: *const libc::c_char, mode: libc::mode_t) -> libc::c_int);
//unix_mktime
export_libc!(mktime(tm: *mut libc::tm) -> libc::time_t);
//unix_nice
export_libc!(nice(inc: libc::c_int) -> libc::c_int);
//unix_open
export_libc!(open(path: *const libc::c_char, oflag: libc::c_int) -> libc::c_int);
//unix_opendir
export_libc!(opendir(name: *const libc::c_char) -> *mut libc::DIR);
//unix_outchannel_of_filedescr
dummy_libc!(outchannel_of_filedescr(fd: libc::c_int) -> *mut libc::FILE);
//unix_pipe
export_libc!(pipe(fds: *mut libc::c_int) -> libc::c_int);
//unix_putenv
export_libc!(putenv(string: *mut libc::c_char) -> libc::c_int);
//unix_read
export_libc!(read(fd: libc::c_int, buf: *mut libc::c_void, count: libc::size_t) -> libc::ssize_t);
//unix_readdir
export_libc!(readdir(dirp: *mut libc::DIR) -> *mut libc::dirent);
//unix_readlink
export_libc!(readlink(path: *const libc::c_char, buf: *mut libc::c_char, bufsz: libc::size_t) -> libc::ssize_t);
//unix_realpath
export_libc!(realpath(pathname: *const libc::c_char, resolved: *mut libc::c_char) -> *mut libc::c_char);
//unix_recv
export_libc!(recv(sockfd: libc::c_int, buf: *mut libc::c_void, len: libc::size_t, flags: libc::c_int) -> libc::ssize_t);
//unix_recvfrom
export_libc!(recvfrom(sockfd: libc::c_int, buf: *mut libc::c_void, len: libc::size_t, flags: libc::c_int, addr: *mut libc::sockaddr, addrlen: *mut libc::socklen_t) -> libc::ssize_t);
//unix_rename
export_libc!(rename(oldpath: *const libc::c_char, newpath: *const libc::c_char) -> libc::c_int);
//unix_rewinddir
export_libc!(rewinddir(dirp: *mut libc::DIR) -> ());
//unix_rmdir
export_libc!(rmdir(path: *const libc::c_char) -> libc::c_int);
//unix_select
export_libc!(select(nfds: libc::c_int, readfds: *mut libc::fd_set, writefds: *mut libc::fd_set, exceptfds: *mut libc::fd_set, timeout: *mut libc::timeval) -> libc::c_int);
//unix_send
export_libc!(send(sockfd: libc::c_int, buf: *const libc::c_void, len: libc::size_t, flags: libc::c_int) -> libc::ssize_t);
//unix_sendto_native
dummy_libc!(sendto_native(sockfd: libc::c_int, buf: *const libc::c_void, len: libc::size_t, flags: libc::c_int, addr: *const libc::sockaddr, addrlen: libc::socklen_t) -> libc::ssize_t);
//unix_set_close_on_exec
dummy_libc!(set_close_on_exec(fd: libc::c_int) -> libc::c_int);
//unix_set_nonblock
dummy_libc!(set_nonblock(fd: libc::c_int) -> libc::c_int);
//unix_setgid
export_libc!(setgid(gid: libc::gid_t) -> libc::c_int);
//unix_setgroups
export_libc!(setgroups(size: libc::c_int, list: *const libc::gid_t) -> libc::c_int);
//unix_setitimer
export_libc!(setitimer(which: libc::c_int, value: *const libc::itimerval, ovalue: *mut libc::itimerval) -> libc::c_int);
//unix_setsid
export_libc!(setsid() -> libc::pid_t);
//unix_setsockopt
export_libc!(setsockopt(sockfd: libc::c_int, level: libc::c_int, optname: libc::c_int, optval: *const libc::c_void, optlen: libc::socklen_t) -> libc::c_int);
//unix_setuid
export_libc!(setuid(uid: libc::uid_t) -> libc::c_int);
//unix_shutdown
export_libc!(shutdown(sockfd: libc::c_int, how: libc::c_int) -> libc::c_int);
//unix_sigpending
export_libc!(sigpending(set: *mut libc::sigset_t) -> libc::c_int);
//unix_sigprocmask
export_libc!(sigprocmask(how: libc::c_int, set: *const libc::sigset_t, oldset: *mut libc::sigset_t) -> libc::c_int);
//unix_sigsuspend
export_libc!(sigsuspend(mask: *const libc::sigset_t) -> libc::c_int);
//unix_single_write
dummy_libc!(single_write(fd: libc::c_int, buf: *const libc::c_void, count: libc::size_t) -> isize);
//unix_sleep
export_libc!(sleep(seconds: libc::c_uint) -> libc::c_uint);
//unix_socket
export_libc!(socket(domain: libc::c_int, ty: libc::c_int, protocol: libc::c_int) -> libc::c_int);
//unix_socketpair
export_libc!(socketpair(domain: libc::c_int, ty: libc::c_int, protocol: libc::c_int, sv: *mut libc::c_int) -> libc::c_int);
//unix_spawn
dummy_libc!(spawn(prog: *const libc::c_char, args: *const *const libc::c_char) -> libc::c_int);
//unix_stat_64
dummy_libc!(stat_64(path: *const libc::c_char, buf: *mut libc::stat) -> libc::c_int);
//unix_string_of_inet_addr
dummy_libc!(string_of_inet_addr(addr: libc::in_addr_t) -> *mut libc::c_char);
//unix_time_unboxed
dummy_libc!(time_unboxed() -> libc::time_t);
//unix_truncate_64
dummy_libc!(truncate_64(path: *const libc::c_char, length: libc::off_t) -> libc::c_int);

export_libc!(stat(path: *const libc::c_char, buf: *mut libc::stat) -> libc::c_int);

export_libc!(symlink(target: *const libc::c_char, linkpath: *const libc::c_char) -> libc::c_int);

export_libc!(tcdrain(fd: libc::c_int) -> libc::c_int);

export_libc!(tcflow(fd: libc::c_int, action: libc::c_int) -> libc::c_int);

export_libc!(tcflush(fd: libc::c_int, queue_selector: libc::c_int) -> libc::c_int);

export_libc!(tcgetattr(fd: libc::c_int, termios_p: *mut libc::termios) -> libc::c_int);

export_libc!(tcsendbreak(fd: libc::c_int, duration: libc::c_int) -> libc::c_int);

export_libc!(tcsetattr(fd: libc::c_int, optional_actions: libc::c_int, termios_p: *const libc::termios) -> libc::c_int);

export_libc!(times(buffer: *mut libc::tms) -> libc::clock_t);

export_libc!(truncate(path: *const libc::c_char, length: libc::off_t) -> libc::c_int);

export_libc!(umask(mask: libc::mode_t) -> libc::mode_t);

export_libc!(unlink(path: *const libc::c_char) -> libc::c_int);

export_libc!(utimes(file: *const libc::c_char, times: *const libc::timeval) -> libc::c_int);

export_libc!(waitpid(pid: libc::c_int, status: *mut libc::c_int, options: libc::c_int) -> libc::c_int);

export_libc!(wait(status: *mut libc::c_int) -> libc::c_int);

export_libc!(write(fd: libc::c_int, buf: *const libc::c_void, count: libc::size_t) -> isize);
