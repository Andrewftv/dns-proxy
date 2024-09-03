use chrono::{DateTime, Local};

#[allow(dead_code)]
#[cfg(debug_assertions)]
pub fn print_dump(buff : &[u8], size : usize) {
    for i in 0..size {
        if i != 0 && ((i % 16) == 0) {
            print!("\n");
        }
        print!("{:02X?} ", buff[i]);
    }
    print!("\n");
}

#[allow(dead_code)]
#[allow(unused_variables)]
#[cfg(not(debug_assertions))]
pub fn print_dump(buff : &[u8], size : usize) {
}

#[derive(PartialEq)]
pub enum LogSeverity {
    None,
    Debug,
    Info,
    Warn,
    Error,
}

pub fn log_print(severity : LogSeverity, msg : &str) {
    if severity != LogSeverity::None {
        let sev_str : &str;
        match severity {
            LogSeverity::Debug => sev_str = "[D] ",
            LogSeverity::Info => sev_str = "[I] ",
            LogSeverity::Warn => sev_str = "[W] ",
            LogSeverity::Error => sev_str = "[E] ",
            _ => sev_str = "",
        }
        let now : DateTime<Local> = Local::now();
        print!("{}: {}{}", now.format("%Y/%m/%d %T:%.3f"), sev_str, msg);
    } else {
        print!("{}", msg);
    }
}

#[macro_export]
macro_rules! log_print 
{
    ($fmt:expr) => {
        $crate::utils::log_print($crate::utils::LogSeverity::None, $fmt);
    };
    ($fmt:expr, $($args:tt)*) => {
        let str = std::fmt::format(format_args!($fmt, $($args)*));
        $crate::utils::log_print($crate::utils::LogSeverity::None, &str);
    };
}
#[macro_export]
macro_rules! log_debug 
{
    ($fmt:expr) => {
        $crate::utils::log_print($crate::utils::LogSeverity::Debug, $fmt);
    };
    ($fmt:expr, $($args:tt)*) => {
        let str = std::fmt::format(format_args!($fmt, $($args)*));
        $crate::utils::log_print($crate::utils::LogSeverity::Debug, &str);
    };
}
#[macro_export]
macro_rules! log_info 
{
    ($fmt:expr) => {
        $crate::utils::log_print($crate::utils::LogSeverity::Info, $fmt);
    };
    ($fmt:expr, $($args:tt)*) => {
        let str = std::fmt::format(format_args!($fmt, $($args)*));
        $crate::utils::log_print($crate::utils::LogSeverity::Info, &str);
    };
}
#[macro_export]
macro_rules! log_warn 
{
    ($fmt:expr) => {
        $crate::utils::Logs::log_print($crate::utils::LogSeverity::Warn, $fmt);
    };
    ($fmt:expr, $($args:tt)*) => {
        let str = std::fmt::format(format_args!($fmt, $($args)*));
        $crate::utils::log_print($crate::utils::LogSeverity::Warn, &str);
    };
}
#[macro_export]
macro_rules! log_error
{
    ($fmt:expr) => {
        $crate::utils::log_print($crate::utils::LogSeverity::Error, $fmt);
    };
    ($fmt:expr, $($args:tt)*) => {
        let str = std::fmt::format(format_args!($fmt, $($args)*));
        $crate::utils::log_print($crate::utils::LogSeverity::Error, &str);
    };
}
