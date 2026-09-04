//! Fake Linux host tools for installer integration tests.

use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::Path,
    process::{Child, Command, ExitCode},
    thread,
    time::{Duration, Instant},
};

const STATE: &str = "/target";

fn main() -> ExitCode {
    let program = env::args_os()
        .next()
        .and_then(|path| Path::new(&path).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.into_string().ok());
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let status = match program.as_deref() {
        Some("systemctl") => systemctl(&arguments),
        Some("getent") => getent(&arguments),
        Some("groupadd") => groupadd(&arguments),
        Some("groupdel") => groupdel(&arguments),
        Some("useradd") => useradd(&arguments),
        Some("timeout") => timeout(&arguments),
        Some("nologin") => 1,
        _ => 2,
    };
    ExitCode::from(u8::try_from(status).unwrap_or(255))
}

fn systemctl(arguments: &[String]) -> i32 {
    match arguments.first().map(String::as_str) {
        Some("show-environment") => 0,
        Some("cat") => 1,
        Some("is-active") => 3,
        Some("is-enabled") => 1,
        _ => 9,
    }
}

fn getent(arguments: &[String]) -> i32 {
    let Some(database) = arguments.first().map(String::as_str) else {
        return 1;
    };
    let key = arguments.get(1).map(String::as_str);
    let records = match database {
        "passwd" => records(
            "root:x:0:0:root:/root:/bin/sh\nservice:x:1:999::/:/usr/sbin/nologin\n",
            "passwd-state",
            Some("passwd-extra"),
        ),
        "shadow" => records("", "shadow-state", None),
        "group" => records("root:x:0:\nunrelated:x:998:member\n", "group-state", None),
        _ => return 1,
    };
    let Ok(records) = records else {
        return 1;
    };
    if let Some(key) = key {
        let matches = records
            .lines()
            .filter(|record| record_matches(database, record, key))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return if matches.is_empty() { 2 } else { 3 };
        }
        println!("{}", matches[0]);
    } else {
        print!("{records}");
    }
    0
}

fn records(initial: &str, state: &str, extra: Option<&str>) -> io::Result<String> {
    let mut output = initial.to_owned();
    for name in [Some(state), extra].into_iter().flatten() {
        match fs::read_to_string(Path::new(STATE).join(name)) {
            Ok(value) => output.push_str(&value),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error),
        }
    }
    Ok(output)
}

fn record_matches(database: &str, record: &str, key: &str) -> bool {
    let fields = record.split(':').collect::<Vec<_>>();
    match database {
        "passwd" => fields.first() == Some(&key) || fields.get(2) == Some(&key),
        "shadow" => fields.first() == Some(&key),
        "group" => fields.first() == Some(&key) || fields.get(2) == Some(&key),
        _ => false,
    }
}

fn groupadd(arguments: &[String]) -> i32 {
    log_command("identity-commands", "groupadd", arguments);
    if arguments.len() != 4
        || arguments[0] != "--system"
        || arguments[1] != "--gid"
        || !matches!(arguments[3].as_str(), "kapsel" | "kapsel-service-callers")
    {
        return 2;
    }
    if state_exists("group-timeout") {
        touch("group-command-started");
        thread::sleep(Duration::from_secs(30));
    } else if state_exists("group-delay") {
        touch("group-command-started");
        thread::sleep(Duration::from_millis(600));
    }
    let current = fs::read_to_string(Path::new(STATE).join("group-state")).unwrap_or_default();
    if current.lines().any(|record| {
        let fields = record.split(':').collect::<Vec<_>>();
        fields.first() == Some(&arguments[3].as_str())
            || fields.get(2) == Some(&arguments[2].as_str())
    }) {
        return 9;
    }
    append(
        "group-state",
        &format!("{}:x:{}:\n", arguments[3], arguments[2]),
    );
    0
}

fn groupdel(arguments: &[String]) -> i32 {
    log_command("identity-commands", "groupdel", arguments);
    if arguments.len() != 1
        || !matches!(arguments[0].as_str(), "kapsel" | "kapsel-service-callers")
    {
        return 2;
    }
    let path = Path::new(STATE).join("group-state");
    let current = fs::read_to_string(&path).unwrap_or_default();
    if !current
        .lines()
        .any(|record| record.split(':').next() == Some(arguments[0].as_str()))
    {
        return 6;
    }
    let mut retained = String::new();
    for record in current
        .lines()
        .filter(|record| record.split(':').next() != Some(arguments[0].as_str()))
    {
        retained.push_str(record);
        retained.push('\n');
    }
    if retained.is_empty() {
        let _ = fs::remove_file(path);
    } else if fs::write(path, retained).is_err() {
        return 1;
    }
    0
}

fn useradd(arguments: &[String]) -> i32 {
    log_command("identity-commands", "useradd", arguments);
    if arguments.len() != 17
        || arguments[0] != "--system"
        || arguments[1] != "--uid"
        || arguments[3] != "--gid"
        || arguments[5] != "--no-create-home"
        || arguments[6] != "--home-dir"
        || arguments[8] != "--shell"
        || arguments[9] != "/usr/sbin/nologin"
        || arguments[10] != "--comment"
        || arguments[12] != "--no-user-group"
        || arguments[13] != "--no-log-init"
        || arguments[14] != "--password"
        || arguments[15] != "!"
        || !matches!(
            (arguments[16].as_str(), arguments[7].as_str()),
            ("kapsel", "/var/lib/kapsel") | ("kapsel-service-caller", "/nonexistent")
        )
    {
        return 2;
    }
    if state_exists("user-timeout") {
        touch("user-command-started");
        thread::sleep(Duration::from_secs(30));
    }
    let current = fs::read_to_string(Path::new(STATE).join("passwd-state")).unwrap_or_default();
    if current.lines().any(|record| {
        let fields = record.split(':').collect::<Vec<_>>();
        fields.first() == Some(&arguments[16].as_str())
            || fields.get(2) == Some(&arguments[2].as_str())
    }) {
        return 9;
    }
    append(
        "passwd-state",
        &format!(
            "{}:x:{}:{}:{}:{}:{}\n",
            arguments[16], arguments[2], arguments[4], arguments[11], arguments[7], arguments[9]
        ),
    );
    append(
        "shadow-state",
        &format!("{}:!:20000::::::\n", arguments[16]),
    );
    0
}

fn timeout(arguments: &[String]) -> i32 {
    log_command("timeout-commands", "timeout", arguments);
    if arguments.len() < 3 || arguments[0] != "--signal=KILL" || arguments[1] != "10s" {
        return 2;
    }
    let Ok(mut child) = Command::new(&arguments[2]).args(&arguments[3..]).spawn() else {
        return 1;
    };
    let bound = if state_exists("group-timeout") || state_exists("user-timeout") {
        Duration::from_millis(300)
    } else {
        Duration::from_secs(10)
    };
    wait_bounded(&mut child, bound)
}

fn wait_bounded(child: &mut Child, bound: Duration) -> i32 {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code().unwrap_or(137),
            Ok(None) if started.elapsed() < bound => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return 137;
            },
            Err(_) => return 1,
        }
    }
}

fn state_exists(name: &str) -> bool {
    Path::new(STATE).join(name).exists()
}

fn touch(name: &str) {
    let _ = fs::write(Path::new(STATE).join(name), b"");
}

fn append(name: &str, value: &str) {
    let path = Path::new(STATE).join(name);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(value.as_bytes());
    }
}

fn log_command(name: &str, program: &str, arguments: &[String]) {
    append(name, &format!("{program} {}\n", arguments.join(" ")));
}
