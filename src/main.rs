use chrono::{Local, Timelike};
use chrono_tz::Asia::Shanghai;
use std::fs;
use std::time::Duration;
use std::{io, thread};

fn extract<'a>(text: &'a str, prefix: &'a str, suffix: &'a str) -> io::Result<&'a str> {
    let left = text.find(prefix);
    let right = text.find(suffix);
    if let (Some(l), Some(r)) = (left, right) {
        if l + prefix.len() < r {
            return Ok(&text[l + prefix.len()..r]);
        }
    }
    Err(io::ErrorKind::InvalidData.into())
}

fn is_user(username: &str) -> io::Result<bool> {
    let resp =
        minreq::get("http://192.168.50.3:8080/eportal/InterFace.do?method=getOnlineUserInfo")
            .with_timeout(3)
            .send()
            .map_err(|e| {
                println!("get user failed: {}", e);
                io::ErrorKind::ConnectionRefused
            })?;
    let resp = resp.as_str().map_err(|e| {
        println!("invalid resp format {}", e);
        io::ErrorKind::InvalidData
    })?;
    if resp.contains(username) {
        Ok(true)
    } else {
        println!("not current user!");
        Ok(false)
    }
}

fn logout() {
    println!("logout...");
    let resp = minreq::get("http://192.168.50.3:8080/eportal/InterFace.do?method=logout")
        .with_timeout(3)
        .send();
    if resp.is_err(){
        println!("logout failed");
        return;
    }
    println!("{}",resp.unwrap().as_str().unwrap_or("get resp body failed"));
    thread::sleep(Duration::from_secs(3));
}

fn login(username: &str, password: &str) -> io::Result<()> {
    match is_user(username) {
        Ok(res) => {
            if !res {
                logout();
            }
        }
        Err(_) => {
            logout();
        }
    }
    let resp = minreq::get("http://www.baidu.com")
        .with_timeout(3)
        .send()
        .map_err(|e| {
            println!("baidu boom! {}", e);
            io::ErrorKind::ConnectionRefused
        })?;
    let resp = resp.as_str().map_err(|e| {
        println!("invalid resp format {}", e);
        io::ErrorKind::InvalidData
    })?;
    if !resp.contains("/eportal/index.jsp")
        && !resp.contains("<script>top.self.location.href='http://")
    {
        return Ok(());
    }

    let portal_ip = extract(
        resp,
        "<script>top.self.location.href='http://",
        "/eportal/index.jsp",
    )?;
    println!("portal ip: {}", portal_ip);

    let query_string = extract(resp, "/eportal/index.jsp?", "'</script>\r\n")?;
    println!("query_string: {}", query_string);

    let query_string = urlencoding::encode(query_string);

    let body = format!(
        "userId={}&password={}&service=&queryString={}&passwordEncrypt=false",
        username, password, query_string
    );

    let login_url = format!("http://{}/eportal/InterFace.do?method=login", portal_ip);

    let resp = minreq::post(login_url)
        .with_body(body)
        .with_header(
            "Content-Type",
            "application/x-www-form-urlencoded; charset=UTF-8",
        )
        .with_header("Accept", "*/*")
        .with_header("User-Agent", "hust-network-login")
        .with_timeout(3)
        .send()
        .map_err(|e| {
            println!("portal boom! {}", e);
            io::ErrorKind::ConnectionRefused
        })?;

    let resp = resp.as_str().map_err(|e| {
        println!("invalid login resp format {}", e);
        io::ErrorKind::InvalidData
    })?;

    println!("login resp: {}", resp);

    if resp.contains("success") {
        Ok(())
    } else {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

#[test]
fn login_test() {
    let _ = login("username", "password");
}

fn main() {
    let args = std::env::args();
    if args.len() <= 1 {
        panic!("give me your config filename, you idiot")
    }
    let path = args.last().unwrap();
    let s = String::from_utf8(fs::read(&path).unwrap()).unwrap();
    let mut lines = s.lines();
    let username = lines.next().unwrap().to_owned();
    let password = lines.next().unwrap().to_owned();
    let night_username = lines.next().unwrap_or("").to_owned();
    let night_password = lines.next().unwrap_or("").to_owned();
    let current_time = Local::now().with_timezone(&Shanghai);
    let minute = current_time.minute();
    let hour = current_time.hour();
    println!("{}:{}",hour,minute);
    if !night_username.is_empty() && ((hour >= 23 && minute >= 45) || (hour <= 7)) {
        match login(&night_username, &night_password) {
            Ok(_) => {
                println!("login night account ok. awaiting...");
            }
            Err(e) => {
                println!("error! {}", e);
            }
        }
    } else {
        match login(&username, &password) {
            Ok(_) => {
                println!("login ok. awaiting...");
            }
            Err(e) => {
                println!("error! {}", e);
            }
        }
    }
}
