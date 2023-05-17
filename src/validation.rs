pub fn simplify(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| match c {
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' => 'b',
            '0' => 'o',
            '$' => 's',
            '!' => 'i',
            _ => c,
        })
        .collect()
}

pub fn username(name: &str) -> Result<(), &'static str> {
    if !(3..32).contains(&name.len()) {
        return Err("username: length out of range");
    }

    // ideally this would be a list of slurs like passwords.txt.
    // this here is just a small list to test.
    let banned_keywords = ["admin", "administrator", "nword"];

    let simplified_name: String = simplify(name);

    if banned_keywords
        .iter()
        .any(|keyword| simplified_name.as_str().contains(*keyword))
    {
        return Err("username: banned keyword");
    }

    if name
        .chars()
        .any(|x| !x.is_ascii_alphanumeric() && !x.is_ascii_punctuation())
    {
        return Err("username: disallowed characters");
    }

    Ok(())
}

pub fn password(password: &str) -> Result<(), &'static str> {
    if !(8..).contains(&password.len()) {
        return Err("password: too short");
    }

    // let mut banned_passwords = include_str!("passwords.txt").split('\n');

    // if banned_passwords.any(|keyword| password == keyword) {
    //     return Err("password: in top1k list");
    // }

    Ok(())
}

#[test]
fn username_validation() {
    username("unknowntrojan").unwrap();
    username("xd").unwrap_err();
    username("xuliet").unwrap();
    username("RealMan420").unwrap();
    username("G3N1U5").unwrap();
    username("__").unwrap_err();
    username("..").unwrap_err();
    username("oisdhfoashdfgohasdopfh").unwrap();
    username("()7/(=&$§$§").unwrap_err();
    username("nword").unwrap_err();
    username("nw0rd").unwrap_err();
    username("normalname\n").unwrap_err();
}

#[test]
fn password_validation() {
    password("123456").unwrap_err();
    password("aa").unwrap_err();
    password("OIASUHDOPIAHSDOPIHASOPDHPAOISHDPOAISHDPOASHDOPAISHD").unwrap();
    password(".6WV@Ud35VBnHeOiK&F!kr':Sh+s90v$").unwrap();
    password("l{/H^(Y-dT)MeLrhPfUtn/I-[`UNjxq*").unwrap();
    password("0:&LD))6q6gP_\\oZ`k}ZOM=8fpEYwgn\\").unwrap();
    password("4FH73~V'&ZJ_!\"t}4`*}*hBSxaqC:fMd").unwrap();
    username("normalpassword\n").unwrap_err();
}

#[test]
fn simplification_validation() {
    assert_eq!(simplify("$1mple"), "simple");
    assert_eq!(simplify("genius"), "genius");
    assert_eq!(simplify("g3n1u5"), "genius");
    assert_eq!(simplify("G3N1U5"), "genius");
    assert_eq!(simplify("l0lh4x0r"), "lolhaxor");
}
