import hashaudit;
import std.stdio;
import std.algorithm : canFind, any, count;
import std.array : replicate;

int passed, failed;
void check(bool cond, string name) {
    if (cond) passed++; else { failed++; writeln("FAIL: ", name); }
}
string pad(char c, size_t n) { return replicate([c], n); }

bool hasRule(Finding[] fs, string rule, Sev sev) { return fs.any!(f => f.rule == rule && f.sev == sev); }
Finding[] audit(string text) { int a, b, c; return auditText("f", text, a, b, c); }

int main() {
    // classification
    check(classify("").rule == "HA001" && classify("").sev == Sev.critical, "empty");
    check(classify("!").locked, "bang locked");
    check(classify("!!").locked, "double bang locked");
    check(classify("*").locked, "star locked");
    check(classify("x").locked, "x shadowed");
    check(classify("!$6$abc$def").locked, "locked with hash");
    check(classify("{PLAIN}secret").sev == Sev.critical, "plain");
    check(classify("{SHA}abcdefghijklmnopqrstuvwxyz0=").rule == "HA002", "sha1");
    check(classify("{SSHA}abcdefghijklmnopqrstuvwxyz0123").rule == "HA002", "ssha");
    check(classify("$apr1$abcdefgh$abcdefghijklmnopqrstuv").rule == "HA003", "apr1");
    check(classify("$1$abcdefgh$abcdefghijklmnopqrstuv").rule == "HA003", "md5crypt");
    check(classify("abcdefghijklm").alg == "des", "des 13 chars");
    check(classify("abcdefghijkl").alg == "unknown", "12 chars is unknown");
    check(classify("abcdefghijklmn").alg == "unknown", "14 chars is unknown");
    check(classify("abcdefghijk!m").alg == "unknown", "13 chars with bad char is unknown");
    check(classify("hunter2").rule == "HA001", "plaintext guess");
    check(classify("$y$j9T$salt$hash").strong, "yescrypt strong");
    check(classify("$7$CU..../....$hash").strong, "scrypt strong");
    check(classify("$argon2id$v=19$m=65536,t=3,p=4$salt$hash").strong, "argon2 strong");
    check(classify("$2y$12$" ~ pad('a', 53)).strong, "bcrypt 12 strong");
    check(classify("$2b$10$" ~ pad('a', 53)).strong, "bcrypt 10 strong");
    check(classify("$2a$09$" ~ pad('a', 53)).rule == "HA004", "bcrypt 9 weak");
    check(classify("$2y$04$" ~ pad('a', 53)).sev == Sev.medium, "bcrypt 4 medium");
    check(classify("$2y$xx$" ~ pad('a', 53)).rule == "HA004", "bcrypt unreadable cost");
    check(classify("$6$salt$" ~ pad('a', 86)).rule == "HA004", "sha512 default rounds");
    check(classify("$5$salt$" ~ pad('a', 43)).rule == "HA004", "sha256 default rounds");
    check(classify("$6$rounds=4999$salt$" ~ pad('a', 86)).rule == "HA004", "sha512 4999 rounds");
    check(classify("$6$rounds=10000$salt$" ~ pad('a', 86)).strong, "sha512 10000 rounds");
    check(classify("$6$rounds=500000$salt$" ~ pad('a', 86)).strong, "sha512 500000 rounds");
    check(classify("$99$what$ever").rule == "HA004", "unrecognised $ format");
    check(shaRounds("$6$rounds=777$s$h") == 777, "shaRounds");
    check(shaRounds("$6$s$h") == -1, "shaRounds absent");
    check(shaRounds("$6$rounds=x$s$h") == -1, "shaRounds garbage");

    // file auditing
    int strong, locked, accounts;
    auto fs = auditText("shadow", "root:!:1::::::\nalice:$y$j9T$s$h:1::::::\nbob::1::::::\n# c\n\nbad line\n", strong, locked, accounts);
    check(accounts == 3 && strong == 1 && locked == 1, "counts");
    check(fs.length == 1 && fs[0].rule == "HA001" && fs[0].where == "shadow:3 (bob)", "where has line and user");
    check(audit("a:{SHA}abcdefghijklmnopqrstuvwxyz0=\n").hasRule("HA002", Sev.high), "htpasswd sha1 line");
    check(audit("a:$6$s$" ~ pad('a', 86) ~ ":1::::::\nb:$6$s$" ~ pad('a', 86) ~ ":1::::::\n").hasRule("HA005", Sev.medium), "reuse detected");
    check(!audit("a:$y$j9T$s$h1:1::::::\nb:$y$j9T$s$h2:1::::::\n").hasRule("HA005", Sev.medium), "different hashes are not reuse");
    check(!audit("a:!:1::::::\nb:!:1::::::\n").hasRule("HA005", Sev.medium), "locked accounts are not reuse");
    check(!audit("a::1::::::\nb::1::::::\n").hasRule("HA005", Sev.medium), "empty passwords reported as HA001 not reuse");
    check(audit("a::1::::::\nb::1::::::\n").count!(f => f.rule == "HA001") == 2, "two empty passwords");
    check(audit("a:x:1000:1000::/home/a:/bin/sh\n").length == 0, "passwd style x ignored");
    check(audit("").length == 0, "empty file");
    check(audit("\r\na:!:1::::::\r\n").length == 0, "CRLF tolerated");
    fs = audit("z:{PLAIN}b\ny:{SHA}abcdefghijklmnopqrstuvwxyz0=\nx:$6$s$" ~ pad('a', 86) ~ "\n");
    check(fs[0].sev == Sev.critical && fs[$ - 1].sev == Sev.medium, "sorted by severity");
    // hashes never appear in output
    bool leaked = false;
    foreach (f; audit("u:{PLAIN}topsecretvalue\nv:$1$salt1234$abcdefghijklmnopqrstuv\n")) {
        if (f.message.canFind("topsecretvalue") || f.message.canFind("abcdefghijklmnopqrstuv") || f.where.canFind("topsecretvalue")) leaked = true;
    }
    check(!leaked, "hash text is never in findings");
    check(sevName(Sev.critical) == "critical" && sevName(Sev.info) == "info", "sevName");

    writefln("%d passed, %d failed", passed, failed);
    return failed == 0 ? 0 : 1;
}
