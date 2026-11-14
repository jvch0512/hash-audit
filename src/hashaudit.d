/// hash-audit core: classify password hash strings and audit shadow / htpasswd files.
module hashaudit;

import std.algorithm : canFind, map, sort, startsWith, all, filter;
import std.array : array, join, split, appender;
import std.conv : to, ConvException;
import std.string : indexOf, strip, splitLines, endsWith;
import std.format : format;

enum Sev { critical, high, medium, low, info }

struct Finding {
    Sev sev;
    string rule;
    string where;
    string message;
}

struct Class {
    string alg;      // short name
    Sev sev;         // Sev.info means fine
    string rule;     // "" when fine
    string message;  // "" when fine
    bool locked;
    bool strong;
}

private bool isCryptChars(string s) {
    foreach (c; s) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '/')) return false;
    }
    return true;
}

/// Reads "rounds=N" from a SHA-crypt parameter segment; returns -1 when absent.
int shaRounds(string h) {
    // h starts with "$5$" or "$6$"
    auto rest = h[3 .. $];
    if (rest.startsWith("rounds=")) {
        auto end = rest.indexOf('$');
        if (end < 0) return -1;
        try { return rest[7 .. end].to!int; } catch (ConvException) { return -1; }
    }
    return -1;
}

Class classify(string h) {
    Class c;
    if (h.length == 0) {
        c.alg = "empty"; c.sev = Sev.critical; c.rule = "HA001";
        c.message = "empty password field: the account logs in without a password";
        return c;
    }
    if (h[0] == '!' || h[0] == '*') { c.alg = "locked"; c.locked = true; return c; }
    if (h == "x") { c.alg = "shadowed"; c.locked = true; return c; }
    if (h.startsWith("{PLAIN}")) {
        c.alg = "plaintext"; c.sev = Sev.critical; c.rule = "HA001";
        c.message = "password stored in plaintext ({PLAIN})";
    } else if (h.startsWith("{SSHA}")) {
        c.alg = "ssha"; c.sev = Sev.high; c.rule = "HA002";
        c.message = "salted SHA-1 ({SSHA}) is fast to brute force; use bcrypt, scrypt or argon2";
    } else if (h.startsWith("{SHA}")) {
        c.alg = "sha1"; c.sev = Sev.high; c.rule = "HA002";
        c.message = "unsalted SHA-1 ({SHA}): identical passwords give identical hashes and rainbow tables apply";
    } else if (h.startsWith("$apr1$")) {
        c.alg = "apr1"; c.sev = Sev.high; c.rule = "HA003";
        c.message = "Apache MD5 ($apr1$) is obsolete; use bcrypt ($2y$)";
    } else if (h.startsWith("$1$")) {
        c.alg = "md5crypt"; c.sev = Sev.high; c.rule = "HA003";
        c.message = "MD5 crypt ($1$) is obsolete; use yescrypt, bcrypt or SHA-512 crypt with many rounds";
    } else if (h.startsWith("$y$")) {
        c.alg = "yescrypt"; c.strong = true;
    } else if (h.startsWith("$7$")) {
        c.alg = "scrypt"; c.strong = true;
    } else if (h.startsWith("$argon2")) {
        c.alg = "argon2"; c.strong = true;
    } else if (h.length >= 7 && h[0] == '$' && h[1] == '2' && (h[2] == 'a' || h[2] == 'b' || h[2] == 'x' || h[2] == 'y') && h[3] == '$') {
        c.alg = "bcrypt";
        int cost = -1;
        try { cost = h[4 .. 6].to!int; } catch (ConvException) {}
        if (cost < 0) { c.sev = Sev.medium; c.rule = "HA004"; c.message = "bcrypt hash with an unreadable cost"; }
        else if (cost < 10) {
            c.sev = Sev.medium; c.rule = "HA004";
            c.message = format("bcrypt cost %d is low; use 12 or more", cost);
        } else c.strong = true;
    } else if (h.startsWith("$6$") || h.startsWith("$5$")) {
        c.alg = h[1] == '6' ? "sha512crypt" : "sha256crypt";
        int r = shaRounds(h);
        if (r < 0) {
            c.sev = Sev.medium; c.rule = "HA004";
            c.message = c.alg ~ " with the default 5000 rounds is cheap to attack; set rounds=100000 or more, or use yescrypt";
        } else if (r < 10000) {
            c.sev = Sev.medium; c.rule = "HA004";
            c.message = format("%s with only %d rounds; use 100000 or more", c.alg, r);
        } else c.strong = true;
    } else if (h.length == 13 && isCryptChars(h)) {
        c.alg = "des"; c.sev = Sev.high; c.rule = "HA003";
        c.message = "traditional DES crypt: only the first 8 characters count and it is trivial to crack";
    } else if (h[0] == '$') {
        c.alg = "unrecognised"; c.sev = Sev.medium; c.rule = "HA004";
        c.message = "unrecognised hash format: verify it is a strong algorithm";
    } else {
        c.alg = "unknown"; c.sev = Sev.critical; c.rule = "HA001";
        c.message = "unrecognised value, probably a plaintext password";
    }
    return c;
}

/// Audits file content. `label` names the file in the report.
Finding[] auditText(string label, string text, out int strong, out int locked, out int accounts) {
    Finding[] fs;
    strong = 0; locked = 0; accounts = 0;
    string[][string] byHash;
    int ln = 0;
    foreach (raw; text.splitLines()) {
        ln++;
        auto line = raw.strip();
        if (line.length == 0 || line[0] == '#') continue;
        auto f = line.split(":");
        if (f.length < 2) continue;
        accounts++;
        auto user = f[0];
        auto hash = f[1];
        auto c = classify(hash);
        if (c.locked) { locked++; continue; }
        if (c.strong) strong++;
        if (c.rule.length) {
            fs ~= Finding(c.sev, c.rule, format("%s:%d (%s)", label, ln, user), c.message);
        }
        if (!c.locked && hash.length > 4 && c.rule != "HA001") byHash[hash] ~= user;
    }
    foreach (h, users; byHash) {
        if (users.length > 1)
            fs ~= Finding(Sev.medium, "HA005", label ~ " (" ~ users.join(", ") ~ ")",
                          format("%d accounts share exactly the same hash, so they share a password", users.length));
    }
    fs.sort!((a, b) => a.sev != b.sev ? a.sev < b.sev : a.where < b.where);
    return fs;
}

string sevName(Sev s) {
    final switch (s) {
        case Sev.critical: return "critical";
        case Sev.high: return "high";
        case Sev.medium: return "medium";
        case Sev.low: return "low";
        case Sev.info: return "info";
    }
}
