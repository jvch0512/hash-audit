module app;

import hashaudit;
import std.stdio;
import std.file : readText, exists, isFile;
import std.algorithm : sort, canFind;
import std.string : toUpper, leftJustify;
import std.format : format;
import core.stdc.stdlib : exit;
import std.path : baseName;

void usage() {
    stderr.writeln("usage: hash-audit FILE... [--tsv] [--fail-on medium|high|critical]");
    stderr.writeln("Exit: 0 ok, 1 findings at or above --fail-on, 2 bad input.");
    exit(2);
}

int main(string[] args) {
    string[] files;
    bool tsv = false;
    string failOn = "";
    for (size_t i = 1; i < args.length; i++) {
        auto a = args[i];
        if (a == "--tsv") tsv = true;
        else if (a == "--fail-on") {
            i++;
            if (i >= args.length || !["medium", "high", "critical"].canFind(args[i])) usage();
            failOn = args[i];
        } else if (a.length > 0 && a[0] == '-') usage();
        else files ~= a;
    }
    if (files.length == 0) usage();

    Finding[] all;
    int strongTotal = 0, lockedTotal = 0, accountsTotal = 0;
    foreach (f; files) {
        if (!exists(f) || !isFile(f)) { stderr.writeln("error: cannot read ", f); return 2; }
        string text;
        try text = readText(f); catch (Exception e) { stderr.writeln("error: cannot read ", f); return 2; }
        int s, l, n;
        all ~= auditText(f.baseName, text, s, l, n);
        strongTotal += s; lockedTotal += l; accountsTotal += n;
    }
    all.sort!((a, b) => a.sev != b.sev ? a.sev < b.sev : a.where < b.where);
    all ~= Finding(Sev.info, "HA006", "all files", format("%d accounts: %d strong hashes, %d locked", accountsTotal, strongTotal, lockedTotal));

    int nfind = cast(int) all.length - 1;
    if (tsv) writefln("# %d files, %d accounts, %d findings", files.length, accountsTotal, nfind);
    else writefln("%d files, %d accounts, %d findings", files.length, accountsTotal, nfind);
    foreach (f; all) {
        if (tsv) writefln("%s\t%s\t%s\t%s", sevName(f.sev), f.rule, f.where, f.message);
        else writefln("%s %s %s\n         %s", sevName(f.sev).toUpper.leftJustify(8), f.rule, f.where, f.message);
    }
    int code = 0;
    foreach (f; all) {
        if (failOn == "critical" && f.sev <= Sev.critical && f.rule != "HA006") code = 1;
        if (failOn == "high" && f.sev <= Sev.high && f.rule != "HA006") code = 1;
        if (failOn == "medium" && f.sev <= Sev.medium && f.rule != "HA006") code = 1;
    }
    return code;
}
