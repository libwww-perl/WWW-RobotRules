use strict;
use warnings;

use Test::More;
use WWW::RobotRules;

# Test 1: Oversized body -> cache untouched. Seed real rules, then
# feed an oversized body; the seeded rules must survive unchanged
# (no clear_rules, no fresh_until bump).
{
    my $rules = WWW::RobotRules->new('TestBot/1.0');
    $rules->parse(
        'http://foo/robots.txt',
        "User-agent: *\nDisallow: /sensitive\n"
    );
    ok(
        !$rules->allowed('http://foo/sensitive'),
        'sanity: seed rule blocks /sensitive'
    );
    my $fresh_before = $rules->fresh_until('foo:80');

    my $head     = "User-agent: *\nDisallow: /early\n";
    my $pad_line = "# padding line that the parser skips\n";
    my $pad_count
        = int( WWW::RobotRules::DEFAULT_MAX_PARSE_BYTES / length($pad_line) )
        + 10;
    my $tail = "\nUser-agent: *\nDisallow: /late\n";
    my $body = $head . ( $pad_line x $pad_count ) . $tail;

    cmp_ok(
        length($body), '>', WWW::RobotRules::DEFAULT_MAX_PARSE_BYTES,
        'sanity: test body is larger than the cap'
    );

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };

    $rules->parse( 'http://foo/robots.txt', $body );

    ok(
        !$rules->allowed('http://foo/sensitive'),
        'seeded rule SURVIVES an oversized parse (cache untouched)'
    );
    is(
        $rules->fresh_until('foo:80'), $fresh_before,
        'fresh_until is not bumped on an oversized parse'
    );
    my @trunc = grep { /input exceeds .* bytes; cache untouched/ } @warnings;
    is( scalar @trunc, 1, 'exactly one truncation warn fired' );

    # Positive control: lift the cap so the body fits, and /late
    # must now be disallowed (proves the body's contents are real).
    {
        my $rules2 = WWW::RobotRules->new(
            'TestBot/1.0',
            max_parse_bytes => length($body) + 1
        );
        $rules2->parse( 'http://foo/robots.txt', $body );

        ok(
            !$rules2->allowed('http://foo/late'),
            'control: with the cap lifted, /late is disallowed'
        );
    }
}

# Test 2: UTF-8-flagged input is measured in bytes, not characters.
# A body whose byte length is over the cap triggers the bail, so
# the seeded rule survives.
{
    my $line    = "# \x{263A}\n";     # 4 chars / 6 UTF-8 bytes
    my $padding = $line x 100_000;    # 400,000 chars / 600,000 bytes
    utf8::upgrade($padding);
    my $tail = "User-agent: *\nDisallow: /late\n";
    my $body = $padding . $tail;

    cmp_ok(
        length($body), '<', WWW::RobotRules::DEFAULT_MAX_PARSE_BYTES,
        'sanity: character length is under the cap'
    );
    {
        use bytes;
        cmp_ok(
            length($body), '>', WWW::RobotRules::DEFAULT_MAX_PARSE_BYTES,
            'sanity: byte length is over the cap'
        );
    }

    my $rules = WWW::RobotRules->new('TestBot/1.0');
    $rules->parse(
        'http://foo/robots.txt',
        "User-agent: *\nDisallow: /seed\n"
    );
    ok(
        !$rules->allowed('http://foo/seed'),
        'sanity: seed rule is in effect'
    );

    $rules->parse( 'http://foo/robots.txt', $body );

    ok(
        !$rules->allowed('http://foo/seed'),
        'seeded rule survives: cap is measured in bytes, so oversized UTF-8 body bails'
    );
}

# Test 3: Exactly MAX_PARSE_BYTES is NOT over the cap.
{
    my $tail = "User-agent: *\nDisallow: /tail\n";
    my $padding_len
        = WWW::RobotRules::DEFAULT_MAX_PARSE_BYTES - length($tail) - 2;
    my $body = "#" . ( "a" x $padding_len ) . "\n" . $tail;

    is(
        length($body), WWW::RobotRules::DEFAULT_MAX_PARSE_BYTES,
        'sanity: body is exactly MAX_PARSE_BYTES bytes'
    );

    my $rules = WWW::RobotRules->new('TestBot/1.0');
    $rules->parse( 'http://foo/robots.txt', $body );

    ok(
        !$rules->allowed('http://foo/tail'),
        '/tail rule at exactly MAX_PARSE_BYTES is applied (not truncated)'
    );
}

# Test 5: Empty input does not regress.
{
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };

    my $rules = WWW::RobotRules->new('TestBot/1.0');
    $rules->parse( 'http://foo/robots.txt', "" );

    is( scalar @warnings, 0, 'no warnings on empty input' );
    ok(
        $rules->allowed('http://foo/anything'),
        'empty robots.txt means everything is allowed'
    );
}

# Test 6: Control characters in malformed lines are escaped, covering
# C0 (NUL, BEL), ESC, and the C1 single-byte CSI/OSC.
{
    my $bad = "garbage\x07\x1b[31m\x9b31m\x9d0;title\x00line\n";

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    local $^W = 1;

    my $rules = WWW::RobotRules->new('TestBot/1.0');
    $rules->parse( 'http://foo/robots.txt', $bad );

    cmp_ok( scalar @warnings, '>=', 1, 'malformed line produced a warning' );
    my $w = join "", @warnings;

    unlike( $w, qr/\x07/, 'raw BEL byte is not present in warn output' );
    unlike( $w, qr/\x1b/, 'raw ESC byte is not present in warn output' );
    unlike(
        $w, qr/\x9b/,
        'raw CSI (0x9B) byte is not present in warn output'
    );
    unlike(
        $w, qr/\x9d/,
        'raw OSC (0x9D) byte is not present in warn output'
    );
    unlike( $w, qr/\x00/, 'raw NUL byte is not present in warn output' );

    like( $w, qr/\\x07/, 'BEL is escaped as \\x07' );
    like( $w, qr/\\x1b/, 'ESC is escaped as \\x1b' );
    like( $w, qr/\\x9b/, 'CSI is escaped as \\x9b' );
    like( $w, qr/\\x9d/, 'OSC is escaped as \\x9d' );
    like( $w, qr/\\x00/, 'NUL is escaped as \\x00' );
}

# Test 7: A single oversized malformed line does not dump in full --
# the per-line snippet is truncated.
{
    my $line = "BAD" . ( "x" x 5000 ) . "\n";

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    local $^W = 1;

    my $rules = WWW::RobotRules->new('TestBot/1.0');
    $rules->parse( 'http://foo/robots.txt', $line );

    my @malformed = grep { /Malformed record/ } @warnings;
    is( scalar @malformed, 1, 'one malformed-line warning' );
    cmp_ok(
        length( $malformed[0] ), '<', 1000,
        'warn payload is bounded per malformed line (not the full 5000-char line)'
    );
    like(
        $malformed[0], qr/\.\.\./,
        'truncated snippet ends with "..." marker'
    );
}

# Test 9: max_parse_warnings is overridable per-instance.
{
    my $line       = "garbage_line_no_colon\n";
    my $line_count = 50;
    my $cap        = 5;
    my $body       = $line x $line_count;

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    local $^W = 1;

    my $rules = WWW::RobotRules->new(
        'TestBot/1.0',
        max_parse_warnings => $cap
    );
    $rules->parse( 'http://foo/robots.txt', $body );

    my $malformed = grep { /Malformed record/ } @warnings;
    is(
        $malformed, $cap,
        'malformed warnings honour the locally-lowered cap'
    );

    my @suppressed
        = grep { /(\d+) further parse warnings suppressed/ } @warnings;
    is( scalar @suppressed, 1, 'aggregate suppressed warning emitted' );
    $suppressed[0] =~ /(\d+) further/;
    is(
        $1, $line_count - $cap,
        'aggregate reports the correct suppressed count (computed, not hard-coded)'
    );
}

# Test 13: max_parse_warnings => 0 emits no individual warnings;
# every offending line collapses into the single suppression trailer.
{
    my $body = ("garbage_line_no_colon\n") x 20;

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    local $^W = 1;

    my $rules = WWW::RobotRules->new(
        'TestBot/1.0',
        max_parse_warnings => 0
    );
    $rules->parse( 'http://foo/robots.txt', $body );

    my @malformed  = grep { /Malformed record/ } @warnings;
    my @suppressed = grep { /further parse warnings suppressed/ } @warnings;
    is( scalar @malformed, 0, 'no individual malformed warns when cap is 0' );
    is( scalar @suppressed, 1, 'single aggregate trailer fires' );
    $suppressed[0] =~ /(\d+) further/;
    is( $1, 20, 'aggregate reports all 20 lines as suppressed' );
}

# Test 15: A malformed line whose 200-byte snippet cut lands mid
# UTF-8 sequence must not leak orphan bytes into the log.
{
    # 70 copies of U+263A (3 UTF-8 bytes each) -> 210 bytes; the
    # 200-byte snippet cut lands mid 3-byte sequence.
    my $line = ( "\x{263A}" x 70 ) . "xx";
    my $body = $line . "\n";

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    local $^W = 1;

    my $rules = WWW::RobotRules->new('TestBot/1.0');
    $rules->parse( 'http://foo/robots.txt', $body );

    my @malformed = grep { /Malformed record/ } @warnings;
    is(
        scalar @malformed, 1,
        'malformed-record warn fired (snippet path exercised)'
    );

    my $w = join "", @warnings;
    ok(
        utf8::decode( my $copy = $w ),
        'warn output is valid UTF-8 even when the 200-byte snippet cut lands mid-multibyte'
    );
    unlike(
        $w, qr/[\x80-\xff]/,
        'no raw high bytes leaked through the sanitizer'
    );
}

# Exhaustive lock-down of the sanitizer's contract for every byte
# in 0x00..0xFF. Locks behavior independent of implementation so
# the helper can be swapped (e.g. for a CPAN module) without
# silently changing what reaches log sinks. Contract is bytes only;
# decoded character strings are the caller's responsibility.
{
    my @escaped_ranges = (
        [ 0x00, 0x08 ],    # C0 controls (NUL..BS), TAB excluded
        [ 0x0A, 0x1F ],    # LF..US (incl. VT, FF, CR, ESC)
        [ 0x7F, 0x7F ],    # DEL
        [ 0x80, 0xFF ],    # C1 controls + all high bytes; high bytes
                           # are escaped so orphan UTF-8 continuation
                           # bytes (from mid-multibyte snippet truncation)
                           # cannot corrupt a UTF-8 log file
    );
    my %escape = map {
        my ( $lo, $hi ) = @$_;
        map { $_ => 1 } $lo .. $hi;
    } @escaped_ranges;

    subtest 'sanitizer locks down 0x00..0xFF on codepoint inputs' => sub {
        plan( tests => 256 );
        for my $byte ( 0 .. 255 ) {
            my $input = chr($byte);
            my $expected
                = $escape{$byte}
                ? sprintf( '\x%02x', $byte )
                : $input;
            is(
                WWW::RobotRules::_sanitize_for_log($input),
                $expected,
                sprintf(
                    'codepoint U+%04X: %s',
                    $byte, $escape{$byte} ? 'escaped' : 'passes through'
                )
            );
        }
    };

    subtest 'sanitizer locks down 0x00..0xFF on raw-byte inputs' => sub {
        plan( tests => 256 );
        for my $byte ( 0 .. 255 ) {
            my $input = pack( 'C', $byte );
            my $expected
                = $escape{$byte}
                ? sprintf( '\x%02x', $byte )
                : $input;
            is(
                WWW::RobotRules::_sanitize_for_log($input),
                $expected,
                sprintf(
                    'byte 0x%02x: %s',
                    $byte, $escape{$byte} ? 'escaped' : 'passes through'
                )
            );
        }
    };
}

# Test 17: Latin-1 / Windows-1252 byte bodies must NOT be re-encoded
# as if they were Unicode codepoints. A "Disallow: /\xe9" byte body
# from a server that serves Latin-1 robots.txt must block "/%E9"
# (the path the client will request) and NOT block "/%C3%A9" (the
# UTF-8 re-encoding that a buggy utf8::encode of the byte string
# would produce).
{
    my $body = "User-agent: *\nDisallow: /\xe9\n";

    # Make sure the SV is NOT utf8-flagged -- this simulates octets
    # straight from an HTTP socket.
    utf8::downgrade($body);
    ok( !utf8::is_utf8($body), 'sanity: body is not utf8-flagged' );

    my $rules = WWW::RobotRules->new('TestBot/1.0');
    $rules->parse( 'http://foo/robots.txt', $body );

    ok(
        !$rules->allowed('http://foo/%E9'),
        'Latin-1 byte body blocks /%E9 (the byte semantics are preserved)'
    );
    ok(
        $rules->allowed('http://foo/%C3%A9'),
        'Latin-1 byte body does NOT block /%C3%A9 (no spurious re-encoding)'
    );
}

# Test 18: A utf8-flagged body with the same logical character still
# gets blocked under the UTF-8-encoded URL.
{
    my $body = "User-agent: *\nDisallow: /\x{00e9}\n";
    utf8::upgrade($body);
    ok( utf8::is_utf8($body), 'sanity: body is utf8-flagged' );

    my $rules = WWW::RobotRules->new('TestBot/1.0');
    $rules->parse( 'http://foo/robots.txt', $body );

    # When the SV is utf8-flagged, the encode step turns U+00E9 into
    # the two-byte UTF-8 sequence \xC3\xA9 before the rule is stored,
    # so /%C3%A9 is what gets blocked.
    ok(
        !$rules->allowed('http://foo/%C3%A9'),
        'utf8-flagged body blocks the UTF-8-encoded path'
    );
}

# Test 19: "Disallow:" without a preceding "User-agent:" must be
# bounded by MAX_PARSE_WARNINGS, sharing the malformed-record
# counter so it cannot be used as a log-flood vector.
{
    # Stay under MAX_PARSE_BYTES so the parser actually runs.
    my $line_count = int( ( WWW::RobotRules::DEFAULT_MAX_PARSE_BYTES - 100 ) /
            length("Disallow: /foo\n") );
    my $body = "Disallow: /foo\n" x $line_count;

    cmp_ok(
        length($body), '<=', WWW::RobotRules::DEFAULT_MAX_PARSE_BYTES,
        'sanity: body fits under the cap'
    );
    cmp_ok(
        $line_count, '>', WWW::RobotRules::DEFAULT_MAX_PARSE_WARNINGS,
        'sanity: line count exceeds the warn cap'
    );

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    local $^W = 1;

    my $rules = WWW::RobotRules->new('TestBot/1.0');
    $rules->parse( 'http://foo/robots.txt', $body );

    my @dis_no_ua
        = grep { /Disallow without preceding User-agent/ } @warnings;
    is(
        scalar @dis_no_ua, WWW::RobotRules::DEFAULT_MAX_PARSE_WARNINGS,
        'Disallow-without-User-agent warns hit MAX_PARSE_WARNINGS exactly'
    );

    my @suppressed = grep { /further parse warnings suppressed/ } @warnings;
    is(
        scalar @suppressed, 1,
        'aggregate suppressed-records trailer fires when Disallow-no-UA floods'
    );
}

done_testing();
