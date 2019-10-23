# Copyright (c) 2019 Kyle Patrick Godbold <kylegodbold@gmail.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use v6;

unit module OpenBSD::Pledge;

BEGIN {
    if $*DISTRO.name ne 'openbsd' {
        die "OpenBSD::Pledge: {$*DISTRO.name} is not supported!";
    }
}

use NativeCall;

sub openbsd_pledge(Str:D, Str:D) returns int32
    is native('c') is symbol('pledge') {*}

sub openbsd_unveil(Str:D, Str:D) returns int32
    is native('c') is symbol('unveil') {*}

sub pledge(Str:D $promises --> Bool:D) is export {
    my @promise_types =
    <ps bpf tape prot audio mcast flock wpath vminfo unveil
     id dns proc inet video fattr stdio cpath sendfd tmppath
     pf tty exec unix getpw chown rpath dpath recvfd settime
     prot_exec>;

    my @requested_promises = $promises.split(' ');

    unless @requested_promises.all ~~ @promise_types.any {
        for @requested_promises -> $promise {
            unless $promise.all ~~ @promise_types.any {
                warn "OpenBSD::Pledge: Invalid promise: {$promise}";
            }
        }
    }

    return True.so if openbsd_pledge($promises, '') == 0;

    warn "OpenBSD::Pledge: Failed! pledge('{$promises}')";

    return False.so;
}

sub unveil(Str:D $path --> Bool:D) is export {
    return True.so if openbsd_unveil($path, '') == 0;
    warn "OpenBSD::Pledge: Failed! unveil('{$path}')";
    return False.so;
}
