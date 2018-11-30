#!/bin/sh

TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
SRCDIR=${SRCDIR:-$TOPDIR/src}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

RITOD=${RITOD:-$SRCDIR/ritod}
RITOCLI=${RITOCLI:-$SRCDIR/rito-cli}
RITOTX=${RITOTX:-$SRCDIR/rito-tx}
RITOQT=${RITOQT:-$SRCDIR/qt/rito-qt}

[ ! -x $RITOD ] && echo "$RITOD not found or not executable." && exit 1

# The autodetected version git tag can screw up manpage output a little bit
RITOVER=($($RITOCLI --version | head -n1 | awk -F'[ -]' '{ print $6, $7 }'))

# Create a footer file with copyright content.
# This gets autodetected fine for ritod if --version-string is not set,
# but has different outcomes for rito-qt and rito-cli.
echo "[COPYRIGHT]" > footer.h2m
$RITOD --version | sed -n '1!p' >> footer.h2m

for cmd in $RITOD $RITOCLI $RITOTX $RITOQT; do
  cmdname="${cmd##*/}"
  help2man -N --version-string=${RITOVER[0]} --include=footer.h2m -o ${MANDIR}/${cmdname}.1 ${cmd}
  sed -i "s/\\\-${RITOVER[1]}//g" ${MANDIR}/${cmdname}.1
done

rm -f footer.h2m
