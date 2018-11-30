
Debian
====================
This directory contains files used to package ritod/rito-qt
for Debian-based Linux systems. If you compile ritod/rito-qt yourself, there are some useful files here.

## rito: URI support ##


rito-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install rito-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your rito-qt binary to `/usr/bin`
and the `../../share/pixmaps/rito128.png` to `/usr/share/pixmaps`

rito-qt.protocol (KDE)

