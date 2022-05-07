#!/bin/sh

tmp=$(mktemp -d)
chown root:ctf "$tmp" || exit
chmod 750 "$tmp" || exit

cp -R /lib* "$tmp" && \
mkdir "$tmp/usr" && \
cp -R /usr/lib* "$tmp/usr" && \
mkdir "$tmp/dev" && \
mknod "$tmp/dev/null" c 1 3 && \
mknod "$tmp/dev/zero" c 1 5 && \
mknod "$tmp/dev/random" c 1 8 && \
mknod "$tmp/dev/urandom" c 1 9 && \
chmod  666 "$tmp"/dev/* && \
mkdir "$tmp/bin" && \
cp /bin/echo /bin/sh /bin/ls /bin/cat /usr/bin/timeout $(which qemu-system-x86_64) "$tmp/bin" || exit
mkdir -p "$tmp/usr/share/seabios/"
cp -r /usr/share/seabios/* "$tmp/usr/share/seabios/" || exit

# copy your binary file
cp -R /chal/* "$tmp" || exit
chmod +x "$tmp/run.sh"

# repack the flag
mkdir "$tmp/tmp" && \
cp "$tmp/rootfs.cpio" "$tmp/tmp/" || exit
cd "$tmp/tmp/" && cpio -idv < "$tmp/tmp/rootfs.cpio" && \
rm "$tmp/tmp/rootfs.cpio" || exit
echo $FLAG > "$tmp/tmp/flag" && \
find . | cpio -o --format=newc > "$tmp/rootfs.cpio" || exit
cd "$tmp" && rm -rf "$tmp/tmp/" || exit

# replace /bin/sh with your binary file
chroot --userspec=1000:1000 "$tmp" /bin/timeout -k 5 300 /run.sh
rm -rf "$tmp" || exit