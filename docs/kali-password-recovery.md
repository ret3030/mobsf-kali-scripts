# Kali password recovery (own machine, physical access)

Personal recovery note for when I have lost the password to my own Kali box and need
to reset it or add a new administrative account. Requires physical access to the machine.
It resets the login password; it does not defeat full-disk encryption (see the LUKS note).

Two methods:
- **Method A, GRUB init shell:** fastest, works when the bootloader is editable.
- **Method B, live USB chroot:** use when GRUB is password-protected or Method A fails.

---

## Method A: GRUB init shell

1. Reboot. At the GRUB menu, highlight the Kali entry and press `e` to edit it.
2. Find the line starting with `linux` (it ends with something like `ro quiet splash`).
   Change `ro` to `rw` and append `init=/bin/bash` at the end of that line:

   ```
   linux   /boot/vmlinuz-... root=UUID=... rw quiet init=/bin/bash
   ```

3. Press `Ctrl-X` (or `F10`) to boot. You land in a root shell with no password prompt.
4. Make sure the root filesystem is writable (harmless if already rw):

   ```bash
   mount -o remount,rw /
   ```

5. Reset the password for the account you want:

   ```bash
   passwd root          # reset root
   passwd myuser        # or reset a normal user
   ```

6. (Optional) create a new administrative user:

   ```bash
   useradd -m -s /bin/bash newadmin
   passwd newadmin
   usermod -aG sudo newadmin      # grant sudo (Debian/Kali: the 'sudo' group)
   ```

7. Reboot cleanly:

   ```bash
   exec /sbin/init          # hand control back to systemd
   # if that hangs, force it:
   sync; reboot -f
   ```

---

## Method B: live USB + chroot

Use this when the GRUB entry cannot be edited (bootloader password) or the init trick fails.

1. Boot from a Kali live USB (Live mode, not install).
2. Identify the root partition:

   ```bash
   lsblk -f
   sudo fdisk -l
   ```

3. **If the disk is LUKS-encrypted**, unlock it first (this needs the LUKS passphrase,
   which is not the login password, see the note below):

   ```bash
   sudo cryptsetup luksOpen /dev/sdaX cryptroot
   # the root device is then /dev/mapper/cryptroot
   ```

4. Mount the root filesystem and bind the kernel pseudo-filesystems so chroot works:

   ```bash
   sudo mount /dev/sdaX /mnt          # or /dev/mapper/cryptroot
   sudo mount --bind /dev  /mnt/dev
   sudo mount --bind /proc /mnt/proc
   sudo mount --bind /sys  /mnt/sys
   # if /boot is a separate partition and you need it:
   # sudo mount /dev/sdaY /mnt/boot
   ```

5. Enter the installed system:

   ```bash
   sudo chroot /mnt /bin/bash
   ```

6. Reset the password or add a user, exactly as in Method A steps 5 and 6:

   ```bash
   passwd root
   # or
   useradd -m -s /bin/bash newadmin && passwd newadmin && usermod -aG sudo newadmin
   ```

7. Leave and unmount cleanly, then reboot:

   ```bash
   exit
   sudo umount -R /mnt
   sudo reboot
   ```

---

## Notes and caveats

- **Full-disk encryption (LUKS).** These steps reset the *login* password, not the disk
  encryption passphrase. You still need the LUKS passphrase to unlock the disk at boot or
  in Method B. If that passphrase is also lost, the data is not recoverable by design.
- **GRUB password.** If the bootloader itself is password-protected, Method A is blocked;
  use Method B.
- **Secure Boot.** Booting a live USB may require toggling Secure Boot in firmware.
- **After recovery**, set a password you will keep, and if you created a throwaway admin
  user to regain access, remove it afterward: `sudo deluser --remove-home newadmin`.
- This is for a machine you own and can physically access. The same ease of reset is why
  disk encryption matters: without LUKS, anyone with physical access can do all of the above.
