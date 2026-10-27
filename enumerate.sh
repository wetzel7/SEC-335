#!/bin/bash
# SEC-335 Week 9 - Linux Host Enumeration
#
# Usage:
#   ./enumerate.sh              run all 32 commands as the standard lab user
#   ./enumerate.sh --sudo-only  run only the 4 commands that need root (#9, 26, 28, 32);
#                               run this as the SUDO user so those files get real output
# Output: one file per command in /tmp/enumeration/ (override with OUT=/path ./enumerate.sh)

OUT="${OUT:-/tmp/enumeration}"
mkdir -p "$OUT"

# Which items to run: all, or only the root-required ones
ONLY=""
[ "$1" = "--sudo-only" ] && ONLY="9 26 28 32"
want() { [ -z "$ONLY" ] || [[ " $ONLY " == *" $1 "* ]]; }
have() { command -v "$1" >/dev/null 2>&1; }

# 1. Current user, groups, and privileges
want 1 && { whoami; id; groups; } > "$OUT/01_user_groups_privs.txt" 2>&1

# 2. Running processes
want 2 && ps aux > "$OUT/02_processes.txt" 2>&1

# 3. Open network sockets and connections
want 3 && ss -tulpn > "$OUT/03_sockets.txt" 2>&1

# 4. Running services
want 4 && systemctl list-units --type=service --state=running > "$OUT/04_services.txt" 2>&1

# 5. All local user accounts
want 5 && cat /etc/passwd > "$OUT/05_users.txt" 2>&1

# 6. All local groups
want 6 && cat /etc/group > "$OUT/06_groups.txt" 2>&1

# 7. Users in the sudo (administrators) group
want 7 && getent group sudo > "$OUT/07_sudo_group.txt" 2>&1

# 8. Network configuration (IP, gateway, DNS)
want 8 && { ip a; ip route; cat /etc/resolv.conf; } > "$OUT/08_network_config.txt" 2>&1

# 9. Firewall policies (needs root)
want 9 && sudo iptables -L -n -v > "$OUT/09_firewall.txt" 2>&1

# 10. ARP table
want 10 && ip neigh > "$OUT/10_arp.txt" 2>&1

# 11. SMB sessions (smbstatus if installed, otherwise look for connections on port 445)
want 11 && {
  if have smbstatus; then smbstatus; else
    echo "smbstatus not installed - substitute: ss on port 445"
    ss -tn | grep ':445' || echo "no connections on port 445"
  fi
} > "$OUT/11_smb_sessions.txt" 2>&1

# 12. System information
want 12 && { uname -a; cat /etc/os-release; hostnamectl; } > "$OUT/12_system_info.txt" 2>&1

# 13. Sudo privileges for the current account, including NOPASSWD entries
want 13 && sudo -l > "$OUT/13_sudo_privs.txt" 2>&1

# 14. Logged-in users, active sessions, and login history
want 14 && { who -a; w; last -a; lastlog; } > "$OUT/14_logins.txt" 2>&1

# 15. Shell command history left behind by local users
want 15 && {
  ls -la ~ /home/*/ 2>&1 | grep -i hist
  echo "HISTFILE=$HISTFILE"
  cat /home/*/.bash_history ~/.bash_history 2>&1
  echo "(end of history search)"
} > "$OUT/15_shell_history.txt" 2>&1

# 16. Environment variables of the current shell and running processes
want 16 && { env; for p in /proc/[0-9]*/environ; do tr '\0' '\n' < "$p"; done; } > "$OUT/16_environment.txt" 2>&1

# 17. SUID and SGID binaries on the filesystem (errors hidden so only results are saved)
want 17 && find / -xdev \( -perm -4000 -o -perm -2000 \) -type f > "$OUT/17_suid_sgid.txt" 2>/dev/null

# 18. File capabilities assigned to installed binaries (errors hidden)
want 18 && getcap -r / > "$OUT/18_capabilities.txt" 2>/dev/null

# 19. Scheduled tasks: cron jobs and systemd timers
want 19 && { crontab -l; cat /etc/crontab; ls -la /etc/cron*; systemctl list-timers --all; } > "$OUT/19_scheduled_tasks.txt" 2>&1

# 20. Installed security tools and EDR agents, and whether they are running
want 20 && {
  ps aux | grep -iE 'falcon|osquery|auditd|wazuh|clam|ossec|fail2ban|aide' | grep -v grep || echo "no security tool processes found"
  systemctl status auditd
} > "$OUT/20_security_tools.txt" 2>&1

# 21. Installed software package inventory
want 21 && dpkg -l > "$OUT/21_packages.txt" 2>&1

# 22. Kernel version and build information
want 22 && { uname -r; cat /proc/version; } > "$OUT/22_kernel.txt" 2>&1

# 23. Mounted filesystems and free disk space
want 23 && { df -h; mount; findmnt; } > "$OUT/23_mounts_disk.txt" 2>&1

# 24. SSH keys, authorized_keys files, and SSH client/server configuration
want 24 && { ls -la ~/.ssh; cat ~/.ssh/authorized_keys; cat /etc/ssh/sshd_config /etc/ssh/ssh_config; } > "$OUT/24_ssh.txt" 2>&1

# 25. Password hash store - permissions and readability
want 25 && { ls -l /etc/shadow; test -r /etc/shadow && echo readable || echo not readable; } > "$OUT/25_shadow_perms.txt" 2>&1

# 26. Authentication events and failed login attempts in system logs (needs root)
want 26 && { sudo grep -iE 'failed|invalid user|authentication failure' /var/log/auth.log; sudo lastb; } > "$OUT/26_auth_logs.txt" 2>&1

# 27. Running containers and container runtime socket permissions
want 27 && {
  if have docker; then docker ps -a; else echo "docker not installed"; fi
  if have podman; then podman ps -a; else echo "podman not installed"; fi
  ls -l /var/run/docker.sock 2>&1
} > "$OUT/27_containers.txt" 2>&1

# 28. SELinux or AppArmor status (aa-status needs root)
want 28 && {
  if have getenforce; then getenforce; else echo "SELinux (getenforce) not installed"; fi
  if have sestatus; then sestatus; else echo "sestatus not installed"; fi
  echo "AppArmor enabled flag: $(cat /sys/module/apparmor/parameters/enabled 2>&1)"
  sudo aa-status
} > "$OUT/28_mac_status.txt" 2>&1

# 29. Exported NFS / network file shares
want 29 && {
  cat /etc/exports 2>&1
  if have showmount; then showmount -e localhost; else echo "showmount not installed"; fi
} > "$OUT/29_nfs_exports.txt" 2>&1

# 30. Hostname, FQDN, and configured domain membership
want 30 && {
  hostname; hostname -f; dnsdomainname
  grep -E '^(search|domain)' /etc/resolv.conf
  if have realm; then realm list; else echo "realm not installed (host not domain-joined via realmd/sssd)"; fi
} > "$OUT/30_hostname_domain.txt" 2>&1

# 31. World-writable files and directories in system locations (errors hidden)
want 31 && find /etc /usr /bin /sbin /opt /var -xdev -perm -0002 \( -type f -o -type d \) > "$OUT/31_world_writable.txt" 2>/dev/null

# 32. Files opened by running processes, including deleted-but-still-open files (needs root)
want 32 && {
  sudo lsof -nP +L1
  sudo lsof -nP
  echo "--- deleted-but-open files visible to this user via /proc ---"
  ls -l /proc/[0-9]*/fd 2>/dev/null | grep deleted
} > "$OUT/32_open_files.txt" 2>&1

echo "Done: $(ls -1 "$OUT"/*.txt | wc -l) output files in $OUT"
find "$OUT" -name '*.txt' -empty -print | sed 's/^/EMPTY FILE: /'