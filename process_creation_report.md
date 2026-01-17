# Linux Process Creation Data Report

**Generated:** 2026-01-17 17:01:33

**Total Detection Rules:** 117

## Summary Statistics

- **Total Events:** 5,343
- **Match Events:** 2,314
- **Evasion Events:** 3,029
- **Detection Rules with Events:** 22
- **Detection Rules without Events:** 95

## Event Type Distribution

- **Microsoft-Windows-Sysmon_1:** 5,343 events

## Top 20 Detection Rules by Event Count

| Rank | Rule Name | Sigma Rule Title | Total | Match | Evasion |
|------|-----------|------------------|-------|-------|----------|
| 1 | `flock_shell_execution` | Shell Execution via Flock - Linux | 390 | 0 | 390 |
| 2 | `bpftrace_unsafe_option_usage` | BPFtrace Unsafe Option Usage | 360 | 115 | 245 |
| 3 | `find_shell_execution` | Shell Execution via Find - Linux | 352 | 153 | 199 |
| 4 | `crontab_removal` | Remove Scheduled Cron Task/Job | 334 | 134 | 200 |
| 5 | `omigod_scx_runasprovider_executeshellcommand` | OMIGOD SCX RunAsProvider ExecuteShellCommand | 311 | 105 | 206 |
| 6 | `grep_os_arch_discovery` | OS Architecture Discovery Via Grep | 269 | 59 | 210 |
| 7 | `awk_shell_spawn` | Suspicious Invocation of Shell via AWK - Linux | 264 | 84 | 180 |
| 8 | `local_groups` | Local Groups Discovery - Linux | 261 | 115 | 146 |
| 9 | `base64_execution` | Linux Base64 Encoded Pipe to Shell | 260 | 53 | 207 |
| 10 | `disable_ufw` | Ufw Force Stop Using Ufw-Init | 246 | 233 | 13 |
| 11 | `base64_shebang_cli` | Linux Base64 Encoded Shebang In CLI | 232 | 232 | 0 |
| 12 | `crontab_enumeration` | Crontab Enumeration | 230 | 30 | 200 |
| 13 | `local_account` | Local System Accounts Discovery - Linux | 218 | 86 | 132 |
| 14 | `av_kaspersky_av_disabled` | Kaspersky Endpoint Security Stopped Via CommandLine - Linux | 215 | 144 | 71 |
| 15 | `clear_logs` | Clear Linux Logs | 210 | 195 | 15 |
| 16 | `dd_file_overwrite` | DD File Overwrite | 206 | 106 | 100 |
| 17 | `crypto_mining` | Linux Crypto Mining Indicators | 186 | 30 | 156 |
| 18 | `file_and_directory_discovery` | File and Directory Discovery - Linux | 180 | 115 | 65 |
| 19 | `apt_shell_execution` | Shell Invocation via Apt - Linux | 165 | 165 | 0 |
| 20 | `base64_decode` | Decode Base64 Encoded Text | 158 | 66 | 92 |

## Detection Rules with Evasion Analysis

**Rules with evasion_possible=yes:** 0

## Detection Rules with No Events

**Total:** 95 rules

<details>
<summary>Click to expand list</summary>

- `at_command`
- `auditctl_clear_rules`
- `bash_interactive_shell`
- `bpf_kprob_tracing_enabled`
- `chattr_immutable_removal`
- `chroot_execution`
- `clear_syslog`
- `clipboard_collection`
- `cp_passwd_or_shadow_tmp`
- `curl_usage`
- `curl_wget_exec_tmp`
- `dd_process_injection`
- `doas_execution`
- `env_shell_invocation`
- `esxcli_network_discovery`
- `esxcli_permission_change_admin`
- `esxcli_storage_discovery`
- `esxcli_syslog_config_change`
- `esxcli_system_discovery`
- `esxcli_user_account_creation`
- `esxcli_vm_discovery`
- `esxcli_vm_kill`
- `esxcli_vsan_discovery`
- `file_deletion`
- `gcc_shell_execution`
- `git_shell_execution`
- `groupdel`
- `install_root_certificate`
- `install_suspicioua_packages`
- `install_suspicious_packages`
- `iptables_flush_ufw`
- `malware_gobrat_grep_payload_discovery`
- `mkfifo_named_pipe_creation`
- `mkfifo_named_pipe_creation_susp_location`
- `mount_hidepid`
- `netcat_reverse_shell`
- `nice_shell_execution`
- `nohup`
- `nohup_susp_execution`
- `omigod_scx_runasprovider_executescript`
- `perl_reverse_shell`
- `php_reverse_shell`
- `pnscan_binary_cli_pattern`
- `proxy_connection`
- `pua_trufflehog`
- `python_http_server_execution`
- `python_pty_spawn`
- `python_reverse_shell`
- `python_shell_os_system`
- `remote_access_tools_teamviewer_incoming_connection`
- `remote_system_discovery`
- `remove_package`
- `rsync_shell_execution`
- `rsync_shell_spawn`
- `ruby_reverse_shell`
- `schedule_task_job_cron`
- `security_software_discovery`
- `security_tools_disabling`
- `services_stop_and_disable`
- `setgid_setuid`
- `ssh_shell_execution`
- `ssm_agent_abuse`
- `susp_chmod_directories`
- `susp_container_residence_discovery`
- `susp_curl_fileupload`
- `susp_curl_useragent`
- `susp_dockerenv_recon`
- `susp_execution_tmp_folder`
- `susp_find_execution`
- `susp_git_clone`
- `susp_history_delete`
- `susp_history_recon`
- `susp_hktl_execution`
- `susp_inod_listing`
- `susp_interactive_bash`
- `susp_java_children`
- `susp_network_utilities_execution`
- `susp_process_reading_sudoers`
- `susp_recon_indicators`
- `susp_sensitive_file_access`
- `susp_shell_child_process_from_parent_tmp_folder`
- `susp_shell_script_exec_from_susp_location`
- `system_info_discovery`
- `system_network_connections_discovery`
- `system_network_discovery`
- `systemctl_mask_power_settings`
- `touch_susp`
- `triple_cross_rootkit_execve_hijack`
- `triple_cross_rootkit_install`
- `userdel`
- `usermod_susp_group`
- `vim_shell_execution`
- `webshell_detection`
- `wget_download_suspicious_directory`
- `xterm_reverse_shell`

</details>

## Edited Fields Analysis

| Field | Rules Count |
|-------|-------------|
| `CommandLine` | 22 |
| `Image` | 22 |
| `ParentImage` | 22 |

## Detailed Breakdown by Detection Rule

### Shell Execution via Flock - Linux

**Directory:** `flock_shell_execution`

**Sigma Rule ID:** `4b09c71e-4269-4111-9cdd-107d8867f0cc`

**Event Counts:**
- Total: 390
- Match Events: 0
- Evasion Events: 390

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390

**Log Files:**
- `Shel_Execution_via_Flock_attack1.log`
- `Shel_Execution_via_Flock_attack10.log`
- `Shel_Execution_via_Flock_attack100.log`
- `Shel_Execution_via_Flock_attack101.log`
- `Shel_Execution_via_Flock_attack102.log`
- `Shel_Execution_via_Flock_attack103.log`
- `Shel_Execution_via_Flock_attack104.log`
- `Shel_Execution_via_Flock_attack105.log`
- `Shel_Execution_via_Flock_attack106.log`
- `Shel_Execution_via_Flock_attack107.log`
- `Shel_Execution_via_Flock_attack108.log`
- `Shel_Execution_via_Flock_attack109.log`
- `Shel_Execution_via_Flock_attack11.log`
- `Shel_Execution_via_Flock_attack110.log`
- `Shel_Execution_via_Flock_attack111.log`
- `Shel_Execution_via_Flock_attack112.log`
- `Shel_Execution_via_Flock_attack113.log`
- `Shel_Execution_via_Flock_attack114.log`
- `Shel_Execution_via_Flock_attack115.log`
- `Shel_Execution_via_Flock_attack116.log`
- `Shel_Execution_via_Flock_attack117.log`
- `Shel_Execution_via_Flock_attack118.log`
- `Shel_Execution_via_Flock_attack119.log`
- `Shel_Execution_via_Flock_attack12.log`
- `Shel_Execution_via_Flock_attack120.log`
- `Shel_Execution_via_Flock_attack121.log`
- `Shel_Execution_via_Flock_attack122.log`
- `Shel_Execution_via_Flock_attack123.log`
- `Shel_Execution_via_Flock_attack124.log`
- `Shel_Execution_via_Flock_attack125.log`
- `Shel_Execution_via_Flock_attack126.log`
- `Shel_Execution_via_Flock_attack127.log`
- `Shel_Execution_via_Flock_attack128.log`
- `Shel_Execution_via_Flock_attack129.log`
- `Shel_Execution_via_Flock_attack13.log`
- `Shel_Execution_via_Flock_attack130.log`
- `Shel_Execution_via_Flock_attack131.log`
- `Shel_Execution_via_Flock_attack132.log`
- `Shel_Execution_via_Flock_attack133.log`
- `Shel_Execution_via_Flock_attack134.log`
- `Shel_Execution_via_Flock_attack135.log`
- `Shel_Execution_via_Flock_attack136.log`
- `Shel_Execution_via_Flock_attack137.log`
- `Shel_Execution_via_Flock_attack138.log`
- `Shel_Execution_via_Flock_attack139.log`
- `Shel_Execution_via_Flock_attack14.log`
- `Shel_Execution_via_Flock_attack140.log`
- `Shel_Execution_via_Flock_attack141.log`
- `Shel_Execution_via_Flock_attack142.log`
- `Shel_Execution_via_Flock_attack143.log`
- `Shel_Execution_via_Flock_attack144.log`
- `Shel_Execution_via_Flock_attack145.log`
- `Shel_Execution_via_Flock_attack146.log`
- `Shel_Execution_via_Flock_attack147.log`
- `Shel_Execution_via_Flock_attack148.log`
- `Shel_Execution_via_Flock_attack149.log`
- `Shel_Execution_via_Flock_attack15.log`
- `Shel_Execution_via_Flock_attack150.log`
- `Shel_Execution_via_Flock_attack151.log`
- `Shel_Execution_via_Flock_attack152.log`
- `Shel_Execution_via_Flock_attack153.log`
- `Shel_Execution_via_Flock_attack154.log`
- `Shel_Execution_via_Flock_attack155.log`
- `Shel_Execution_via_Flock_attack156.log`
- `Shel_Execution_via_Flock_attack157.log`
- `Shel_Execution_via_Flock_attack158.log`
- `Shel_Execution_via_Flock_attack159.log`
- `Shel_Execution_via_Flock_attack16.log`
- `Shel_Execution_via_Flock_attack160.log`
- `Shel_Execution_via_Flock_attack161.log`
- `Shel_Execution_via_Flock_attack162.log`
- `Shel_Execution_via_Flock_attack163.log`
- `Shel_Execution_via_Flock_attack164.log`
- `Shel_Execution_via_Flock_attack165.log`
- `Shel_Execution_via_Flock_attack166.log`
- `Shel_Execution_via_Flock_attack167.log`
- `Shel_Execution_via_Flock_attack168.log`
- `Shel_Execution_via_Flock_attack169.log`
- `Shel_Execution_via_Flock_attack17.log`
- `Shel_Execution_via_Flock_attack170.log`
- `Shel_Execution_via_Flock_attack171.log`
- `Shel_Execution_via_Flock_attack172.log`
- `Shel_Execution_via_Flock_attack173.log`
- `Shel_Execution_via_Flock_attack174.log`
- `Shel_Execution_via_Flock_attack175.log`
- `Shel_Execution_via_Flock_attack176.log`
- `Shel_Execution_via_Flock_attack177.log`
- `Shel_Execution_via_Flock_attack178.log`
- `Shel_Execution_via_Flock_attack179.log`
- `Shel_Execution_via_Flock_attack18.log`
- `Shel_Execution_via_Flock_attack180.log`
- `Shel_Execution_via_Flock_attack181.log`
- `Shel_Execution_via_Flock_attack182.log`
- `Shel_Execution_via_Flock_attack183.log`
- `Shel_Execution_via_Flock_attack184.log`
- `Shel_Execution_via_Flock_attack185.log`
- `Shel_Execution_via_Flock_attack186.log`
- `Shel_Execution_via_Flock_attack187.log`
- `Shel_Execution_via_Flock_attack188.log`
- `Shel_Execution_via_Flock_attack189.log`
- `Shel_Execution_via_Flock_attack19.log`
- `Shel_Execution_via_Flock_attack190.log`
- `Shel_Execution_via_Flock_attack191.log`
- `Shel_Execution_via_Flock_attack192.log`
- `Shel_Execution_via_Flock_attack193.log`
- `Shel_Execution_via_Flock_attack194.log`
- `Shel_Execution_via_Flock_attack195.log`
- `Shel_Execution_via_Flock_attack196.log`
- `Shel_Execution_via_Flock_attack197.log`
- `Shel_Execution_via_Flock_attack198.log`
- `Shel_Execution_via_Flock_attack199.log`
- `Shel_Execution_via_Flock_attack2.log`
- `Shel_Execution_via_Flock_attack20.log`
- `Shel_Execution_via_Flock_attack200.log`
- `Shel_Execution_via_Flock_attack201.log`
- `Shel_Execution_via_Flock_attack202.log`
- `Shel_Execution_via_Flock_attack203.log`
- `Shel_Execution_via_Flock_attack204.log`
- `Shel_Execution_via_Flock_attack205.log`
- `Shel_Execution_via_Flock_attack206.log`
- `Shel_Execution_via_Flock_attack207.log`
- `Shel_Execution_via_Flock_attack208.log`
- `Shel_Execution_via_Flock_attack209.log`
- `Shel_Execution_via_Flock_attack21.log`
- `Shel_Execution_via_Flock_attack210.log`
- `Shel_Execution_via_Flock_attack211.log`
- `Shel_Execution_via_Flock_attack212.log`
- `Shel_Execution_via_Flock_attack213.log`
- `Shel_Execution_via_Flock_attack214.log`
- `Shel_Execution_via_Flock_attack215.log`
- `Shel_Execution_via_Flock_attack216.log`
- `Shel_Execution_via_Flock_attack217.log`
- `Shel_Execution_via_Flock_attack218.log`
- `Shel_Execution_via_Flock_attack219.log`
- `Shel_Execution_via_Flock_attack22.log`
- `Shel_Execution_via_Flock_attack220.log`
- `Shel_Execution_via_Flock_attack221.log`
- `Shel_Execution_via_Flock_attack222.log`
- `Shel_Execution_via_Flock_attack223.log`
- `Shel_Execution_via_Flock_attack224.log`
- `Shel_Execution_via_Flock_attack225.log`
- `Shel_Execution_via_Flock_attack226.log`
- `Shel_Execution_via_Flock_attack227.log`
- `Shel_Execution_via_Flock_attack228.log`
- `Shel_Execution_via_Flock_attack229.log`
- `Shel_Execution_via_Flock_attack23.log`
- `Shel_Execution_via_Flock_attack230.log`
- `Shel_Execution_via_Flock_attack231.log`
- `Shel_Execution_via_Flock_attack232.log`
- `Shel_Execution_via_Flock_attack233.log`
- `Shel_Execution_via_Flock_attack234.log`
- `Shel_Execution_via_Flock_attack235.log`
- `Shel_Execution_via_Flock_attack236.log`
- `Shel_Execution_via_Flock_attack237.log`
- `Shel_Execution_via_Flock_attack238.log`
- `Shel_Execution_via_Flock_attack239.log`
- `Shel_Execution_via_Flock_attack24.log`
- `Shel_Execution_via_Flock_attack240.log`
- `Shel_Execution_via_Flock_attack241.log`
- `Shel_Execution_via_Flock_attack242.log`
- `Shel_Execution_via_Flock_attack243.log`
- `Shel_Execution_via_Flock_attack244.log`
- `Shel_Execution_via_Flock_attack245.log`
- `Shel_Execution_via_Flock_attack246.log`
- `Shel_Execution_via_Flock_attack247.log`
- `Shel_Execution_via_Flock_attack248.log`
- `Shel_Execution_via_Flock_attack249.log`
- `Shel_Execution_via_Flock_attack25.log`
- `Shel_Execution_via_Flock_attack250.log`
- `Shel_Execution_via_Flock_attack251.log`
- `Shel_Execution_via_Flock_attack252.log`
- `Shel_Execution_via_Flock_attack253.log`
- `Shel_Execution_via_Flock_attack254.log`
- `Shel_Execution_via_Flock_attack255.log`
- `Shel_Execution_via_Flock_attack256.log`
- `Shel_Execution_via_Flock_attack257.log`
- `Shel_Execution_via_Flock_attack258.log`
- `Shel_Execution_via_Flock_attack259.log`
- `Shel_Execution_via_Flock_attack26.log`
- `Shel_Execution_via_Flock_attack260.log`
- `Shel_Execution_via_Flock_attack261.log`
- `Shel_Execution_via_Flock_attack262.log`
- `Shel_Execution_via_Flock_attack263.log`
- `Shel_Execution_via_Flock_attack264.log`
- `Shel_Execution_via_Flock_attack265.log`
- `Shel_Execution_via_Flock_attack266.log`
- `Shel_Execution_via_Flock_attack267.log`
- `Shel_Execution_via_Flock_attack268.log`
- `Shel_Execution_via_Flock_attack269.log`
- `Shel_Execution_via_Flock_attack27.log`
- `Shel_Execution_via_Flock_attack270.log`
- `Shel_Execution_via_Flock_attack271.log`
- `Shel_Execution_via_Flock_attack272.log`
- `Shel_Execution_via_Flock_attack273.log`
- `Shel_Execution_via_Flock_attack274.log`
- `Shel_Execution_via_Flock_attack275.log`
- `Shel_Execution_via_Flock_attack276.log`
- `Shel_Execution_via_Flock_attack277.log`
- `Shel_Execution_via_Flock_attack278.log`
- `Shel_Execution_via_Flock_attack279.log`
- `Shel_Execution_via_Flock_attack28.log`
- `Shel_Execution_via_Flock_attack280.log`
- `Shel_Execution_via_Flock_attack281.log`
- `Shel_Execution_via_Flock_attack282.log`
- `Shel_Execution_via_Flock_attack283.log`
- `Shel_Execution_via_Flock_attack284.log`
- `Shel_Execution_via_Flock_attack285.log`
- `Shel_Execution_via_Flock_attack286.log`
- `Shel_Execution_via_Flock_attack287.log`
- `Shel_Execution_via_Flock_attack288.log`
- `Shel_Execution_via_Flock_attack289.log`
- `Shel_Execution_via_Flock_attack29.log`
- `Shel_Execution_via_Flock_attack290.log`
- `Shel_Execution_via_Flock_attack291.log`
- `Shel_Execution_via_Flock_attack292.log`
- `Shel_Execution_via_Flock_attack293.log`
- `Shel_Execution_via_Flock_attack294.log`
- `Shel_Execution_via_Flock_attack295.log`
- `Shel_Execution_via_Flock_attack296.log`
- `Shel_Execution_via_Flock_attack297.log`
- `Shel_Execution_via_Flock_attack298.log`
- `Shel_Execution_via_Flock_attack299.log`
- `Shel_Execution_via_Flock_attack3.log`
- `Shel_Execution_via_Flock_attack30.log`
- `Shel_Execution_via_Flock_attack300.log`
- `Shel_Execution_via_Flock_attack301.log`
- `Shel_Execution_via_Flock_attack302.log`
- `Shel_Execution_via_Flock_attack303.log`
- `Shel_Execution_via_Flock_attack304.log`
- `Shel_Execution_via_Flock_attack305.log`
- `Shel_Execution_via_Flock_attack306.log`
- `Shel_Execution_via_Flock_attack307.log`
- `Shel_Execution_via_Flock_attack308.log`
- `Shel_Execution_via_Flock_attack309.log`
- `Shel_Execution_via_Flock_attack31.log`
- `Shel_Execution_via_Flock_attack310.log`
- `Shel_Execution_via_Flock_attack311.log`
- `Shel_Execution_via_Flock_attack312.log`
- `Shel_Execution_via_Flock_attack313.log`
- `Shel_Execution_via_Flock_attack314.log`
- `Shel_Execution_via_Flock_attack315.log`
- `Shel_Execution_via_Flock_attack316.log`
- `Shel_Execution_via_Flock_attack317.log`
- `Shel_Execution_via_Flock_attack318.log`
- `Shel_Execution_via_Flock_attack319.log`
- `Shel_Execution_via_Flock_attack32.log`
- `Shel_Execution_via_Flock_attack320.log`
- `Shel_Execution_via_Flock_attack321.log`
- `Shel_Execution_via_Flock_attack322.log`
- `Shel_Execution_via_Flock_attack323.log`
- `Shel_Execution_via_Flock_attack324.log`
- `Shel_Execution_via_Flock_attack325.log`
- `Shel_Execution_via_Flock_attack326.log`
- `Shel_Execution_via_Flock_attack327.log`
- `Shel_Execution_via_Flock_attack328.log`
- `Shel_Execution_via_Flock_attack329.log`
- `Shel_Execution_via_Flock_attack33.log`
- `Shel_Execution_via_Flock_attack330.log`
- `Shel_Execution_via_Flock_attack331.log`
- `Shel_Execution_via_Flock_attack332.log`
- `Shel_Execution_via_Flock_attack333.log`
- `Shel_Execution_via_Flock_attack334.log`
- `Shel_Execution_via_Flock_attack335.log`
- `Shel_Execution_via_Flock_attack336.log`
- `Shel_Execution_via_Flock_attack337.log`
- `Shel_Execution_via_Flock_attack338.log`
- `Shel_Execution_via_Flock_attack339.log`
- `Shel_Execution_via_Flock_attack34.log`
- `Shel_Execution_via_Flock_attack340.log`
- `Shel_Execution_via_Flock_attack341.log`
- `Shel_Execution_via_Flock_attack342.log`
- `Shel_Execution_via_Flock_attack343.log`
- `Shel_Execution_via_Flock_attack344.log`
- `Shel_Execution_via_Flock_attack345.log`
- `Shel_Execution_via_Flock_attack346.log`
- `Shel_Execution_via_Flock_attack347.log`
- `Shel_Execution_via_Flock_attack348.log`
- `Shel_Execution_via_Flock_attack349.log`
- `Shel_Execution_via_Flock_attack35.log`
- `Shel_Execution_via_Flock_attack350.log`
- `Shel_Execution_via_Flock_attack351.log`
- `Shel_Execution_via_Flock_attack352.log`
- `Shel_Execution_via_Flock_attack353.log`
- `Shel_Execution_via_Flock_attack354.log`
- `Shel_Execution_via_Flock_attack355.log`
- `Shel_Execution_via_Flock_attack356.log`
- `Shel_Execution_via_Flock_attack357.log`
- `Shel_Execution_via_Flock_attack358.log`
- `Shel_Execution_via_Flock_attack359.log`
- `Shel_Execution_via_Flock_attack36.log`
- `Shel_Execution_via_Flock_attack360.log`
- `Shel_Execution_via_Flock_attack361.log`
- `Shel_Execution_via_Flock_attack362.log`
- `Shel_Execution_via_Flock_attack363.log`
- `Shel_Execution_via_Flock_attack364.log`
- `Shel_Execution_via_Flock_attack365.log`
- `Shel_Execution_via_Flock_attack366.log`
- `Shel_Execution_via_Flock_attack367.log`
- `Shel_Execution_via_Flock_attack368.log`
- `Shel_Execution_via_Flock_attack369.log`
- `Shel_Execution_via_Flock_attack37.log`
- `Shel_Execution_via_Flock_attack370.log`
- `Shel_Execution_via_Flock_attack371.log`
- `Shel_Execution_via_Flock_attack372.log`
- `Shel_Execution_via_Flock_attack373.log`
- `Shel_Execution_via_Flock_attack374.log`
- `Shel_Execution_via_Flock_attack375.log`
- `Shel_Execution_via_Flock_attack376.log`
- `Shel_Execution_via_Flock_attack377.log`
- `Shel_Execution_via_Flock_attack378.log`
- `Shel_Execution_via_Flock_attack379.log`
- `Shel_Execution_via_Flock_attack38.log`
- `Shel_Execution_via_Flock_attack380.log`
- `Shel_Execution_via_Flock_attack381.log`
- `Shel_Execution_via_Flock_attack382.log`
- `Shel_Execution_via_Flock_attack383.log`
- `Shel_Execution_via_Flock_attack384.log`
- `Shel_Execution_via_Flock_attack385.log`
- `Shel_Execution_via_Flock_attack386.log`
- `Shel_Execution_via_Flock_attack387.log`
- `Shel_Execution_via_Flock_attack388.log`
- `Shel_Execution_via_Flock_attack389.log`
- `Shel_Execution_via_Flock_attack39.log`
- `Shel_Execution_via_Flock_attack390.log`
- `Shel_Execution_via_Flock_attack4.log`
- `Shel_Execution_via_Flock_attack40.log`
- `Shel_Execution_via_Flock_attack41.log`
- `Shel_Execution_via_Flock_attack42.log`
- `Shel_Execution_via_Flock_attack43.log`
- `Shel_Execution_via_Flock_attack44.log`
- `Shel_Execution_via_Flock_attack45.log`
- `Shel_Execution_via_Flock_attack46.log`
- `Shel_Execution_via_Flock_attack47.log`
- `Shel_Execution_via_Flock_attack48.log`
- `Shel_Execution_via_Flock_attack49.log`
- `Shel_Execution_via_Flock_attack5.log`
- `Shel_Execution_via_Flock_attack50.log`
- `Shel_Execution_via_Flock_attack51.log`
- `Shel_Execution_via_Flock_attack52.log`
- `Shel_Execution_via_Flock_attack53.log`
- `Shel_Execution_via_Flock_attack54.log`
- `Shel_Execution_via_Flock_attack55.log`
- `Shel_Execution_via_Flock_attack56.log`
- `Shel_Execution_via_Flock_attack57.log`
- `Shel_Execution_via_Flock_attack58.log`
- `Shel_Execution_via_Flock_attack59.log`
- `Shel_Execution_via_Flock_attack6.log`
- `Shel_Execution_via_Flock_attack60.log`
- `Shel_Execution_via_Flock_attack61.log`
- `Shel_Execution_via_Flock_attack62.log`
- `Shel_Execution_via_Flock_attack63.log`
- `Shel_Execution_via_Flock_attack64.log`
- `Shel_Execution_via_Flock_attack65.log`
- `Shel_Execution_via_Flock_attack66.log`
- `Shel_Execution_via_Flock_attack67.log`
- `Shel_Execution_via_Flock_attack68.log`
- `Shel_Execution_via_Flock_attack69.log`
- `Shel_Execution_via_Flock_attack7.log`
- `Shel_Execution_via_Flock_attack70.log`
- `Shel_Execution_via_Flock_attack71.log`
- `Shel_Execution_via_Flock_attack72.log`
- `Shel_Execution_via_Flock_attack73.log`
- `Shel_Execution_via_Flock_attack74.log`
- `Shel_Execution_via_Flock_attack75.log`
- `Shel_Execution_via_Flock_attack76.log`
- `Shel_Execution_via_Flock_attack77.log`
- `Shel_Execution_via_Flock_attack78.log`
- `Shel_Execution_via_Flock_attack79.log`
- `Shel_Execution_via_Flock_attack8.log`
- `Shel_Execution_via_Flock_attack80.log`
- `Shel_Execution_via_Flock_attack81.log`
- `Shel_Execution_via_Flock_attack82.log`
- `Shel_Execution_via_Flock_attack83.log`
- `Shel_Execution_via_Flock_attack84.log`
- `Shel_Execution_via_Flock_attack85.log`
- `Shel_Execution_via_Flock_attack86.log`
- `Shel_Execution_via_Flock_attack87.log`
- `Shel_Execution_via_Flock_attack88.log`
- `Shel_Execution_via_Flock_attack89.log`
- `Shel_Execution_via_Flock_attack9.log`
- `Shel_Execution_via_Flock_attack90.log`
- `Shel_Execution_via_Flock_attack91.log`
- `Shel_Execution_via_Flock_attack92.log`
- `Shel_Execution_via_Flock_attack93.log`
- `Shel_Execution_via_Flock_attack94.log`
- `Shel_Execution_via_Flock_attack95.log`
- `Shel_Execution_via_Flock_attack96.log`
- `Shel_Execution_via_Flock_attack97.log`
- `Shel_Execution_via_Flock_attack98.log`
- `Shel_Execution_via_Flock_attack99.log`

---

### BPFtrace Unsafe Option Usage

**Directory:** `bpftrace_unsafe_option_usage`

**Sigma Rule ID:** `f8341cb2-ee25-43fa-a975-d8a5a9714b39`

**Event Counts:**
- Total: 360
- Match Events: 115
- Evasion Events: 245

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360

**Log Files:**
- `BPFtrace_Unsafe_Option_Usage_attack1.log`
- `BPFtrace_Unsafe_Option_Usage_attack10.log`
- `BPFtrace_Unsafe_Option_Usage_attack100.log`
- `BPFtrace_Unsafe_Option_Usage_attack101.log`
- `BPFtrace_Unsafe_Option_Usage_attack102.log`
- `BPFtrace_Unsafe_Option_Usage_attack103.log`
- `BPFtrace_Unsafe_Option_Usage_attack104.log`
- `BPFtrace_Unsafe_Option_Usage_attack105.log`
- `BPFtrace_Unsafe_Option_Usage_attack106.log`
- `BPFtrace_Unsafe_Option_Usage_attack107.log`
- `BPFtrace_Unsafe_Option_Usage_attack108.log`
- `BPFtrace_Unsafe_Option_Usage_attack109.log`
- `BPFtrace_Unsafe_Option_Usage_attack11.log`
- `BPFtrace_Unsafe_Option_Usage_attack110.log`
- `BPFtrace_Unsafe_Option_Usage_attack111.log`
- `BPFtrace_Unsafe_Option_Usage_attack112.log`
- `BPFtrace_Unsafe_Option_Usage_attack113.log`
- `BPFtrace_Unsafe_Option_Usage_attack114.log`
- `BPFtrace_Unsafe_Option_Usage_attack115.log`
- `BPFtrace_Unsafe_Option_Usage_attack116.log`
- `BPFtrace_Unsafe_Option_Usage_attack117.log`
- `BPFtrace_Unsafe_Option_Usage_attack118.log`
- `BPFtrace_Unsafe_Option_Usage_attack119.log`
- `BPFtrace_Unsafe_Option_Usage_attack12.log`
- `BPFtrace_Unsafe_Option_Usage_attack120.log`
- `BPFtrace_Unsafe_Option_Usage_attack121.log`
- `BPFtrace_Unsafe_Option_Usage_attack122.log`
- `BPFtrace_Unsafe_Option_Usage_attack123.log`
- `BPFtrace_Unsafe_Option_Usage_attack124.log`
- `BPFtrace_Unsafe_Option_Usage_attack125.log`
- `BPFtrace_Unsafe_Option_Usage_attack126.log`
- `BPFtrace_Unsafe_Option_Usage_attack127.log`
- `BPFtrace_Unsafe_Option_Usage_attack128.log`
- `BPFtrace_Unsafe_Option_Usage_attack129.log`
- `BPFtrace_Unsafe_Option_Usage_attack13.log`
- `BPFtrace_Unsafe_Option_Usage_attack130.log`
- `BPFtrace_Unsafe_Option_Usage_attack131.log`
- `BPFtrace_Unsafe_Option_Usage_attack132.log`
- `BPFtrace_Unsafe_Option_Usage_attack133.log`
- `BPFtrace_Unsafe_Option_Usage_attack134.log`
- `BPFtrace_Unsafe_Option_Usage_attack135.log`
- `BPFtrace_Unsafe_Option_Usage_attack136.log`
- `BPFtrace_Unsafe_Option_Usage_attack137.log`
- `BPFtrace_Unsafe_Option_Usage_attack138.log`
- `BPFtrace_Unsafe_Option_Usage_attack139.log`
- `BPFtrace_Unsafe_Option_Usage_attack14.log`
- `BPFtrace_Unsafe_Option_Usage_attack140.log`
- `BPFtrace_Unsafe_Option_Usage_attack141.log`
- `BPFtrace_Unsafe_Option_Usage_attack142.log`
- `BPFtrace_Unsafe_Option_Usage_attack143.log`
- `BPFtrace_Unsafe_Option_Usage_attack144.log`
- `BPFtrace_Unsafe_Option_Usage_attack145.log`
- `BPFtrace_Unsafe_Option_Usage_attack146.log`
- `BPFtrace_Unsafe_Option_Usage_attack147.log`
- `BPFtrace_Unsafe_Option_Usage_attack148.log`
- `BPFtrace_Unsafe_Option_Usage_attack149.log`
- `BPFtrace_Unsafe_Option_Usage_attack15.log`
- `BPFtrace_Unsafe_Option_Usage_attack150.log`
- `BPFtrace_Unsafe_Option_Usage_attack151.log`
- `BPFtrace_Unsafe_Option_Usage_attack152.log`
- `BPFtrace_Unsafe_Option_Usage_attack153.log`
- `BPFtrace_Unsafe_Option_Usage_attack154.log`
- `BPFtrace_Unsafe_Option_Usage_attack155.log`
- `BPFtrace_Unsafe_Option_Usage_attack156.log`
- `BPFtrace_Unsafe_Option_Usage_attack157.log`
- `BPFtrace_Unsafe_Option_Usage_attack158.log`
- `BPFtrace_Unsafe_Option_Usage_attack159.log`
- `BPFtrace_Unsafe_Option_Usage_attack16.log`
- `BPFtrace_Unsafe_Option_Usage_attack160.log`
- `BPFtrace_Unsafe_Option_Usage_attack161.log`
- `BPFtrace_Unsafe_Option_Usage_attack162.log`
- `BPFtrace_Unsafe_Option_Usage_attack163.log`
- `BPFtrace_Unsafe_Option_Usage_attack164.log`
- `BPFtrace_Unsafe_Option_Usage_attack165.log`
- `BPFtrace_Unsafe_Option_Usage_attack166.log`
- `BPFtrace_Unsafe_Option_Usage_attack167.log`
- `BPFtrace_Unsafe_Option_Usage_attack168.log`
- `BPFtrace_Unsafe_Option_Usage_attack169.log`
- `BPFtrace_Unsafe_Option_Usage_attack17.log`
- `BPFtrace_Unsafe_Option_Usage_attack170.log`
- `BPFtrace_Unsafe_Option_Usage_attack171.log`
- `BPFtrace_Unsafe_Option_Usage_attack172.log`
- `BPFtrace_Unsafe_Option_Usage_attack173.log`
- `BPFtrace_Unsafe_Option_Usage_attack174.log`
- `BPFtrace_Unsafe_Option_Usage_attack175.log`
- `BPFtrace_Unsafe_Option_Usage_attack176.log`
- `BPFtrace_Unsafe_Option_Usage_attack177.log`
- `BPFtrace_Unsafe_Option_Usage_attack178.log`
- `BPFtrace_Unsafe_Option_Usage_attack179.log`
- `BPFtrace_Unsafe_Option_Usage_attack18.log`
- `BPFtrace_Unsafe_Option_Usage_attack180.log`
- `BPFtrace_Unsafe_Option_Usage_attack181.log`
- `BPFtrace_Unsafe_Option_Usage_attack182.log`
- `BPFtrace_Unsafe_Option_Usage_attack183.log`
- `BPFtrace_Unsafe_Option_Usage_attack184.log`
- `BPFtrace_Unsafe_Option_Usage_attack185.log`
- `BPFtrace_Unsafe_Option_Usage_attack186.log`
- `BPFtrace_Unsafe_Option_Usage_attack187.log`
- `BPFtrace_Unsafe_Option_Usage_attack188.log`
- `BPFtrace_Unsafe_Option_Usage_attack189.log`
- `BPFtrace_Unsafe_Option_Usage_attack19.log`
- `BPFtrace_Unsafe_Option_Usage_attack190.log`
- `BPFtrace_Unsafe_Option_Usage_attack191.log`
- `BPFtrace_Unsafe_Option_Usage_attack192.log`
- `BPFtrace_Unsafe_Option_Usage_attack193.log`
- `BPFtrace_Unsafe_Option_Usage_attack194.log`
- `BPFtrace_Unsafe_Option_Usage_attack195.log`
- `BPFtrace_Unsafe_Option_Usage_attack196.log`
- `BPFtrace_Unsafe_Option_Usage_attack197.log`
- `BPFtrace_Unsafe_Option_Usage_attack198.log`
- `BPFtrace_Unsafe_Option_Usage_attack199.log`
- `BPFtrace_Unsafe_Option_Usage_attack2.log`
- `BPFtrace_Unsafe_Option_Usage_attack20.log`
- `BPFtrace_Unsafe_Option_Usage_attack200.log`
- `BPFtrace_Unsafe_Option_Usage_attack201.log`
- `BPFtrace_Unsafe_Option_Usage_attack202.log`
- `BPFtrace_Unsafe_Option_Usage_attack203.log`
- `BPFtrace_Unsafe_Option_Usage_attack204.log`
- `BPFtrace_Unsafe_Option_Usage_attack205.log`
- `BPFtrace_Unsafe_Option_Usage_attack206.log`
- `BPFtrace_Unsafe_Option_Usage_attack207.log`
- `BPFtrace_Unsafe_Option_Usage_attack208.log`
- `BPFtrace_Unsafe_Option_Usage_attack209.log`
- `BPFtrace_Unsafe_Option_Usage_attack21.log`
- `BPFtrace_Unsafe_Option_Usage_attack210.log`
- `BPFtrace_Unsafe_Option_Usage_attack211.log`
- `BPFtrace_Unsafe_Option_Usage_attack212.log`
- `BPFtrace_Unsafe_Option_Usage_attack213.log`
- `BPFtrace_Unsafe_Option_Usage_attack214.log`
- `BPFtrace_Unsafe_Option_Usage_attack215.log`
- `BPFtrace_Unsafe_Option_Usage_attack216.log`
- `BPFtrace_Unsafe_Option_Usage_attack217.log`
- `BPFtrace_Unsafe_Option_Usage_attack218.log`
- `BPFtrace_Unsafe_Option_Usage_attack219.log`
- `BPFtrace_Unsafe_Option_Usage_attack22.log`
- `BPFtrace_Unsafe_Option_Usage_attack220.log`
- `BPFtrace_Unsafe_Option_Usage_attack221.log`
- `BPFtrace_Unsafe_Option_Usage_attack222.log`
- `BPFtrace_Unsafe_Option_Usage_attack223.log`
- `BPFtrace_Unsafe_Option_Usage_attack224.log`
- `BPFtrace_Unsafe_Option_Usage_attack225.log`
- `BPFtrace_Unsafe_Option_Usage_attack226.log`
- `BPFtrace_Unsafe_Option_Usage_attack227.log`
- `BPFtrace_Unsafe_Option_Usage_attack228.log`
- `BPFtrace_Unsafe_Option_Usage_attack229.log`
- `BPFtrace_Unsafe_Option_Usage_attack23.log`
- `BPFtrace_Unsafe_Option_Usage_attack230.log`
- `BPFtrace_Unsafe_Option_Usage_attack231.log`
- `BPFtrace_Unsafe_Option_Usage_attack232.log`
- `BPFtrace_Unsafe_Option_Usage_attack233.log`
- `BPFtrace_Unsafe_Option_Usage_attack234.log`
- `BPFtrace_Unsafe_Option_Usage_attack235.log`
- `BPFtrace_Unsafe_Option_Usage_attack236.log`
- `BPFtrace_Unsafe_Option_Usage_attack237.log`
- `BPFtrace_Unsafe_Option_Usage_attack238.log`
- `BPFtrace_Unsafe_Option_Usage_attack239.log`
- `BPFtrace_Unsafe_Option_Usage_attack24.log`
- `BPFtrace_Unsafe_Option_Usage_attack240.log`
- `BPFtrace_Unsafe_Option_Usage_attack241.log`
- `BPFtrace_Unsafe_Option_Usage_attack242.log`
- `BPFtrace_Unsafe_Option_Usage_attack243.log`
- `BPFtrace_Unsafe_Option_Usage_attack244.log`
- `BPFtrace_Unsafe_Option_Usage_attack245.log`
- `BPFtrace_Unsafe_Option_Usage_attack246.log`
- `BPFtrace_Unsafe_Option_Usage_attack247.log`
- `BPFtrace_Unsafe_Option_Usage_attack248.log`
- `BPFtrace_Unsafe_Option_Usage_attack249.log`
- `BPFtrace_Unsafe_Option_Usage_attack25.log`
- `BPFtrace_Unsafe_Option_Usage_attack250.log`
- `BPFtrace_Unsafe_Option_Usage_attack251.log`
- `BPFtrace_Unsafe_Option_Usage_attack252.log`
- `BPFtrace_Unsafe_Option_Usage_attack253.log`
- `BPFtrace_Unsafe_Option_Usage_attack254.log`
- `BPFtrace_Unsafe_Option_Usage_attack255.log`
- `BPFtrace_Unsafe_Option_Usage_attack256.log`
- `BPFtrace_Unsafe_Option_Usage_attack257.log`
- `BPFtrace_Unsafe_Option_Usage_attack258.log`
- `BPFtrace_Unsafe_Option_Usage_attack259.log`
- `BPFtrace_Unsafe_Option_Usage_attack26.log`
- `BPFtrace_Unsafe_Option_Usage_attack260.log`
- `BPFtrace_Unsafe_Option_Usage_attack261.log`
- `BPFtrace_Unsafe_Option_Usage_attack262.log`
- `BPFtrace_Unsafe_Option_Usage_attack263.log`
- `BPFtrace_Unsafe_Option_Usage_attack264.log`
- `BPFtrace_Unsafe_Option_Usage_attack265.log`
- `BPFtrace_Unsafe_Option_Usage_attack266.log`
- `BPFtrace_Unsafe_Option_Usage_attack267.log`
- `BPFtrace_Unsafe_Option_Usage_attack268.log`
- `BPFtrace_Unsafe_Option_Usage_attack269.log`
- `BPFtrace_Unsafe_Option_Usage_attack27.log`
- `BPFtrace_Unsafe_Option_Usage_attack270.log`
- `BPFtrace_Unsafe_Option_Usage_attack271.log`
- `BPFtrace_Unsafe_Option_Usage_attack272.log`
- `BPFtrace_Unsafe_Option_Usage_attack273.log`
- `BPFtrace_Unsafe_Option_Usage_attack274.log`
- `BPFtrace_Unsafe_Option_Usage_attack275.log`
- `BPFtrace_Unsafe_Option_Usage_attack276.log`
- `BPFtrace_Unsafe_Option_Usage_attack277.log`
- `BPFtrace_Unsafe_Option_Usage_attack278.log`
- `BPFtrace_Unsafe_Option_Usage_attack279.log`
- `BPFtrace_Unsafe_Option_Usage_attack28.log`
- `BPFtrace_Unsafe_Option_Usage_attack280.log`
- `BPFtrace_Unsafe_Option_Usage_attack281.log`
- `BPFtrace_Unsafe_Option_Usage_attack282.log`
- `BPFtrace_Unsafe_Option_Usage_attack283.log`
- `BPFtrace_Unsafe_Option_Usage_attack284.log`
- `BPFtrace_Unsafe_Option_Usage_attack285.log`
- `BPFtrace_Unsafe_Option_Usage_attack286.log`
- `BPFtrace_Unsafe_Option_Usage_attack287.log`
- `BPFtrace_Unsafe_Option_Usage_attack288.log`
- `BPFtrace_Unsafe_Option_Usage_attack289.log`
- `BPFtrace_Unsafe_Option_Usage_attack29.log`
- `BPFtrace_Unsafe_Option_Usage_attack290.log`
- `BPFtrace_Unsafe_Option_Usage_attack291.log`
- `BPFtrace_Unsafe_Option_Usage_attack292.log`
- `BPFtrace_Unsafe_Option_Usage_attack293.log`
- `BPFtrace_Unsafe_Option_Usage_attack294.log`
- `BPFtrace_Unsafe_Option_Usage_attack295.log`
- `BPFtrace_Unsafe_Option_Usage_attack296.log`
- `BPFtrace_Unsafe_Option_Usage_attack297.log`
- `BPFtrace_Unsafe_Option_Usage_attack298.log`
- `BPFtrace_Unsafe_Option_Usage_attack299.log`
- `BPFtrace_Unsafe_Option_Usage_attack3.log`
- `BPFtrace_Unsafe_Option_Usage_attack30.log`
- `BPFtrace_Unsafe_Option_Usage_attack300.log`
- `BPFtrace_Unsafe_Option_Usage_attack301.log`
- `BPFtrace_Unsafe_Option_Usage_attack302.log`
- `BPFtrace_Unsafe_Option_Usage_attack303.log`
- `BPFtrace_Unsafe_Option_Usage_attack304.log`
- `BPFtrace_Unsafe_Option_Usage_attack305.log`
- `BPFtrace_Unsafe_Option_Usage_attack306.log`
- `BPFtrace_Unsafe_Option_Usage_attack307.log`
- `BPFtrace_Unsafe_Option_Usage_attack308.log`
- `BPFtrace_Unsafe_Option_Usage_attack309.log`
- `BPFtrace_Unsafe_Option_Usage_attack31.log`
- `BPFtrace_Unsafe_Option_Usage_attack310.log`
- `BPFtrace_Unsafe_Option_Usage_attack311.log`
- `BPFtrace_Unsafe_Option_Usage_attack312.log`
- `BPFtrace_Unsafe_Option_Usage_attack313.log`
- `BPFtrace_Unsafe_Option_Usage_attack314.log`
- `BPFtrace_Unsafe_Option_Usage_attack315.log`
- `BPFtrace_Unsafe_Option_Usage_attack316.log`
- `BPFtrace_Unsafe_Option_Usage_attack317.log`
- `BPFtrace_Unsafe_Option_Usage_attack318.log`
- `BPFtrace_Unsafe_Option_Usage_attack319.log`
- `BPFtrace_Unsafe_Option_Usage_attack32.log`
- `BPFtrace_Unsafe_Option_Usage_attack320.log`
- `BPFtrace_Unsafe_Option_Usage_attack321.log`
- `BPFtrace_Unsafe_Option_Usage_attack322.log`
- `BPFtrace_Unsafe_Option_Usage_attack323.log`
- `BPFtrace_Unsafe_Option_Usage_attack324.log`
- `BPFtrace_Unsafe_Option_Usage_attack325.log`
- `BPFtrace_Unsafe_Option_Usage_attack326.log`
- `BPFtrace_Unsafe_Option_Usage_attack327.log`
- `BPFtrace_Unsafe_Option_Usage_attack328.log`
- `BPFtrace_Unsafe_Option_Usage_attack329.log`
- `BPFtrace_Unsafe_Option_Usage_attack33.log`
- `BPFtrace_Unsafe_Option_Usage_attack330.log`
- `BPFtrace_Unsafe_Option_Usage_attack331.log`
- `BPFtrace_Unsafe_Option_Usage_attack332.log`
- `BPFtrace_Unsafe_Option_Usage_attack333.log`
- `BPFtrace_Unsafe_Option_Usage_attack334.log`
- `BPFtrace_Unsafe_Option_Usage_attack335.log`
- `BPFtrace_Unsafe_Option_Usage_attack336.log`
- `BPFtrace_Unsafe_Option_Usage_attack337.log`
- `BPFtrace_Unsafe_Option_Usage_attack338.log`
- `BPFtrace_Unsafe_Option_Usage_attack339.log`
- `BPFtrace_Unsafe_Option_Usage_attack34.log`
- `BPFtrace_Unsafe_Option_Usage_attack340.log`
- `BPFtrace_Unsafe_Option_Usage_attack341.log`
- `BPFtrace_Unsafe_Option_Usage_attack342.log`
- `BPFtrace_Unsafe_Option_Usage_attack343.log`
- `BPFtrace_Unsafe_Option_Usage_attack344.log`
- `BPFtrace_Unsafe_Option_Usage_attack345.log`
- `BPFtrace_Unsafe_Option_Usage_attack346.log`
- `BPFtrace_Unsafe_Option_Usage_attack347.log`
- `BPFtrace_Unsafe_Option_Usage_attack348.log`
- `BPFtrace_Unsafe_Option_Usage_attack349.log`
- `BPFtrace_Unsafe_Option_Usage_attack35.log`
- `BPFtrace_Unsafe_Option_Usage_attack350.log`
- `BPFtrace_Unsafe_Option_Usage_attack351.log`
- `BPFtrace_Unsafe_Option_Usage_attack352.log`
- `BPFtrace_Unsafe_Option_Usage_attack353.log`
- `BPFtrace_Unsafe_Option_Usage_attack354.log`
- `BPFtrace_Unsafe_Option_Usage_attack355.log`
- `BPFtrace_Unsafe_Option_Usage_attack356.log`
- `BPFtrace_Unsafe_Option_Usage_attack357.log`
- `BPFtrace_Unsafe_Option_Usage_attack358.log`
- `BPFtrace_Unsafe_Option_Usage_attack359.log`
- `BPFtrace_Unsafe_Option_Usage_attack36.log`
- `BPFtrace_Unsafe_Option_Usage_attack360.log`
- `BPFtrace_Unsafe_Option_Usage_attack37.log`
- `BPFtrace_Unsafe_Option_Usage_attack38.log`
- `BPFtrace_Unsafe_Option_Usage_attack39.log`
- `BPFtrace_Unsafe_Option_Usage_attack4.log`
- `BPFtrace_Unsafe_Option_Usage_attack40.log`
- `BPFtrace_Unsafe_Option_Usage_attack41.log`
- `BPFtrace_Unsafe_Option_Usage_attack42.log`
- `BPFtrace_Unsafe_Option_Usage_attack43.log`
- `BPFtrace_Unsafe_Option_Usage_attack44.log`
- `BPFtrace_Unsafe_Option_Usage_attack45.log`
- `BPFtrace_Unsafe_Option_Usage_attack46.log`
- `BPFtrace_Unsafe_Option_Usage_attack47.log`
- `BPFtrace_Unsafe_Option_Usage_attack48.log`
- `BPFtrace_Unsafe_Option_Usage_attack49.log`
- `BPFtrace_Unsafe_Option_Usage_attack5.log`
- `BPFtrace_Unsafe_Option_Usage_attack50.log`
- `BPFtrace_Unsafe_Option_Usage_attack51.log`
- `BPFtrace_Unsafe_Option_Usage_attack52.log`
- `BPFtrace_Unsafe_Option_Usage_attack53.log`
- `BPFtrace_Unsafe_Option_Usage_attack54.log`
- `BPFtrace_Unsafe_Option_Usage_attack55.log`
- `BPFtrace_Unsafe_Option_Usage_attack56.log`
- `BPFtrace_Unsafe_Option_Usage_attack57.log`
- `BPFtrace_Unsafe_Option_Usage_attack58.log`
- `BPFtrace_Unsafe_Option_Usage_attack59.log`
- `BPFtrace_Unsafe_Option_Usage_attack6.log`
- `BPFtrace_Unsafe_Option_Usage_attack60.log`
- `BPFtrace_Unsafe_Option_Usage_attack61.log`
- `BPFtrace_Unsafe_Option_Usage_attack62.log`
- `BPFtrace_Unsafe_Option_Usage_attack63.log`
- `BPFtrace_Unsafe_Option_Usage_attack64.log`
- `BPFtrace_Unsafe_Option_Usage_attack65.log`
- `BPFtrace_Unsafe_Option_Usage_attack66.log`
- `BPFtrace_Unsafe_Option_Usage_attack67.log`
- `BPFtrace_Unsafe_Option_Usage_attack68.log`
- `BPFtrace_Unsafe_Option_Usage_attack69.log`
- `BPFtrace_Unsafe_Option_Usage_attack7.log`
- `BPFtrace_Unsafe_Option_Usage_attack70.log`
- `BPFtrace_Unsafe_Option_Usage_attack71.log`
- `BPFtrace_Unsafe_Option_Usage_attack72.log`
- `BPFtrace_Unsafe_Option_Usage_attack73.log`
- `BPFtrace_Unsafe_Option_Usage_attack74.log`
- `BPFtrace_Unsafe_Option_Usage_attack75.log`
- `BPFtrace_Unsafe_Option_Usage_attack76.log`
- `BPFtrace_Unsafe_Option_Usage_attack77.log`
- `BPFtrace_Unsafe_Option_Usage_attack78.log`
- `BPFtrace_Unsafe_Option_Usage_attack79.log`
- `BPFtrace_Unsafe_Option_Usage_attack8.log`
- `BPFtrace_Unsafe_Option_Usage_attack80.log`
- `BPFtrace_Unsafe_Option_Usage_attack81.log`
- `BPFtrace_Unsafe_Option_Usage_attack82.log`
- `BPFtrace_Unsafe_Option_Usage_attack83.log`
- `BPFtrace_Unsafe_Option_Usage_attack84.log`
- `BPFtrace_Unsafe_Option_Usage_attack85.log`
- `BPFtrace_Unsafe_Option_Usage_attack86.log`
- `BPFtrace_Unsafe_Option_Usage_attack87.log`
- `BPFtrace_Unsafe_Option_Usage_attack88.log`
- `BPFtrace_Unsafe_Option_Usage_attack89.log`
- `BPFtrace_Unsafe_Option_Usage_attack9.log`
- `BPFtrace_Unsafe_Option_Usage_attack90.log`
- `BPFtrace_Unsafe_Option_Usage_attack91.log`
- `BPFtrace_Unsafe_Option_Usage_attack92.log`
- `BPFtrace_Unsafe_Option_Usage_attack93.log`
- `BPFtrace_Unsafe_Option_Usage_attack94.log`
- `BPFtrace_Unsafe_Option_Usage_attack95.log`
- `BPFtrace_Unsafe_Option_Usage_attack96.log`
- `BPFtrace_Unsafe_Option_Usage_attack97.log`
- `BPFtrace_Unsafe_Option_Usage_attack98.log`
- `BPFtrace_Unsafe_Option_Usage_attack99.log`

---

### Shell Execution via Find - Linux

**Directory:** `find_shell_execution`

**Sigma Rule ID:** `6adfbf8f-52be-4444-9bac-81b539624146`

**Event Counts:**
- Total: 352
- Match Events: 153
- Evasion Events: 199

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 217, 218, 220, 221, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360

**Log Files:**
- `Shell_Execution_via_Find_attack1.log`
- `Shell_Execution_via_Find_attack10.log`
- `Shell_Execution_via_Find_attack100.log`
- `Shell_Execution_via_Find_attack102.log`
- `Shell_Execution_via_Find_attack103.log`
- `Shell_Execution_via_Find_attack104.log`
- `Shell_Execution_via_Find_attack105.log`
- `Shell_Execution_via_Find_attack106.log`
- `Shell_Execution_via_Find_attack107.log`
- `Shell_Execution_via_Find_attack108.log`
- `Shell_Execution_via_Find_attack109.log`
- `Shell_Execution_via_Find_attack11.log`
- `Shell_Execution_via_Find_attack110.log`
- `Shell_Execution_via_Find_attack111.log`
- `Shell_Execution_via_Find_attack112.log`
- `Shell_Execution_via_Find_attack113.log`
- `Shell_Execution_via_Find_attack114.log`
- `Shell_Execution_via_Find_attack115.log`
- `Shell_Execution_via_Find_attack116.log`
- `Shell_Execution_via_Find_attack117.log`
- `Shell_Execution_via_Find_attack118.log`
- `Shell_Execution_via_Find_attack119.log`
- `Shell_Execution_via_Find_attack12.log`
- `Shell_Execution_via_Find_attack120.log`
- `Shell_Execution_via_Find_attack121.log`
- `Shell_Execution_via_Find_attack122.log`
- `Shell_Execution_via_Find_attack123.log`
- `Shell_Execution_via_Find_attack124.log`
- `Shell_Execution_via_Find_attack125.log`
- `Shell_Execution_via_Find_attack126.log`
- `Shell_Execution_via_Find_attack127.log`
- `Shell_Execution_via_Find_attack128.log`
- `Shell_Execution_via_Find_attack129.log`
- `Shell_Execution_via_Find_attack13.log`
- `Shell_Execution_via_Find_attack130.log`
- `Shell_Execution_via_Find_attack131.log`
- `Shell_Execution_via_Find_attack132.log`
- `Shell_Execution_via_Find_attack133.log`
- `Shell_Execution_via_Find_attack134.log`
- `Shell_Execution_via_Find_attack135.log`
- `Shell_Execution_via_Find_attack136.log`
- `Shell_Execution_via_Find_attack137.log`
- `Shell_Execution_via_Find_attack138.log`
- `Shell_Execution_via_Find_attack139.log`
- `Shell_Execution_via_Find_attack14.log`
- `Shell_Execution_via_Find_attack140.log`
- `Shell_Execution_via_Find_attack141.log`
- `Shell_Execution_via_Find_attack142.log`
- `Shell_Execution_via_Find_attack143.log`
- `Shell_Execution_via_Find_attack144.log`
- `Shell_Execution_via_Find_attack145.log`
- `Shell_Execution_via_Find_attack146.log`
- `Shell_Execution_via_Find_attack147.log`
- `Shell_Execution_via_Find_attack148.log`
- `Shell_Execution_via_Find_attack149.log`
- `Shell_Execution_via_Find_attack15.log`
- `Shell_Execution_via_Find_attack150.log`
- `Shell_Execution_via_Find_attack151.log`
- `Shell_Execution_via_Find_attack152.log`
- `Shell_Execution_via_Find_attack153.log`
- `Shell_Execution_via_Find_attack154.log`
- `Shell_Execution_via_Find_attack155.log`
- `Shell_Execution_via_Find_attack156.log`
- `Shell_Execution_via_Find_attack157.log`
- `Shell_Execution_via_Find_attack158.log`
- `Shell_Execution_via_Find_attack159.log`
- `Shell_Execution_via_Find_attack16.log`
- `Shell_Execution_via_Find_attack160.log`
- `Shell_Execution_via_Find_attack161.log`
- `Shell_Execution_via_Find_attack162.log`
- `Shell_Execution_via_Find_attack163.log`
- `Shell_Execution_via_Find_attack164.log`
- `Shell_Execution_via_Find_attack165.log`
- `Shell_Execution_via_Find_attack166.log`
- `Shell_Execution_via_Find_attack167.log`
- `Shell_Execution_via_Find_attack168.log`
- `Shell_Execution_via_Find_attack169.log`
- `Shell_Execution_via_Find_attack17.log`
- `Shell_Execution_via_Find_attack170.log`
- `Shell_Execution_via_Find_attack171.log`
- `Shell_Execution_via_Find_attack172.log`
- `Shell_Execution_via_Find_attack173.log`
- `Shell_Execution_via_Find_attack174.log`
- `Shell_Execution_via_Find_attack175.log`
- `Shell_Execution_via_Find_attack176.log`
- `Shell_Execution_via_Find_attack177.log`
- `Shell_Execution_via_Find_attack178.log`
- `Shell_Execution_via_Find_attack179.log`
- `Shell_Execution_via_Find_attack18.log`
- `Shell_Execution_via_Find_attack180.log`
- `Shell_Execution_via_Find_attack181.log`
- `Shell_Execution_via_Find_attack182.log`
- `Shell_Execution_via_Find_attack183.log`
- `Shell_Execution_via_Find_attack184.log`
- `Shell_Execution_via_Find_attack185.log`
- `Shell_Execution_via_Find_attack186.log`
- `Shell_Execution_via_Find_attack189.log`
- `Shell_Execution_via_Find_attack19.log`
- `Shell_Execution_via_Find_attack190.log`
- `Shell_Execution_via_Find_attack191.log`
- `Shell_Execution_via_Find_attack192.log`
- `Shell_Execution_via_Find_attack193.log`
- `Shell_Execution_via_Find_attack194.log`
- `Shell_Execution_via_Find_attack195.log`
- `Shell_Execution_via_Find_attack196.log`
- `Shell_Execution_via_Find_attack197.log`
- `Shell_Execution_via_Find_attack198.log`
- `Shell_Execution_via_Find_attack199.log`
- `Shell_Execution_via_Find_attack2.log`
- `Shell_Execution_via_Find_attack20.log`
- `Shell_Execution_via_Find_attack200.log`
- `Shell_Execution_via_Find_attack201.log`
- `Shell_Execution_via_Find_attack202.log`
- `Shell_Execution_via_Find_attack203.log`
- `Shell_Execution_via_Find_attack205.log`
- `Shell_Execution_via_Find_attack206.log`
- `Shell_Execution_via_Find_attack207.log`
- `Shell_Execution_via_Find_attack208.log`
- `Shell_Execution_via_Find_attack209.log`
- `Shell_Execution_via_Find_attack21.log`
- `Shell_Execution_via_Find_attack210.log`
- `Shell_Execution_via_Find_attack211.log`
- `Shell_Execution_via_Find_attack212.log`
- `Shell_Execution_via_Find_attack213.log`
- `Shell_Execution_via_Find_attack214.log`
- `Shell_Execution_via_Find_attack215.log`
- `Shell_Execution_via_Find_attack217.log`
- `Shell_Execution_via_Find_attack218.log`
- `Shell_Execution_via_Find_attack22.log`
- `Shell_Execution_via_Find_attack220.log`
- `Shell_Execution_via_Find_attack221.log`
- `Shell_Execution_via_Find_attack223.log`
- `Shell_Execution_via_Find_attack224.log`
- `Shell_Execution_via_Find_attack225.log`
- `Shell_Execution_via_Find_attack226.log`
- `Shell_Execution_via_Find_attack227.log`
- `Shell_Execution_via_Find_attack228.log`
- `Shell_Execution_via_Find_attack229.log`
- `Shell_Execution_via_Find_attack23.log`
- `Shell_Execution_via_Find_attack230.log`
- `Shell_Execution_via_Find_attack231.log`
- `Shell_Execution_via_Find_attack232.log`
- `Shell_Execution_via_Find_attack233.log`
- `Shell_Execution_via_Find_attack234.log`
- `Shell_Execution_via_Find_attack235.log`
- `Shell_Execution_via_Find_attack236.log`
- `Shell_Execution_via_Find_attack237.log`
- `Shell_Execution_via_Find_attack238.log`
- `Shell_Execution_via_Find_attack239.log`
- `Shell_Execution_via_Find_attack24.log`
- `Shell_Execution_via_Find_attack240.log`
- `Shell_Execution_via_Find_attack241.log`
- `Shell_Execution_via_Find_attack242.log`
- `Shell_Execution_via_Find_attack243.log`
- `Shell_Execution_via_Find_attack244.log`
- `Shell_Execution_via_Find_attack245.log`
- `Shell_Execution_via_Find_attack246.log`
- `Shell_Execution_via_Find_attack247.log`
- `Shell_Execution_via_Find_attack248.log`
- `Shell_Execution_via_Find_attack249.log`
- `Shell_Execution_via_Find_attack25.log`
- `Shell_Execution_via_Find_attack250.log`
- `Shell_Execution_via_Find_attack251.log`
- `Shell_Execution_via_Find_attack252.log`
- `Shell_Execution_via_Find_attack253.log`
- `Shell_Execution_via_Find_attack254.log`
- `Shell_Execution_via_Find_attack255.log`
- `Shell_Execution_via_Find_attack256.log`
- `Shell_Execution_via_Find_attack257.log`
- `Shell_Execution_via_Find_attack258.log`
- `Shell_Execution_via_Find_attack259.log`
- `Shell_Execution_via_Find_attack26.log`
- `Shell_Execution_via_Find_attack260.log`
- `Shell_Execution_via_Find_attack261.log`
- `Shell_Execution_via_Find_attack262.log`
- `Shell_Execution_via_Find_attack263.log`
- `Shell_Execution_via_Find_attack264.log`
- `Shell_Execution_via_Find_attack265.log`
- `Shell_Execution_via_Find_attack266.log`
- `Shell_Execution_via_Find_attack267.log`
- `Shell_Execution_via_Find_attack268.log`
- `Shell_Execution_via_Find_attack269.log`
- `Shell_Execution_via_Find_attack27.log`
- `Shell_Execution_via_Find_attack270.log`
- `Shell_Execution_via_Find_attack271.log`
- `Shell_Execution_via_Find_attack272.log`
- `Shell_Execution_via_Find_attack273.log`
- `Shell_Execution_via_Find_attack274.log`
- `Shell_Execution_via_Find_attack275.log`
- `Shell_Execution_via_Find_attack276.log`
- `Shell_Execution_via_Find_attack277.log`
- `Shell_Execution_via_Find_attack278.log`
- `Shell_Execution_via_Find_attack279.log`
- `Shell_Execution_via_Find_attack28.log`
- `Shell_Execution_via_Find_attack280.log`
- `Shell_Execution_via_Find_attack281.log`
- `Shell_Execution_via_Find_attack282.log`
- `Shell_Execution_via_Find_attack283.log`
- `Shell_Execution_via_Find_attack284.log`
- `Shell_Execution_via_Find_attack285.log`
- `Shell_Execution_via_Find_attack286.log`
- `Shell_Execution_via_Find_attack287.log`
- `Shell_Execution_via_Find_attack288.log`
- `Shell_Execution_via_Find_attack289.log`
- `Shell_Execution_via_Find_attack29.log`
- `Shell_Execution_via_Find_attack290.log`
- `Shell_Execution_via_Find_attack291.log`
- `Shell_Execution_via_Find_attack292.log`
- `Shell_Execution_via_Find_attack293.log`
- `Shell_Execution_via_Find_attack294.log`
- `Shell_Execution_via_Find_attack295.log`
- `Shell_Execution_via_Find_attack296.log`
- `Shell_Execution_via_Find_attack297.log`
- `Shell_Execution_via_Find_attack298.log`
- `Shell_Execution_via_Find_attack299.log`
- `Shell_Execution_via_Find_attack3.log`
- `Shell_Execution_via_Find_attack30.log`
- `Shell_Execution_via_Find_attack300.log`
- `Shell_Execution_via_Find_attack301.log`
- `Shell_Execution_via_Find_attack302.log`
- `Shell_Execution_via_Find_attack303.log`
- `Shell_Execution_via_Find_attack304.log`
- `Shell_Execution_via_Find_attack305.log`
- `Shell_Execution_via_Find_attack306.log`
- `Shell_Execution_via_Find_attack307.log`
- `Shell_Execution_via_Find_attack308.log`
- `Shell_Execution_via_Find_attack309.log`
- `Shell_Execution_via_Find_attack31.log`
- `Shell_Execution_via_Find_attack310.log`
- `Shell_Execution_via_Find_attack311.log`
- `Shell_Execution_via_Find_attack312.log`
- `Shell_Execution_via_Find_attack313.log`
- `Shell_Execution_via_Find_attack314.log`
- `Shell_Execution_via_Find_attack315.log`
- `Shell_Execution_via_Find_attack316.log`
- `Shell_Execution_via_Find_attack317.log`
- `Shell_Execution_via_Find_attack318.log`
- `Shell_Execution_via_Find_attack319.log`
- `Shell_Execution_via_Find_attack32.log`
- `Shell_Execution_via_Find_attack320.log`
- `Shell_Execution_via_Find_attack321.log`
- `Shell_Execution_via_Find_attack322.log`
- `Shell_Execution_via_Find_attack323.log`
- `Shell_Execution_via_Find_attack324.log`
- `Shell_Execution_via_Find_attack325.log`
- `Shell_Execution_via_Find_attack326.log`
- `Shell_Execution_via_Find_attack327.log`
- `Shell_Execution_via_Find_attack328.log`
- `Shell_Execution_via_Find_attack329.log`
- `Shell_Execution_via_Find_attack33.log`
- `Shell_Execution_via_Find_attack330.log`
- `Shell_Execution_via_Find_attack331.log`
- `Shell_Execution_via_Find_attack332.log`
- `Shell_Execution_via_Find_attack333.log`
- `Shell_Execution_via_Find_attack334.log`
- `Shell_Execution_via_Find_attack335.log`
- `Shell_Execution_via_Find_attack336.log`
- `Shell_Execution_via_Find_attack337.log`
- `Shell_Execution_via_Find_attack338.log`
- `Shell_Execution_via_Find_attack339.log`
- `Shell_Execution_via_Find_attack34.log`
- `Shell_Execution_via_Find_attack340.log`
- `Shell_Execution_via_Find_attack341.log`
- `Shell_Execution_via_Find_attack342.log`
- `Shell_Execution_via_Find_attack343.log`
- `Shell_Execution_via_Find_attack344.log`
- `Shell_Execution_via_Find_attack345.log`
- `Shell_Execution_via_Find_attack346.log`
- `Shell_Execution_via_Find_attack347.log`
- `Shell_Execution_via_Find_attack348.log`
- `Shell_Execution_via_Find_attack349.log`
- `Shell_Execution_via_Find_attack35.log`
- `Shell_Execution_via_Find_attack350.log`
- `Shell_Execution_via_Find_attack351.log`
- `Shell_Execution_via_Find_attack352.log`
- `Shell_Execution_via_Find_attack353.log`
- `Shell_Execution_via_Find_attack354.log`
- `Shell_Execution_via_Find_attack355.log`
- `Shell_Execution_via_Find_attack356.log`
- `Shell_Execution_via_Find_attack357.log`
- `Shell_Execution_via_Find_attack358.log`
- `Shell_Execution_via_Find_attack359.log`
- `Shell_Execution_via_Find_attack36.log`
- `Shell_Execution_via_Find_attack360.log`
- `Shell_Execution_via_Find_attack37.log`
- `Shell_Execution_via_Find_attack38.log`
- `Shell_Execution_via_Find_attack39.log`
- `Shell_Execution_via_Find_attack4.log`
- `Shell_Execution_via_Find_attack40.log`
- `Shell_Execution_via_Find_attack41.log`
- `Shell_Execution_via_Find_attack42.log`
- `Shell_Execution_via_Find_attack43.log`
- `Shell_Execution_via_Find_attack44.log`
- `Shell_Execution_via_Find_attack45.log`
- `Shell_Execution_via_Find_attack46.log`
- `Shell_Execution_via_Find_attack48.log`
- `Shell_Execution_via_Find_attack49.log`
- `Shell_Execution_via_Find_attack5.log`
- `Shell_Execution_via_Find_attack50.log`
- `Shell_Execution_via_Find_attack51.log`
- `Shell_Execution_via_Find_attack52.log`
- `Shell_Execution_via_Find_attack53.log`
- `Shell_Execution_via_Find_attack54.log`
- `Shell_Execution_via_Find_attack55.log`
- `Shell_Execution_via_Find_attack56.log`
- `Shell_Execution_via_Find_attack57.log`
- `Shell_Execution_via_Find_attack58.log`
- `Shell_Execution_via_Find_attack59.log`
- `Shell_Execution_via_Find_attack6.log`
- `Shell_Execution_via_Find_attack60.log`
- `Shell_Execution_via_Find_attack61.log`
- `Shell_Execution_via_Find_attack62.log`
- `Shell_Execution_via_Find_attack63.log`
- `Shell_Execution_via_Find_attack64.log`
- `Shell_Execution_via_Find_attack65.log`
- `Shell_Execution_via_Find_attack66.log`
- `Shell_Execution_via_Find_attack67.log`
- `Shell_Execution_via_Find_attack68.log`
- `Shell_Execution_via_Find_attack69.log`
- `Shell_Execution_via_Find_attack7.log`
- `Shell_Execution_via_Find_attack70.log`
- `Shell_Execution_via_Find_attack71.log`
- `Shell_Execution_via_Find_attack72.log`
- `Shell_Execution_via_Find_attack73.log`
- `Shell_Execution_via_Find_attack74.log`
- `Shell_Execution_via_Find_attack75.log`
- `Shell_Execution_via_Find_attack76.log`
- `Shell_Execution_via_Find_attack77.log`
- `Shell_Execution_via_Find_attack78.log`
- `Shell_Execution_via_Find_attack79.log`
- `Shell_Execution_via_Find_attack8.log`
- `Shell_Execution_via_Find_attack80.log`
- `Shell_Execution_via_Find_attack81.log`
- `Shell_Execution_via_Find_attack82.log`
- `Shell_Execution_via_Find_attack83.log`
- `Shell_Execution_via_Find_attack84.log`
- `Shell_Execution_via_Find_attack85.log`
- `Shell_Execution_via_Find_attack86.log`
- `Shell_Execution_via_Find_attack87.log`
- `Shell_Execution_via_Find_attack88.log`
- `Shell_Execution_via_Find_attack89.log`
- `Shell_Execution_via_Find_attack9.log`
- `Shell_Execution_via_Find_attack90.log`
- `Shell_Execution_via_Find_attack91.log`
- `Shell_Execution_via_Find_attack92.log`
- `Shell_Execution_via_Find_attack93.log`
- `Shell_Execution_via_Find_attack94.log`
- `Shell_Execution_via_Find_attack95.log`
- `Shell_Execution_via_Find_attack96.log`
- `Shell_Execution_via_Find_attack97.log`
- `Shell_Execution_via_Find_attack98.log`
- `Shell_Execution_via_Find_attack99.log`

---

### Remove Scheduled Cron Task/Job

**Directory:** `crontab_removal`

**Sigma Rule ID:** `c2e234de-03a3-41e1-b39a-1e56dc17ba67`

**Event Counts:**
- Total: 334
- Match Events: 134
- Evasion Events: 200

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 83, 85, 86, 87, 88, 90, 91, 92, 93, 94, 95, 96, 97, 98, 100, 101, 102, 103, 105, 107, 108, 110, 111, 112, 113, 115, 116, 117, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 157, 159, 160, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 246, 247, 248, 250, 251, 252, 253, 254, 256, 257, 261, 262, 263, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 276, 277, 279, 280, 281, 282, 283, 284, 286, 287, 288, 289, 290, 292, 293, 294, 295, 296, 297, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360

**Log Files:**
- `Remove_Scheduled_Cron_Task_attack1.log`
- `Remove_Scheduled_Cron_Task_attack10.log`
- `Remove_Scheduled_Cron_Task_attack100.log`
- `Remove_Scheduled_Cron_Task_attack101.log`
- `Remove_Scheduled_Cron_Task_attack102.log`
- `Remove_Scheduled_Cron_Task_attack103.log`
- `Remove_Scheduled_Cron_Task_attack105.log`
- `Remove_Scheduled_Cron_Task_attack107.log`
- `Remove_Scheduled_Cron_Task_attack108.log`
- `Remove_Scheduled_Cron_Task_attack11.log`
- `Remove_Scheduled_Cron_Task_attack110.log`
- `Remove_Scheduled_Cron_Task_attack111.log`
- `Remove_Scheduled_Cron_Task_attack112.log`
- `Remove_Scheduled_Cron_Task_attack113.log`
- `Remove_Scheduled_Cron_Task_attack115.log`
- `Remove_Scheduled_Cron_Task_attack116.log`
- `Remove_Scheduled_Cron_Task_attack117.log`
- `Remove_Scheduled_Cron_Task_attack12.log`
- `Remove_Scheduled_Cron_Task_attack120.log`
- `Remove_Scheduled_Cron_Task_attack121.log`
- `Remove_Scheduled_Cron_Task_attack122.log`
- `Remove_Scheduled_Cron_Task_attack123.log`
- `Remove_Scheduled_Cron_Task_attack124.log`
- `Remove_Scheduled_Cron_Task_attack125.log`
- `Remove_Scheduled_Cron_Task_attack126.log`
- `Remove_Scheduled_Cron_Task_attack127.log`
- `Remove_Scheduled_Cron_Task_attack128.log`
- `Remove_Scheduled_Cron_Task_attack129.log`
- `Remove_Scheduled_Cron_Task_attack13.log`
- `Remove_Scheduled_Cron_Task_attack130.log`
- `Remove_Scheduled_Cron_Task_attack131.log`
- `Remove_Scheduled_Cron_Task_attack132.log`
- `Remove_Scheduled_Cron_Task_attack133.log`
- `Remove_Scheduled_Cron_Task_attack134.log`
- `Remove_Scheduled_Cron_Task_attack135.log`
- `Remove_Scheduled_Cron_Task_attack136.log`
- `Remove_Scheduled_Cron_Task_attack137.log`
- `Remove_Scheduled_Cron_Task_attack138.log`
- `Remove_Scheduled_Cron_Task_attack139.log`
- `Remove_Scheduled_Cron_Task_attack14.log`
- `Remove_Scheduled_Cron_Task_attack140.log`
- `Remove_Scheduled_Cron_Task_attack141.log`
- `Remove_Scheduled_Cron_Task_attack142.log`
- `Remove_Scheduled_Cron_Task_attack143.log`
- `Remove_Scheduled_Cron_Task_attack144.log`
- `Remove_Scheduled_Cron_Task_attack145.log`
- `Remove_Scheduled_Cron_Task_attack146.log`
- `Remove_Scheduled_Cron_Task_attack147.log`
- `Remove_Scheduled_Cron_Task_attack148.log`
- `Remove_Scheduled_Cron_Task_attack149.log`
- `Remove_Scheduled_Cron_Task_attack15.log`
- `Remove_Scheduled_Cron_Task_attack150.log`
- `Remove_Scheduled_Cron_Task_attack151.log`
- `Remove_Scheduled_Cron_Task_attack152.log`
- `Remove_Scheduled_Cron_Task_attack153.log`
- `Remove_Scheduled_Cron_Task_attack154.log`
- `Remove_Scheduled_Cron_Task_attack155.log`
- `Remove_Scheduled_Cron_Task_attack157.log`
- `Remove_Scheduled_Cron_Task_attack159.log`
- `Remove_Scheduled_Cron_Task_attack16.log`
- `Remove_Scheduled_Cron_Task_attack160.log`
- `Remove_Scheduled_Cron_Task_attack162.log`
- `Remove_Scheduled_Cron_Task_attack163.log`
- `Remove_Scheduled_Cron_Task_attack164.log`
- `Remove_Scheduled_Cron_Task_attack165.log`
- `Remove_Scheduled_Cron_Task_attack166.log`
- `Remove_Scheduled_Cron_Task_attack167.log`
- `Remove_Scheduled_Cron_Task_attack168.log`
- `Remove_Scheduled_Cron_Task_attack169.log`
- `Remove_Scheduled_Cron_Task_attack17.log`
- `Remove_Scheduled_Cron_Task_attack170.log`
- `Remove_Scheduled_Cron_Task_attack171.log`
- `Remove_Scheduled_Cron_Task_attack172.log`
- `Remove_Scheduled_Cron_Task_attack173.log`
- `Remove_Scheduled_Cron_Task_attack174.log`
- `Remove_Scheduled_Cron_Task_attack175.log`
- `Remove_Scheduled_Cron_Task_attack176.log`
- `Remove_Scheduled_Cron_Task_attack177.log`
- `Remove_Scheduled_Cron_Task_attack178.log`
- `Remove_Scheduled_Cron_Task_attack179.log`
- `Remove_Scheduled_Cron_Task_attack18.log`
- `Remove_Scheduled_Cron_Task_attack180.log`
- `Remove_Scheduled_Cron_Task_attack182.log`
- `Remove_Scheduled_Cron_Task_attack183.log`
- `Remove_Scheduled_Cron_Task_attack184.log`
- `Remove_Scheduled_Cron_Task_attack185.log`
- `Remove_Scheduled_Cron_Task_attack186.log`
- `Remove_Scheduled_Cron_Task_attack187.log`
- `Remove_Scheduled_Cron_Task_attack188.log`
- `Remove_Scheduled_Cron_Task_attack189.log`
- `Remove_Scheduled_Cron_Task_attack19.log`
- `Remove_Scheduled_Cron_Task_attack190.log`
- `Remove_Scheduled_Cron_Task_attack191.log`
- `Remove_Scheduled_Cron_Task_attack192.log`
- `Remove_Scheduled_Cron_Task_attack193.log`
- `Remove_Scheduled_Cron_Task_attack194.log`
- `Remove_Scheduled_Cron_Task_attack195.log`
- `Remove_Scheduled_Cron_Task_attack196.log`
- `Remove_Scheduled_Cron_Task_attack197.log`
- `Remove_Scheduled_Cron_Task_attack198.log`
- `Remove_Scheduled_Cron_Task_attack199.log`
- `Remove_Scheduled_Cron_Task_attack2.log`
- `Remove_Scheduled_Cron_Task_attack20.log`
- `Remove_Scheduled_Cron_Task_attack200.log`
- `Remove_Scheduled_Cron_Task_attack201.log`
- `Remove_Scheduled_Cron_Task_attack202.log`
- `Remove_Scheduled_Cron_Task_attack203.log`
- `Remove_Scheduled_Cron_Task_attack204.log`
- `Remove_Scheduled_Cron_Task_attack205.log`
- `Remove_Scheduled_Cron_Task_attack206.log`
- `Remove_Scheduled_Cron_Task_attack207.log`
- `Remove_Scheduled_Cron_Task_attack208.log`
- `Remove_Scheduled_Cron_Task_attack209.log`
- `Remove_Scheduled_Cron_Task_attack21.log`
- `Remove_Scheduled_Cron_Task_attack210.log`
- `Remove_Scheduled_Cron_Task_attack211.log`
- `Remove_Scheduled_Cron_Task_attack212.log`
- `Remove_Scheduled_Cron_Task_attack213.log`
- `Remove_Scheduled_Cron_Task_attack214.log`
- `Remove_Scheduled_Cron_Task_attack215.log`
- `Remove_Scheduled_Cron_Task_attack216.log`
- `Remove_Scheduled_Cron_Task_attack217.log`
- `Remove_Scheduled_Cron_Task_attack218.log`
- `Remove_Scheduled_Cron_Task_attack219.log`
- `Remove_Scheduled_Cron_Task_attack22.log`
- `Remove_Scheduled_Cron_Task_attack220.log`
- `Remove_Scheduled_Cron_Task_attack221.log`
- `Remove_Scheduled_Cron_Task_attack222.log`
- `Remove_Scheduled_Cron_Task_attack223.log`
- `Remove_Scheduled_Cron_Task_attack224.log`
- `Remove_Scheduled_Cron_Task_attack225.log`
- `Remove_Scheduled_Cron_Task_attack226.log`
- `Remove_Scheduled_Cron_Task_attack227.log`
- `Remove_Scheduled_Cron_Task_attack228.log`
- `Remove_Scheduled_Cron_Task_attack229.log`
- `Remove_Scheduled_Cron_Task_attack23.log`
- `Remove_Scheduled_Cron_Task_attack230.log`
- `Remove_Scheduled_Cron_Task_attack231.log`
- `Remove_Scheduled_Cron_Task_attack232.log`
- `Remove_Scheduled_Cron_Task_attack233.log`
- `Remove_Scheduled_Cron_Task_attack234.log`
- `Remove_Scheduled_Cron_Task_attack235.log`
- `Remove_Scheduled_Cron_Task_attack236.log`
- `Remove_Scheduled_Cron_Task_attack237.log`
- `Remove_Scheduled_Cron_Task_attack238.log`
- `Remove_Scheduled_Cron_Task_attack239.log`
- `Remove_Scheduled_Cron_Task_attack24.log`
- `Remove_Scheduled_Cron_Task_attack240.log`
- `Remove_Scheduled_Cron_Task_attack241.log`
- `Remove_Scheduled_Cron_Task_attack242.log`
- `Remove_Scheduled_Cron_Task_attack243.log`
- `Remove_Scheduled_Cron_Task_attack244.log`
- `Remove_Scheduled_Cron_Task_attack246.log`
- `Remove_Scheduled_Cron_Task_attack247.log`
- `Remove_Scheduled_Cron_Task_attack248.log`
- `Remove_Scheduled_Cron_Task_attack25.log`
- `Remove_Scheduled_Cron_Task_attack250.log`
- `Remove_Scheduled_Cron_Task_attack251.log`
- `Remove_Scheduled_Cron_Task_attack252.log`
- `Remove_Scheduled_Cron_Task_attack253.log`
- `Remove_Scheduled_Cron_Task_attack254.log`
- `Remove_Scheduled_Cron_Task_attack256.log`
- `Remove_Scheduled_Cron_Task_attack257.log`
- `Remove_Scheduled_Cron_Task_attack26.log`
- `Remove_Scheduled_Cron_Task_attack261.log`
- `Remove_Scheduled_Cron_Task_attack262.log`
- `Remove_Scheduled_Cron_Task_attack263.log`
- `Remove_Scheduled_Cron_Task_attack265.log`
- `Remove_Scheduled_Cron_Task_attack266.log`
- `Remove_Scheduled_Cron_Task_attack267.log`
- `Remove_Scheduled_Cron_Task_attack268.log`
- `Remove_Scheduled_Cron_Task_attack269.log`
- `Remove_Scheduled_Cron_Task_attack27.log`
- `Remove_Scheduled_Cron_Task_attack270.log`
- `Remove_Scheduled_Cron_Task_attack271.log`
- `Remove_Scheduled_Cron_Task_attack272.log`
- `Remove_Scheduled_Cron_Task_attack273.log`
- `Remove_Scheduled_Cron_Task_attack274.log`
- `Remove_Scheduled_Cron_Task_attack276.log`
- `Remove_Scheduled_Cron_Task_attack277.log`
- `Remove_Scheduled_Cron_Task_attack279.log`
- `Remove_Scheduled_Cron_Task_attack28.log`
- `Remove_Scheduled_Cron_Task_attack280.log`
- `Remove_Scheduled_Cron_Task_attack281.log`
- `Remove_Scheduled_Cron_Task_attack282.log`
- `Remove_Scheduled_Cron_Task_attack283.log`
- `Remove_Scheduled_Cron_Task_attack284.log`
- `Remove_Scheduled_Cron_Task_attack286.log`
- `Remove_Scheduled_Cron_Task_attack287.log`
- `Remove_Scheduled_Cron_Task_attack288.log`
- `Remove_Scheduled_Cron_Task_attack289.log`
- `Remove_Scheduled_Cron_Task_attack29.log`
- `Remove_Scheduled_Cron_Task_attack290.log`
- `Remove_Scheduled_Cron_Task_attack292.log`
- `Remove_Scheduled_Cron_Task_attack293.log`
- `Remove_Scheduled_Cron_Task_attack294.log`
- `Remove_Scheduled_Cron_Task_attack295.log`
- `Remove_Scheduled_Cron_Task_attack296.log`
- `Remove_Scheduled_Cron_Task_attack297.log`
- `Remove_Scheduled_Cron_Task_attack299.log`
- `Remove_Scheduled_Cron_Task_attack3.log`
- `Remove_Scheduled_Cron_Task_attack30.log`
- `Remove_Scheduled_Cron_Task_attack300.log`
- `Remove_Scheduled_Cron_Task_attack301.log`
- `Remove_Scheduled_Cron_Task_attack302.log`
- `Remove_Scheduled_Cron_Task_attack303.log`
- `Remove_Scheduled_Cron_Task_attack304.log`
- `Remove_Scheduled_Cron_Task_attack305.log`
- `Remove_Scheduled_Cron_Task_attack306.log`
- `Remove_Scheduled_Cron_Task_attack307.log`
- `Remove_Scheduled_Cron_Task_attack308.log`
- `Remove_Scheduled_Cron_Task_attack309.log`
- `Remove_Scheduled_Cron_Task_attack31.log`
- `Remove_Scheduled_Cron_Task_attack310.log`
- `Remove_Scheduled_Cron_Task_attack311.log`
- `Remove_Scheduled_Cron_Task_attack312.log`
- `Remove_Scheduled_Cron_Task_attack313.log`
- `Remove_Scheduled_Cron_Task_attack314.log`
- `Remove_Scheduled_Cron_Task_attack315.log`
- `Remove_Scheduled_Cron_Task_attack316.log`
- `Remove_Scheduled_Cron_Task_attack317.log`
- `Remove_Scheduled_Cron_Task_attack318.log`
- `Remove_Scheduled_Cron_Task_attack319.log`
- `Remove_Scheduled_Cron_Task_attack32.log`
- `Remove_Scheduled_Cron_Task_attack320.log`
- `Remove_Scheduled_Cron_Task_attack321.log`
- `Remove_Scheduled_Cron_Task_attack322.log`
- `Remove_Scheduled_Cron_Task_attack323.log`
- `Remove_Scheduled_Cron_Task_attack324.log`
- `Remove_Scheduled_Cron_Task_attack325.log`
- `Remove_Scheduled_Cron_Task_attack326.log`
- `Remove_Scheduled_Cron_Task_attack327.log`
- `Remove_Scheduled_Cron_Task_attack328.log`
- `Remove_Scheduled_Cron_Task_attack329.log`
- `Remove_Scheduled_Cron_Task_attack33.log`
- `Remove_Scheduled_Cron_Task_attack330.log`
- `Remove_Scheduled_Cron_Task_attack331.log`
- `Remove_Scheduled_Cron_Task_attack332.log`
- `Remove_Scheduled_Cron_Task_attack333.log`
- `Remove_Scheduled_Cron_Task_attack334.log`
- `Remove_Scheduled_Cron_Task_attack335.log`
- `Remove_Scheduled_Cron_Task_attack336.log`
- `Remove_Scheduled_Cron_Task_attack337.log`
- `Remove_Scheduled_Cron_Task_attack338.log`
- `Remove_Scheduled_Cron_Task_attack339.log`
- `Remove_Scheduled_Cron_Task_attack34.log`
- `Remove_Scheduled_Cron_Task_attack340.log`
- `Remove_Scheduled_Cron_Task_attack341.log`
- `Remove_Scheduled_Cron_Task_attack342.log`
- `Remove_Scheduled_Cron_Task_attack343.log`
- `Remove_Scheduled_Cron_Task_attack344.log`
- `Remove_Scheduled_Cron_Task_attack345.log`
- `Remove_Scheduled_Cron_Task_attack346.log`
- `Remove_Scheduled_Cron_Task_attack347.log`
- `Remove_Scheduled_Cron_Task_attack348.log`
- `Remove_Scheduled_Cron_Task_attack349.log`
- `Remove_Scheduled_Cron_Task_attack35.log`
- `Remove_Scheduled_Cron_Task_attack350.log`
- `Remove_Scheduled_Cron_Task_attack351.log`
- `Remove_Scheduled_Cron_Task_attack352.log`
- `Remove_Scheduled_Cron_Task_attack353.log`
- `Remove_Scheduled_Cron_Task_attack354.log`
- `Remove_Scheduled_Cron_Task_attack355.log`
- `Remove_Scheduled_Cron_Task_attack356.log`
- `Remove_Scheduled_Cron_Task_attack357.log`
- `Remove_Scheduled_Cron_Task_attack358.log`
- `Remove_Scheduled_Cron_Task_attack359.log`
- `Remove_Scheduled_Cron_Task_attack36.log`
- `Remove_Scheduled_Cron_Task_attack360.log`
- `Remove_Scheduled_Cron_Task_attack37.log`
- `Remove_Scheduled_Cron_Task_attack38.log`
- `Remove_Scheduled_Cron_Task_attack39.log`
- `Remove_Scheduled_Cron_Task_attack4.log`
- `Remove_Scheduled_Cron_Task_attack40.log`
- `Remove_Scheduled_Cron_Task_attack41.log`
- `Remove_Scheduled_Cron_Task_attack42.log`
- `Remove_Scheduled_Cron_Task_attack43.log`
- `Remove_Scheduled_Cron_Task_attack44.log`
- `Remove_Scheduled_Cron_Task_attack45.log`
- `Remove_Scheduled_Cron_Task_attack46.log`
- `Remove_Scheduled_Cron_Task_attack47.log`
- `Remove_Scheduled_Cron_Task_attack48.log`
- `Remove_Scheduled_Cron_Task_attack49.log`
- `Remove_Scheduled_Cron_Task_attack5.log`
- `Remove_Scheduled_Cron_Task_attack50.log`
- `Remove_Scheduled_Cron_Task_attack51.log`
- `Remove_Scheduled_Cron_Task_attack52.log`
- `Remove_Scheduled_Cron_Task_attack53.log`
- `Remove_Scheduled_Cron_Task_attack54.log`
- `Remove_Scheduled_Cron_Task_attack55.log`
- `Remove_Scheduled_Cron_Task_attack56.log`
- `Remove_Scheduled_Cron_Task_attack57.log`
- `Remove_Scheduled_Cron_Task_attack58.log`
- `Remove_Scheduled_Cron_Task_attack59.log`
- `Remove_Scheduled_Cron_Task_attack6.log`
- `Remove_Scheduled_Cron_Task_attack60.log`
- `Remove_Scheduled_Cron_Task_attack61.log`
- `Remove_Scheduled_Cron_Task_attack62.log`
- `Remove_Scheduled_Cron_Task_attack63.log`
- `Remove_Scheduled_Cron_Task_attack64.log`
- `Remove_Scheduled_Cron_Task_attack65.log`
- `Remove_Scheduled_Cron_Task_attack66.log`
- `Remove_Scheduled_Cron_Task_attack67.log`
- `Remove_Scheduled_Cron_Task_attack68.log`
- `Remove_Scheduled_Cron_Task_attack69.log`
- `Remove_Scheduled_Cron_Task_attack7.log`
- `Remove_Scheduled_Cron_Task_attack70.log`
- `Remove_Scheduled_Cron_Task_attack71.log`
- `Remove_Scheduled_Cron_Task_attack72.log`
- `Remove_Scheduled_Cron_Task_attack73.log`
- `Remove_Scheduled_Cron_Task_attack74.log`
- `Remove_Scheduled_Cron_Task_attack75.log`
- `Remove_Scheduled_Cron_Task_attack76.log`
- `Remove_Scheduled_Cron_Task_attack77.log`
- `Remove_Scheduled_Cron_Task_attack78.log`
- `Remove_Scheduled_Cron_Task_attack79.log`
- `Remove_Scheduled_Cron_Task_attack8.log`
- `Remove_Scheduled_Cron_Task_attack80.log`
- `Remove_Scheduled_Cron_Task_attack81.log`
- `Remove_Scheduled_Cron_Task_attack83.log`
- `Remove_Scheduled_Cron_Task_attack85.log`
- `Remove_Scheduled_Cron_Task_attack86.log`
- `Remove_Scheduled_Cron_Task_attack87.log`
- `Remove_Scheduled_Cron_Task_attack88.log`
- `Remove_Scheduled_Cron_Task_attack9.log`
- `Remove_Scheduled_Cron_Task_attack90.log`
- `Remove_Scheduled_Cron_Task_attack91.log`
- `Remove_Scheduled_Cron_Task_attack92.log`
- `Remove_Scheduled_Cron_Task_attack93.log`
- `Remove_Scheduled_Cron_Task_attack94.log`
- `Remove_Scheduled_Cron_Task_attack95.log`
- `Remove_Scheduled_Cron_Task_attack96.log`
- `Remove_Scheduled_Cron_Task_attack97.log`
- `Remove_Scheduled_Cron_Task_attack98.log`

---

### OMIGOD SCX RunAsProvider ExecuteShellCommand

**Directory:** `omigod_scx_runasprovider_executeshellcommand`

**Sigma Rule ID:** `21541900-27a9-4454-9c4c-3f0a4240344a`

**Event Counts:**
- Total: 311
- Match Events: 105
- Evasion Events: 206

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311

**Log Files:**
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack1.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack10.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack100.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack101.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack102.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack103.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack104.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack105.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack106.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack107.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack108.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack109.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack11.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack110.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack111.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack112.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack113.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack114.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack115.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack116.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack117.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack118.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack119.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack12.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack120.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack121.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack122.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack123.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack124.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack125.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack126.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack127.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack128.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack129.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack13.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack130.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack131.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack132.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack133.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack134.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack135.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack136.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack137.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack138.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack139.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack14.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack140.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack141.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack142.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack143.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack144.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack145.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack146.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack147.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack148.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack149.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack15.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack150.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack151.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack152.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack153.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack154.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack155.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack156.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack157.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack158.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack159.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack16.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack160.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack161.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack162.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack163.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack164.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack165.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack166.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack167.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack168.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack169.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack17.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack170.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack171.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack172.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack173.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack174.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack175.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack176.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack177.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack178.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack179.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack18.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack180.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack181.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack182.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack183.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack184.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack185.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack186.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack187.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack188.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack189.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack19.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack190.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack191.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack192.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack193.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack194.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack195.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack196.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack197.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack198.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack199.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack2.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack20.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack200.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack201.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack202.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack203.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack204.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack205.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack206.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack207.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack208.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack209.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack21.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack210.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack211.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack212.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack213.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack214.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack215.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack216.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack217.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack218.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack219.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack22.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack220.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack221.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack222.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack223.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack224.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack225.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack226.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack227.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack228.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack229.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack23.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack230.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack231.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack232.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack233.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack234.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack235.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack236.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack237.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack238.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack239.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack24.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack240.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack241.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack242.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack243.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack244.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack245.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack246.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack247.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack248.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack249.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack25.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack250.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack251.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack252.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack253.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack254.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack255.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack256.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack257.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack258.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack259.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack26.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack260.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack261.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack262.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack263.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack264.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack265.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack266.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack267.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack268.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack269.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack27.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack270.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack271.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack272.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack273.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack274.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack275.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack276.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack277.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack278.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack279.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack28.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack280.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack281.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack282.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack283.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack284.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack285.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack286.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack287.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack288.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack289.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack29.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack290.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack291.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack292.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack293.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack294.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack295.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack296.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack297.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack298.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack299.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack3.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack30.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack300.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack301.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack302.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack303.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack304.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack305.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack306.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack307.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack308.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack309.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack31.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack310.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack311.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack32.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack33.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack34.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack35.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack36.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack37.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack38.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack39.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack4.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack40.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack41.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack42.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack43.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack44.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack45.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack46.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack47.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack48.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack49.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack5.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack50.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack51.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack52.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack53.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack54.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack55.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack56.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack57.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack58.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack59.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack6.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack60.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack61.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack62.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack63.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack64.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack65.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack66.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack67.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack68.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack69.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack7.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack70.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack71.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack72.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack73.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack74.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack75.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack76.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack77.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack78.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack79.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack8.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack80.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack81.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack82.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack83.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack84.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack85.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack86.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack87.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack88.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack89.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack9.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack90.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack91.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack92.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack93.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack94.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack95.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack96.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack97.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack98.log`
- `OMIGOD_SCX_RunAsProvider_ExecuteShellCommand_attack99.log`

---

### OS Architecture Discovery Via Grep

**Directory:** `grep_os_arch_discovery`

**Sigma Rule ID:** `d27ab432-2199-483f-a297-03633c05bae6`

**Event Counts:**
- Total: 269
- Match Events: 59
- Evasion Events: 210

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269

**Log Files:**
- `OS_Architecture_Discovery_Via_Grep_attack1.log`
- `OS_Architecture_Discovery_Via_Grep_attack10.log`
- `OS_Architecture_Discovery_Via_Grep_attack100.log`
- `OS_Architecture_Discovery_Via_Grep_attack101.log`
- `OS_Architecture_Discovery_Via_Grep_attack102.log`
- `OS_Architecture_Discovery_Via_Grep_attack103.log`
- `OS_Architecture_Discovery_Via_Grep_attack104.log`
- `OS_Architecture_Discovery_Via_Grep_attack105.log`
- `OS_Architecture_Discovery_Via_Grep_attack106.log`
- `OS_Architecture_Discovery_Via_Grep_attack107.log`
- `OS_Architecture_Discovery_Via_Grep_attack108.log`
- `OS_Architecture_Discovery_Via_Grep_attack109.log`
- `OS_Architecture_Discovery_Via_Grep_attack11.log`
- `OS_Architecture_Discovery_Via_Grep_attack110.log`
- `OS_Architecture_Discovery_Via_Grep_attack111.log`
- `OS_Architecture_Discovery_Via_Grep_attack112.log`
- `OS_Architecture_Discovery_Via_Grep_attack113.log`
- `OS_Architecture_Discovery_Via_Grep_attack114.log`
- `OS_Architecture_Discovery_Via_Grep_attack115.log`
- `OS_Architecture_Discovery_Via_Grep_attack116.log`
- `OS_Architecture_Discovery_Via_Grep_attack117.log`
- `OS_Architecture_Discovery_Via_Grep_attack118.log`
- `OS_Architecture_Discovery_Via_Grep_attack119.log`
- `OS_Architecture_Discovery_Via_Grep_attack12.log`
- `OS_Architecture_Discovery_Via_Grep_attack120.log`
- `OS_Architecture_Discovery_Via_Grep_attack121.log`
- `OS_Architecture_Discovery_Via_Grep_attack122.log`
- `OS_Architecture_Discovery_Via_Grep_attack123.log`
- `OS_Architecture_Discovery_Via_Grep_attack124.log`
- `OS_Architecture_Discovery_Via_Grep_attack125.log`
- `OS_Architecture_Discovery_Via_Grep_attack126.log`
- `OS_Architecture_Discovery_Via_Grep_attack127.log`
- `OS_Architecture_Discovery_Via_Grep_attack128.log`
- `OS_Architecture_Discovery_Via_Grep_attack129.log`
- `OS_Architecture_Discovery_Via_Grep_attack13.log`
- `OS_Architecture_Discovery_Via_Grep_attack130.log`
- `OS_Architecture_Discovery_Via_Grep_attack131.log`
- `OS_Architecture_Discovery_Via_Grep_attack132.log`
- `OS_Architecture_Discovery_Via_Grep_attack133.log`
- `OS_Architecture_Discovery_Via_Grep_attack134.log`
- `OS_Architecture_Discovery_Via_Grep_attack135.log`
- `OS_Architecture_Discovery_Via_Grep_attack136.log`
- `OS_Architecture_Discovery_Via_Grep_attack137.log`
- `OS_Architecture_Discovery_Via_Grep_attack138.log`
- `OS_Architecture_Discovery_Via_Grep_attack139.log`
- `OS_Architecture_Discovery_Via_Grep_attack14.log`
- `OS_Architecture_Discovery_Via_Grep_attack140.log`
- `OS_Architecture_Discovery_Via_Grep_attack141.log`
- `OS_Architecture_Discovery_Via_Grep_attack142.log`
- `OS_Architecture_Discovery_Via_Grep_attack143.log`
- `OS_Architecture_Discovery_Via_Grep_attack144.log`
- `OS_Architecture_Discovery_Via_Grep_attack145.log`
- `OS_Architecture_Discovery_Via_Grep_attack146.log`
- `OS_Architecture_Discovery_Via_Grep_attack147.log`
- `OS_Architecture_Discovery_Via_Grep_attack148.log`
- `OS_Architecture_Discovery_Via_Grep_attack149.log`
- `OS_Architecture_Discovery_Via_Grep_attack15.log`
- `OS_Architecture_Discovery_Via_Grep_attack150.log`
- `OS_Architecture_Discovery_Via_Grep_attack151.log`
- `OS_Architecture_Discovery_Via_Grep_attack152.log`
- `OS_Architecture_Discovery_Via_Grep_attack153.log`
- `OS_Architecture_Discovery_Via_Grep_attack154.log`
- `OS_Architecture_Discovery_Via_Grep_attack155.log`
- `OS_Architecture_Discovery_Via_Grep_attack156.log`
- `OS_Architecture_Discovery_Via_Grep_attack157.log`
- `OS_Architecture_Discovery_Via_Grep_attack158.log`
- `OS_Architecture_Discovery_Via_Grep_attack159.log`
- `OS_Architecture_Discovery_Via_Grep_attack16.log`
- `OS_Architecture_Discovery_Via_Grep_attack160.log`
- `OS_Architecture_Discovery_Via_Grep_attack161.log`
- `OS_Architecture_Discovery_Via_Grep_attack162.log`
- `OS_Architecture_Discovery_Via_Grep_attack163.log`
- `OS_Architecture_Discovery_Via_Grep_attack164.log`
- `OS_Architecture_Discovery_Via_Grep_attack165.log`
- `OS_Architecture_Discovery_Via_Grep_attack166.log`
- `OS_Architecture_Discovery_Via_Grep_attack167.log`
- `OS_Architecture_Discovery_Via_Grep_attack168.log`
- `OS_Architecture_Discovery_Via_Grep_attack169.log`
- `OS_Architecture_Discovery_Via_Grep_attack17.log`
- `OS_Architecture_Discovery_Via_Grep_attack170.log`
- `OS_Architecture_Discovery_Via_Grep_attack171.log`
- `OS_Architecture_Discovery_Via_Grep_attack172.log`
- `OS_Architecture_Discovery_Via_Grep_attack173.log`
- `OS_Architecture_Discovery_Via_Grep_attack174.log`
- `OS_Architecture_Discovery_Via_Grep_attack175.log`
- `OS_Architecture_Discovery_Via_Grep_attack176.log`
- `OS_Architecture_Discovery_Via_Grep_attack177.log`
- `OS_Architecture_Discovery_Via_Grep_attack178.log`
- `OS_Architecture_Discovery_Via_Grep_attack179.log`
- `OS_Architecture_Discovery_Via_Grep_attack18.log`
- `OS_Architecture_Discovery_Via_Grep_attack180.log`
- `OS_Architecture_Discovery_Via_Grep_attack181.log`
- `OS_Architecture_Discovery_Via_Grep_attack182.log`
- `OS_Architecture_Discovery_Via_Grep_attack183.log`
- `OS_Architecture_Discovery_Via_Grep_attack184.log`
- `OS_Architecture_Discovery_Via_Grep_attack185.log`
- `OS_Architecture_Discovery_Via_Grep_attack186.log`
- `OS_Architecture_Discovery_Via_Grep_attack187.log`
- `OS_Architecture_Discovery_Via_Grep_attack188.log`
- `OS_Architecture_Discovery_Via_Grep_attack189.log`
- `OS_Architecture_Discovery_Via_Grep_attack19.log`
- `OS_Architecture_Discovery_Via_Grep_attack190.log`
- `OS_Architecture_Discovery_Via_Grep_attack191.log`
- `OS_Architecture_Discovery_Via_Grep_attack192.log`
- `OS_Architecture_Discovery_Via_Grep_attack193.log`
- `OS_Architecture_Discovery_Via_Grep_attack194.log`
- `OS_Architecture_Discovery_Via_Grep_attack195.log`
- `OS_Architecture_Discovery_Via_Grep_attack196.log`
- `OS_Architecture_Discovery_Via_Grep_attack197.log`
- `OS_Architecture_Discovery_Via_Grep_attack198.log`
- `OS_Architecture_Discovery_Via_Grep_attack199.log`
- `OS_Architecture_Discovery_Via_Grep_attack2.log`
- `OS_Architecture_Discovery_Via_Grep_attack20.log`
- `OS_Architecture_Discovery_Via_Grep_attack200.log`
- `OS_Architecture_Discovery_Via_Grep_attack201.log`
- `OS_Architecture_Discovery_Via_Grep_attack202.log`
- `OS_Architecture_Discovery_Via_Grep_attack203.log`
- `OS_Architecture_Discovery_Via_Grep_attack204.log`
- `OS_Architecture_Discovery_Via_Grep_attack205.log`
- `OS_Architecture_Discovery_Via_Grep_attack206.log`
- `OS_Architecture_Discovery_Via_Grep_attack207.log`
- `OS_Architecture_Discovery_Via_Grep_attack208.log`
- `OS_Architecture_Discovery_Via_Grep_attack209.log`
- `OS_Architecture_Discovery_Via_Grep_attack21.log`
- `OS_Architecture_Discovery_Via_Grep_attack210.log`
- `OS_Architecture_Discovery_Via_Grep_attack211.log`
- `OS_Architecture_Discovery_Via_Grep_attack212.log`
- `OS_Architecture_Discovery_Via_Grep_attack213.log`
- `OS_Architecture_Discovery_Via_Grep_attack214.log`
- `OS_Architecture_Discovery_Via_Grep_attack215.log`
- `OS_Architecture_Discovery_Via_Grep_attack216.log`
- `OS_Architecture_Discovery_Via_Grep_attack217.log`
- `OS_Architecture_Discovery_Via_Grep_attack218.log`
- `OS_Architecture_Discovery_Via_Grep_attack219.log`
- `OS_Architecture_Discovery_Via_Grep_attack22.log`
- `OS_Architecture_Discovery_Via_Grep_attack220.log`
- `OS_Architecture_Discovery_Via_Grep_attack221.log`
- `OS_Architecture_Discovery_Via_Grep_attack222.log`
- `OS_Architecture_Discovery_Via_Grep_attack223.log`
- `OS_Architecture_Discovery_Via_Grep_attack224.log`
- `OS_Architecture_Discovery_Via_Grep_attack225.log`
- `OS_Architecture_Discovery_Via_Grep_attack226.log`
- `OS_Architecture_Discovery_Via_Grep_attack227.log`
- `OS_Architecture_Discovery_Via_Grep_attack228.log`
- `OS_Architecture_Discovery_Via_Grep_attack229.log`
- `OS_Architecture_Discovery_Via_Grep_attack23.log`
- `OS_Architecture_Discovery_Via_Grep_attack230.log`
- `OS_Architecture_Discovery_Via_Grep_attack231.log`
- `OS_Architecture_Discovery_Via_Grep_attack232.log`
- `OS_Architecture_Discovery_Via_Grep_attack233.log`
- `OS_Architecture_Discovery_Via_Grep_attack234.log`
- `OS_Architecture_Discovery_Via_Grep_attack235.log`
- `OS_Architecture_Discovery_Via_Grep_attack236.log`
- `OS_Architecture_Discovery_Via_Grep_attack237.log`
- `OS_Architecture_Discovery_Via_Grep_attack238.log`
- `OS_Architecture_Discovery_Via_Grep_attack239.log`
- `OS_Architecture_Discovery_Via_Grep_attack24.log`
- `OS_Architecture_Discovery_Via_Grep_attack240.log`
- `OS_Architecture_Discovery_Via_Grep_attack241.log`
- `OS_Architecture_Discovery_Via_Grep_attack242.log`
- `OS_Architecture_Discovery_Via_Grep_attack243.log`
- `OS_Architecture_Discovery_Via_Grep_attack244.log`
- `OS_Architecture_Discovery_Via_Grep_attack245.log`
- `OS_Architecture_Discovery_Via_Grep_attack246.log`
- `OS_Architecture_Discovery_Via_Grep_attack247.log`
- `OS_Architecture_Discovery_Via_Grep_attack248.log`
- `OS_Architecture_Discovery_Via_Grep_attack249.log`
- `OS_Architecture_Discovery_Via_Grep_attack25.log`
- `OS_Architecture_Discovery_Via_Grep_attack250.log`
- `OS_Architecture_Discovery_Via_Grep_attack251.log`
- `OS_Architecture_Discovery_Via_Grep_attack252.log`
- `OS_Architecture_Discovery_Via_Grep_attack253.log`
- `OS_Architecture_Discovery_Via_Grep_attack254.log`
- `OS_Architecture_Discovery_Via_Grep_attack255.log`
- `OS_Architecture_Discovery_Via_Grep_attack256.log`
- `OS_Architecture_Discovery_Via_Grep_attack257.log`
- `OS_Architecture_Discovery_Via_Grep_attack258.log`
- `OS_Architecture_Discovery_Via_Grep_attack259.log`
- `OS_Architecture_Discovery_Via_Grep_attack26.log`
- `OS_Architecture_Discovery_Via_Grep_attack260.log`
- `OS_Architecture_Discovery_Via_Grep_attack261.log`
- `OS_Architecture_Discovery_Via_Grep_attack262.log`
- `OS_Architecture_Discovery_Via_Grep_attack263.log`
- `OS_Architecture_Discovery_Via_Grep_attack264.log`
- `OS_Architecture_Discovery_Via_Grep_attack265.log`
- `OS_Architecture_Discovery_Via_Grep_attack266.log`
- `OS_Architecture_Discovery_Via_Grep_attack267.log`
- `OS_Architecture_Discovery_Via_Grep_attack268.log`
- `OS_Architecture_Discovery_Via_Grep_attack269.log`
- `OS_Architecture_Discovery_Via_Grep_attack27.log`
- `OS_Architecture_Discovery_Via_Grep_attack28.log`
- `OS_Architecture_Discovery_Via_Grep_attack29.log`
- `OS_Architecture_Discovery_Via_Grep_attack3.log`
- `OS_Architecture_Discovery_Via_Grep_attack30.log`
- `OS_Architecture_Discovery_Via_Grep_attack31.log`
- `OS_Architecture_Discovery_Via_Grep_attack32.log`
- `OS_Architecture_Discovery_Via_Grep_attack33.log`
- `OS_Architecture_Discovery_Via_Grep_attack34.log`
- `OS_Architecture_Discovery_Via_Grep_attack35.log`
- `OS_Architecture_Discovery_Via_Grep_attack36.log`
- `OS_Architecture_Discovery_Via_Grep_attack37.log`
- `OS_Architecture_Discovery_Via_Grep_attack38.log`
- `OS_Architecture_Discovery_Via_Grep_attack39.log`
- `OS_Architecture_Discovery_Via_Grep_attack4.log`
- `OS_Architecture_Discovery_Via_Grep_attack40.log`
- `OS_Architecture_Discovery_Via_Grep_attack41.log`
- `OS_Architecture_Discovery_Via_Grep_attack42.log`
- `OS_Architecture_Discovery_Via_Grep_attack43.log`
- `OS_Architecture_Discovery_Via_Grep_attack44.log`
- `OS_Architecture_Discovery_Via_Grep_attack45.log`
- `OS_Architecture_Discovery_Via_Grep_attack46.log`
- `OS_Architecture_Discovery_Via_Grep_attack47.log`
- `OS_Architecture_Discovery_Via_Grep_attack48.log`
- `OS_Architecture_Discovery_Via_Grep_attack49.log`
- `OS_Architecture_Discovery_Via_Grep_attack5.log`
- `OS_Architecture_Discovery_Via_Grep_attack50.log`
- `OS_Architecture_Discovery_Via_Grep_attack51.log`
- `OS_Architecture_Discovery_Via_Grep_attack52.log`
- `OS_Architecture_Discovery_Via_Grep_attack53.log`
- `OS_Architecture_Discovery_Via_Grep_attack54.log`
- `OS_Architecture_Discovery_Via_Grep_attack55.log`
- `OS_Architecture_Discovery_Via_Grep_attack56.log`
- `OS_Architecture_Discovery_Via_Grep_attack57.log`
- `OS_Architecture_Discovery_Via_Grep_attack58.log`
- `OS_Architecture_Discovery_Via_Grep_attack59.log`
- `OS_Architecture_Discovery_Via_Grep_attack6.log`
- `OS_Architecture_Discovery_Via_Grep_attack60.log`
- `OS_Architecture_Discovery_Via_Grep_attack61.log`
- `OS_Architecture_Discovery_Via_Grep_attack62.log`
- `OS_Architecture_Discovery_Via_Grep_attack63.log`
- `OS_Architecture_Discovery_Via_Grep_attack64.log`
- `OS_Architecture_Discovery_Via_Grep_attack65.log`
- `OS_Architecture_Discovery_Via_Grep_attack66.log`
- `OS_Architecture_Discovery_Via_Grep_attack67.log`
- `OS_Architecture_Discovery_Via_Grep_attack68.log`
- `OS_Architecture_Discovery_Via_Grep_attack69.log`
- `OS_Architecture_Discovery_Via_Grep_attack7.log`
- `OS_Architecture_Discovery_Via_Grep_attack70.log`
- `OS_Architecture_Discovery_Via_Grep_attack71.log`
- `OS_Architecture_Discovery_Via_Grep_attack72.log`
- `OS_Architecture_Discovery_Via_Grep_attack73.log`
- `OS_Architecture_Discovery_Via_Grep_attack74.log`
- `OS_Architecture_Discovery_Via_Grep_attack75.log`
- `OS_Architecture_Discovery_Via_Grep_attack76.log`
- `OS_Architecture_Discovery_Via_Grep_attack77.log`
- `OS_Architecture_Discovery_Via_Grep_attack78.log`
- `OS_Architecture_Discovery_Via_Grep_attack79.log`
- `OS_Architecture_Discovery_Via_Grep_attack8.log`
- `OS_Architecture_Discovery_Via_Grep_attack80.log`
- `OS_Architecture_Discovery_Via_Grep_attack81.log`
- `OS_Architecture_Discovery_Via_Grep_attack82.log`
- `OS_Architecture_Discovery_Via_Grep_attack83.log`
- `OS_Architecture_Discovery_Via_Grep_attack84.log`
- `OS_Architecture_Discovery_Via_Grep_attack85.log`
- `OS_Architecture_Discovery_Via_Grep_attack86.log`
- `OS_Architecture_Discovery_Via_Grep_attack87.log`
- `OS_Architecture_Discovery_Via_Grep_attack88.log`
- `OS_Architecture_Discovery_Via_Grep_attack89.log`
- `OS_Architecture_Discovery_Via_Grep_attack9.log`
- `OS_Architecture_Discovery_Via_Grep_attack90.log`
- `OS_Architecture_Discovery_Via_Grep_attack91.log`
- `OS_Architecture_Discovery_Via_Grep_attack92.log`
- `OS_Architecture_Discovery_Via_Grep_attack93.log`
- `OS_Architecture_Discovery_Via_Grep_attack94.log`
- `OS_Architecture_Discovery_Via_Grep_attack95.log`
- `OS_Architecture_Discovery_Via_Grep_attack96.log`
- `OS_Architecture_Discovery_Via_Grep_attack97.log`
- `OS_Architecture_Discovery_Via_Grep_attack98.log`
- `OS_Architecture_Discovery_Via_Grep_attack99.log`

---

### Suspicious Invocation of Shell via AWK - Linux

**Directory:** `awk_shell_spawn`

**Sigma Rule ID:** `8c1a5675-cb85-452f-a298-b01b22a51856`

**Event Counts:**
- Total: 264
- Match Events: 84
- Evasion Events: 180

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 36, 37, 38, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 115, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 146, 147, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 186, 187, 188, 189, 190, 192, 193, 194, 195, 196, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 228, 229, 230, 231, 232, 233, 235, 236, 238, 239, 240, 241, 242, 243, 244, 245, 247, 248, 249, 250, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301

**Log Files:**
- `Suspicious_Invocation_of_Shell_via_AWK_attack1.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack10.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack100.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack101.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack102.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack103.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack104.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack105.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack106.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack107.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack108.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack109.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack11.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack110.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack111.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack112.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack113.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack115.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack12.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack129.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack13.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack130.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack131.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack132.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack133.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack134.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack135.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack136.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack137.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack138.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack139.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack14.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack146.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack147.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack15.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack152.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack153.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack154.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack155.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack156.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack157.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack158.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack159.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack16.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack160.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack161.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack162.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack163.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack164.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack166.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack167.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack168.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack169.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack17.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack170.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack171.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack172.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack173.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack174.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack175.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack176.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack177.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack178.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack179.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack18.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack180.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack181.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack182.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack183.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack184.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack186.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack187.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack188.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack189.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack19.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack190.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack192.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack193.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack194.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack195.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack196.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack198.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack199.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack2.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack20.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack200.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack201.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack202.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack203.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack204.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack205.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack206.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack207.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack208.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack209.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack21.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack210.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack211.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack212.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack213.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack214.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack215.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack216.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack217.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack218.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack219.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack22.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack220.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack221.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack222.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack223.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack224.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack225.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack226.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack228.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack229.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack230.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack231.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack232.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack233.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack235.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack236.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack238.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack239.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack24.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack240.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack241.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack242.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack243.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack244.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack245.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack247.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack248.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack249.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack25.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack250.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack252.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack253.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack254.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack255.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack256.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack257.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack258.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack259.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack26.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack260.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack261.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack262.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack263.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack264.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack265.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack266.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack267.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack268.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack269.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack27.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack270.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack271.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack272.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack273.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack274.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack275.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack276.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack277.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack278.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack279.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack28.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack280.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack281.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack282.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack283.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack284.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack285.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack286.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack287.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack288.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack289.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack29.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack290.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack291.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack292.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack293.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack294.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack295.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack296.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack297.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack298.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack299.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack3.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack30.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack300.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack301.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack31.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack32.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack33.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack36.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack37.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack38.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack4.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack40.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack41.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack42.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack43.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack44.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack45.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack46.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack47.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack48.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack49.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack5.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack50.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack51.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack52.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack53.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack54.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack55.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack56.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack57.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack58.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack59.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack6.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack60.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack61.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack62.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack63.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack64.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack65.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack66.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack67.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack68.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack69.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack7.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack70.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack71.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack72.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack73.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack74.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack75.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack76.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack77.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack78.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack79.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack8.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack80.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack81.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack82.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack83.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack84.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack85.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack86.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack87.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack88.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack89.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack9.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack90.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack91.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack92.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack93.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack94.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack95.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack96.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack97.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack98.log`
- `Suspicious_Invocation_of_Shell_via_AWK_attack99.log`

---

### Local Groups Discovery - Linux

**Directory:** `local_groups`

**Event Counts:**
- Total: 261
- Match Events: 115
- Evasion Events: 146

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261

**Log Files:**
- `Local_Groups_Discovery_-_Linux_attack1.log`
- `Local_Groups_Discovery_-_Linux_attack10.log`
- `Local_Groups_Discovery_-_Linux_attack100.log`
- `Local_Groups_Discovery_-_Linux_attack101.log`
- `Local_Groups_Discovery_-_Linux_attack102.log`
- `Local_Groups_Discovery_-_Linux_attack103.log`
- `Local_Groups_Discovery_-_Linux_attack104.log`
- `Local_Groups_Discovery_-_Linux_attack105.log`
- `Local_Groups_Discovery_-_Linux_attack106.log`
- `Local_Groups_Discovery_-_Linux_attack107.log`
- `Local_Groups_Discovery_-_Linux_attack108.log`
- `Local_Groups_Discovery_-_Linux_attack109.log`
- `Local_Groups_Discovery_-_Linux_attack11.log`
- `Local_Groups_Discovery_-_Linux_attack110.log`
- `Local_Groups_Discovery_-_Linux_attack111.log`
- `Local_Groups_Discovery_-_Linux_attack112.log`
- `Local_Groups_Discovery_-_Linux_attack113.log`
- `Local_Groups_Discovery_-_Linux_attack114.log`
- `Local_Groups_Discovery_-_Linux_attack115.log`
- `Local_Groups_Discovery_-_Linux_attack116.log`
- `Local_Groups_Discovery_-_Linux_attack117.log`
- `Local_Groups_Discovery_-_Linux_attack118.log`
- `Local_Groups_Discovery_-_Linux_attack119.log`
- `Local_Groups_Discovery_-_Linux_attack12.log`
- `Local_Groups_Discovery_-_Linux_attack120.log`
- `Local_Groups_Discovery_-_Linux_attack121.log`
- `Local_Groups_Discovery_-_Linux_attack122.log`
- `Local_Groups_Discovery_-_Linux_attack123.log`
- `Local_Groups_Discovery_-_Linux_attack124.log`
- `Local_Groups_Discovery_-_Linux_attack125.log`
- `Local_Groups_Discovery_-_Linux_attack126.log`
- `Local_Groups_Discovery_-_Linux_attack127.log`
- `Local_Groups_Discovery_-_Linux_attack128.log`
- `Local_Groups_Discovery_-_Linux_attack129.log`
- `Local_Groups_Discovery_-_Linux_attack13.log`
- `Local_Groups_Discovery_-_Linux_attack130.log`
- `Local_Groups_Discovery_-_Linux_attack131.log`
- `Local_Groups_Discovery_-_Linux_attack132.log`
- `Local_Groups_Discovery_-_Linux_attack133.log`
- `Local_Groups_Discovery_-_Linux_attack134.log`
- `Local_Groups_Discovery_-_Linux_attack135.log`
- `Local_Groups_Discovery_-_Linux_attack136.log`
- `Local_Groups_Discovery_-_Linux_attack137.log`
- `Local_Groups_Discovery_-_Linux_attack138.log`
- `Local_Groups_Discovery_-_Linux_attack139.log`
- `Local_Groups_Discovery_-_Linux_attack14.log`
- `Local_Groups_Discovery_-_Linux_attack140.log`
- `Local_Groups_Discovery_-_Linux_attack141.log`
- `Local_Groups_Discovery_-_Linux_attack142.log`
- `Local_Groups_Discovery_-_Linux_attack143.log`
- `Local_Groups_Discovery_-_Linux_attack144.log`
- `Local_Groups_Discovery_-_Linux_attack145.log`
- `Local_Groups_Discovery_-_Linux_attack146.log`
- `Local_Groups_Discovery_-_Linux_attack147.log`
- `Local_Groups_Discovery_-_Linux_attack148.log`
- `Local_Groups_Discovery_-_Linux_attack149.log`
- `Local_Groups_Discovery_-_Linux_attack15.log`
- `Local_Groups_Discovery_-_Linux_attack150.log`
- `Local_Groups_Discovery_-_Linux_attack151.log`
- `Local_Groups_Discovery_-_Linux_attack152.log`
- `Local_Groups_Discovery_-_Linux_attack153.log`
- `Local_Groups_Discovery_-_Linux_attack154.log`
- `Local_Groups_Discovery_-_Linux_attack155.log`
- `Local_Groups_Discovery_-_Linux_attack156.log`
- `Local_Groups_Discovery_-_Linux_attack157.log`
- `Local_Groups_Discovery_-_Linux_attack158.log`
- `Local_Groups_Discovery_-_Linux_attack159.log`
- `Local_Groups_Discovery_-_Linux_attack16.log`
- `Local_Groups_Discovery_-_Linux_attack160.log`
- `Local_Groups_Discovery_-_Linux_attack161.log`
- `Local_Groups_Discovery_-_Linux_attack162.log`
- `Local_Groups_Discovery_-_Linux_attack163.log`
- `Local_Groups_Discovery_-_Linux_attack164.log`
- `Local_Groups_Discovery_-_Linux_attack165.log`
- `Local_Groups_Discovery_-_Linux_attack166.log`
- `Local_Groups_Discovery_-_Linux_attack167.log`
- `Local_Groups_Discovery_-_Linux_attack168.log`
- `Local_Groups_Discovery_-_Linux_attack169.log`
- `Local_Groups_Discovery_-_Linux_attack17.log`
- `Local_Groups_Discovery_-_Linux_attack170.log`
- `Local_Groups_Discovery_-_Linux_attack171.log`
- `Local_Groups_Discovery_-_Linux_attack172.log`
- `Local_Groups_Discovery_-_Linux_attack173.log`
- `Local_Groups_Discovery_-_Linux_attack174.log`
- `Local_Groups_Discovery_-_Linux_attack175.log`
- `Local_Groups_Discovery_-_Linux_attack176.log`
- `Local_Groups_Discovery_-_Linux_attack177.log`
- `Local_Groups_Discovery_-_Linux_attack178.log`
- `Local_Groups_Discovery_-_Linux_attack179.log`
- `Local_Groups_Discovery_-_Linux_attack18.log`
- `Local_Groups_Discovery_-_Linux_attack180.log`
- `Local_Groups_Discovery_-_Linux_attack181.log`
- `Local_Groups_Discovery_-_Linux_attack182.log`
- `Local_Groups_Discovery_-_Linux_attack183.log`
- `Local_Groups_Discovery_-_Linux_attack184.log`
- `Local_Groups_Discovery_-_Linux_attack185.log`
- `Local_Groups_Discovery_-_Linux_attack186.log`
- `Local_Groups_Discovery_-_Linux_attack187.log`
- `Local_Groups_Discovery_-_Linux_attack188.log`
- `Local_Groups_Discovery_-_Linux_attack189.log`
- `Local_Groups_Discovery_-_Linux_attack19.log`
- `Local_Groups_Discovery_-_Linux_attack190.log`
- `Local_Groups_Discovery_-_Linux_attack191.log`
- `Local_Groups_Discovery_-_Linux_attack192.log`
- `Local_Groups_Discovery_-_Linux_attack193.log`
- `Local_Groups_Discovery_-_Linux_attack194.log`
- `Local_Groups_Discovery_-_Linux_attack195.log`
- `Local_Groups_Discovery_-_Linux_attack196.log`
- `Local_Groups_Discovery_-_Linux_attack197.log`
- `Local_Groups_Discovery_-_Linux_attack198.log`
- `Local_Groups_Discovery_-_Linux_attack199.log`
- `Local_Groups_Discovery_-_Linux_attack2.log`
- `Local_Groups_Discovery_-_Linux_attack20.log`
- `Local_Groups_Discovery_-_Linux_attack200.log`
- `Local_Groups_Discovery_-_Linux_attack201.log`
- `Local_Groups_Discovery_-_Linux_attack202.log`
- `Local_Groups_Discovery_-_Linux_attack203.log`
- `Local_Groups_Discovery_-_Linux_attack204.log`
- `Local_Groups_Discovery_-_Linux_attack205.log`
- `Local_Groups_Discovery_-_Linux_attack206.log`
- `Local_Groups_Discovery_-_Linux_attack207.log`
- `Local_Groups_Discovery_-_Linux_attack208.log`
- `Local_Groups_Discovery_-_Linux_attack209.log`
- `Local_Groups_Discovery_-_Linux_attack21.log`
- `Local_Groups_Discovery_-_Linux_attack210.log`
- `Local_Groups_Discovery_-_Linux_attack211.log`
- `Local_Groups_Discovery_-_Linux_attack212.log`
- `Local_Groups_Discovery_-_Linux_attack213.log`
- `Local_Groups_Discovery_-_Linux_attack214.log`
- `Local_Groups_Discovery_-_Linux_attack215.log`
- `Local_Groups_Discovery_-_Linux_attack216.log`
- `Local_Groups_Discovery_-_Linux_attack217.log`
- `Local_Groups_Discovery_-_Linux_attack218.log`
- `Local_Groups_Discovery_-_Linux_attack219.log`
- `Local_Groups_Discovery_-_Linux_attack22.log`
- `Local_Groups_Discovery_-_Linux_attack220.log`
- `Local_Groups_Discovery_-_Linux_attack221.log`
- `Local_Groups_Discovery_-_Linux_attack222.log`
- `Local_Groups_Discovery_-_Linux_attack223.log`
- `Local_Groups_Discovery_-_Linux_attack224.log`
- `Local_Groups_Discovery_-_Linux_attack225.log`
- `Local_Groups_Discovery_-_Linux_attack226.log`
- `Local_Groups_Discovery_-_Linux_attack227.log`
- `Local_Groups_Discovery_-_Linux_attack228.log`
- `Local_Groups_Discovery_-_Linux_attack229.log`
- `Local_Groups_Discovery_-_Linux_attack23.log`
- `Local_Groups_Discovery_-_Linux_attack230.log`
- `Local_Groups_Discovery_-_Linux_attack231.log`
- `Local_Groups_Discovery_-_Linux_attack232.log`
- `Local_Groups_Discovery_-_Linux_attack233.log`
- `Local_Groups_Discovery_-_Linux_attack234.log`
- `Local_Groups_Discovery_-_Linux_attack235.log`
- `Local_Groups_Discovery_-_Linux_attack236.log`
- `Local_Groups_Discovery_-_Linux_attack237.log`
- `Local_Groups_Discovery_-_Linux_attack238.log`
- `Local_Groups_Discovery_-_Linux_attack239.log`
- `Local_Groups_Discovery_-_Linux_attack24.log`
- `Local_Groups_Discovery_-_Linux_attack240.log`
- `Local_Groups_Discovery_-_Linux_attack241.log`
- `Local_Groups_Discovery_-_Linux_attack242.log`
- `Local_Groups_Discovery_-_Linux_attack243.log`
- `Local_Groups_Discovery_-_Linux_attack244.log`
- `Local_Groups_Discovery_-_Linux_attack245.log`
- `Local_Groups_Discovery_-_Linux_attack246.log`
- `Local_Groups_Discovery_-_Linux_attack247.log`
- `Local_Groups_Discovery_-_Linux_attack248.log`
- `Local_Groups_Discovery_-_Linux_attack249.log`
- `Local_Groups_Discovery_-_Linux_attack25.log`
- `Local_Groups_Discovery_-_Linux_attack250.log`
- `Local_Groups_Discovery_-_Linux_attack251.log`
- `Local_Groups_Discovery_-_Linux_attack252.log`
- `Local_Groups_Discovery_-_Linux_attack253.log`
- `Local_Groups_Discovery_-_Linux_attack254.log`
- `Local_Groups_Discovery_-_Linux_attack255.log`
- `Local_Groups_Discovery_-_Linux_attack256.log`
- `Local_Groups_Discovery_-_Linux_attack257.log`
- `Local_Groups_Discovery_-_Linux_attack258.log`
- `Local_Groups_Discovery_-_Linux_attack259.log`
- `Local_Groups_Discovery_-_Linux_attack26.log`
- `Local_Groups_Discovery_-_Linux_attack260.log`
- `Local_Groups_Discovery_-_Linux_attack261.log`
- `Local_Groups_Discovery_-_Linux_attack27.log`
- `Local_Groups_Discovery_-_Linux_attack28.log`
- `Local_Groups_Discovery_-_Linux_attack29.log`
- `Local_Groups_Discovery_-_Linux_attack3.log`
- `Local_Groups_Discovery_-_Linux_attack30.log`
- `Local_Groups_Discovery_-_Linux_attack31.log`
- `Local_Groups_Discovery_-_Linux_attack32.log`
- `Local_Groups_Discovery_-_Linux_attack33.log`
- `Local_Groups_Discovery_-_Linux_attack34.log`
- `Local_Groups_Discovery_-_Linux_attack35.log`
- `Local_Groups_Discovery_-_Linux_attack36.log`
- `Local_Groups_Discovery_-_Linux_attack37.log`
- `Local_Groups_Discovery_-_Linux_attack38.log`
- `Local_Groups_Discovery_-_Linux_attack39.log`
- `Local_Groups_Discovery_-_Linux_attack4.log`
- `Local_Groups_Discovery_-_Linux_attack40.log`
- `Local_Groups_Discovery_-_Linux_attack41.log`
- `Local_Groups_Discovery_-_Linux_attack42.log`
- `Local_Groups_Discovery_-_Linux_attack43.log`
- `Local_Groups_Discovery_-_Linux_attack44.log`
- `Local_Groups_Discovery_-_Linux_attack45.log`
- `Local_Groups_Discovery_-_Linux_attack46.log`
- `Local_Groups_Discovery_-_Linux_attack47.log`
- `Local_Groups_Discovery_-_Linux_attack48.log`
- `Local_Groups_Discovery_-_Linux_attack49.log`
- `Local_Groups_Discovery_-_Linux_attack5.log`
- `Local_Groups_Discovery_-_Linux_attack50.log`
- `Local_Groups_Discovery_-_Linux_attack51.log`
- `Local_Groups_Discovery_-_Linux_attack52.log`
- `Local_Groups_Discovery_-_Linux_attack53.log`
- `Local_Groups_Discovery_-_Linux_attack54.log`
- `Local_Groups_Discovery_-_Linux_attack55.log`
- `Local_Groups_Discovery_-_Linux_attack56.log`
- `Local_Groups_Discovery_-_Linux_attack57.log`
- `Local_Groups_Discovery_-_Linux_attack58.log`
- `Local_Groups_Discovery_-_Linux_attack59.log`
- `Local_Groups_Discovery_-_Linux_attack6.log`
- `Local_Groups_Discovery_-_Linux_attack60.log`
- `Local_Groups_Discovery_-_Linux_attack61.log`
- `Local_Groups_Discovery_-_Linux_attack62.log`
- `Local_Groups_Discovery_-_Linux_attack63.log`
- `Local_Groups_Discovery_-_Linux_attack64.log`
- `Local_Groups_Discovery_-_Linux_attack65.log`
- `Local_Groups_Discovery_-_Linux_attack66.log`
- `Local_Groups_Discovery_-_Linux_attack67.log`
- `Local_Groups_Discovery_-_Linux_attack68.log`
- `Local_Groups_Discovery_-_Linux_attack69.log`
- `Local_Groups_Discovery_-_Linux_attack7.log`
- `Local_Groups_Discovery_-_Linux_attack70.log`
- `Local_Groups_Discovery_-_Linux_attack71.log`
- `Local_Groups_Discovery_-_Linux_attack72.log`
- `Local_Groups_Discovery_-_Linux_attack73.log`
- `Local_Groups_Discovery_-_Linux_attack74.log`
- `Local_Groups_Discovery_-_Linux_attack75.log`
- `Local_Groups_Discovery_-_Linux_attack76.log`
- `Local_Groups_Discovery_-_Linux_attack77.log`
- `Local_Groups_Discovery_-_Linux_attack78.log`
- `Local_Groups_Discovery_-_Linux_attack79.log`
- `Local_Groups_Discovery_-_Linux_attack8.log`
- `Local_Groups_Discovery_-_Linux_attack80.log`
- `Local_Groups_Discovery_-_Linux_attack81.log`
- `Local_Groups_Discovery_-_Linux_attack82.log`
- `Local_Groups_Discovery_-_Linux_attack83.log`
- `Local_Groups_Discovery_-_Linux_attack84.log`
- `Local_Groups_Discovery_-_Linux_attack85.log`
- `Local_Groups_Discovery_-_Linux_attack86.log`
- `Local_Groups_Discovery_-_Linux_attack87.log`
- `Local_Groups_Discovery_-_Linux_attack88.log`
- `Local_Groups_Discovery_-_Linux_attack89.log`
- `Local_Groups_Discovery_-_Linux_attack9.log`
- `Local_Groups_Discovery_-_Linux_attack90.log`
- `Local_Groups_Discovery_-_Linux_attack91.log`
- `Local_Groups_Discovery_-_Linux_attack92.log`
- `Local_Groups_Discovery_-_Linux_attack93.log`
- `Local_Groups_Discovery_-_Linux_attack94.log`
- `Local_Groups_Discovery_-_Linux_attack95.log`
- `Local_Groups_Discovery_-_Linux_attack96.log`
- `Local_Groups_Discovery_-_Linux_attack97.log`
- `Local_Groups_Discovery_-_Linux_attack98.log`
- `Local_Groups_Discovery_-_Linux_attack99.log`

---

### Linux Base64 Encoded Pipe to Shell

**Directory:** `base64_execution`

**Sigma Rule ID:** `ba592c6d-6888-43c3-b8c6-689b8fe47337`

**Event Counts:**
- Total: 260
- Match Events: 53
- Evasion Events: 207

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260

**Log Files:**
- `Linux_Base64_Encoded_Pipe_to_Shell_attack1.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack10.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack100.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack101.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack102.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack103.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack104.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack105.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack106.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack107.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack108.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack109.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack11.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack110.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack111.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack112.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack113.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack114.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack115.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack116.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack117.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack118.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack119.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack12.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack120.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack121.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack122.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack123.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack124.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack125.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack126.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack127.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack128.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack129.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack13.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack130.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack131.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack132.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack133.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack134.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack135.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack136.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack137.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack138.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack139.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack14.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack140.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack141.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack142.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack143.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack144.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack145.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack146.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack147.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack148.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack149.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack15.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack150.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack151.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack152.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack153.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack154.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack155.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack156.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack157.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack158.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack159.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack16.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack160.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack161.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack162.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack163.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack164.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack165.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack166.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack167.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack168.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack169.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack17.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack170.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack171.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack172.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack173.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack174.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack175.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack176.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack177.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack178.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack179.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack18.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack180.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack181.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack182.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack183.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack184.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack185.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack186.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack187.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack188.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack189.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack19.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack190.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack191.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack192.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack193.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack194.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack195.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack196.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack197.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack198.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack199.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack2.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack20.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack200.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack201.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack202.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack203.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack204.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack205.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack206.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack207.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack208.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack209.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack21.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack210.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack211.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack212.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack213.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack214.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack215.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack216.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack217.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack218.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack219.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack22.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack220.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack221.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack222.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack223.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack224.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack225.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack226.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack227.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack228.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack229.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack23.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack230.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack231.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack232.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack233.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack234.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack235.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack236.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack237.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack238.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack239.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack24.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack240.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack241.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack242.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack243.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack244.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack245.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack246.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack247.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack248.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack249.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack25.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack250.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack251.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack252.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack253.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack254.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack255.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack256.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack257.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack258.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack259.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack26.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack260.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack27.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack28.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack29.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack3.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack30.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack31.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack32.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack33.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack34.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack35.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack36.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack37.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack38.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack39.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack4.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack40.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack41.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack42.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack43.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack44.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack45.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack46.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack47.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack48.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack49.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack5.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack50.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack51.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack52.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack53.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack54.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack55.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack56.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack57.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack58.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack59.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack6.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack60.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack61.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack62.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack63.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack64.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack65.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack66.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack67.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack68.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack69.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack7.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack70.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack71.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack72.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack73.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack74.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack75.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack76.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack77.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack78.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack79.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack8.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack80.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack81.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack82.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack83.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack84.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack85.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack86.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack87.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack88.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack89.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack9.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack90.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack91.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack92.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack93.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack94.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack95.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack96.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack97.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack98.log`
- `Linux_Base64_Encoded_Pipe_to_Shell_attack99.log`

---

### Ufw Force Stop Using Ufw-Init

**Directory:** `disable_ufw`

**Sigma Rule ID:** `84c9e83c-599a-458a-a0cb-0ecce44e807a`

**Event Counts:**
- Total: 246
- Match Events: 233
- Evasion Events: 13

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246

**Log Files:**
- `Ufw_Force_Stop_Using_Ufw-Init_attack1.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack10.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack100.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack101.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack102.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack103.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack104.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack105.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack106.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack107.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack108.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack109.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack11.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack110.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack111.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack112.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack113.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack114.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack115.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack116.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack117.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack118.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack119.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack12.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack120.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack121.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack122.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack123.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack124.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack125.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack126.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack127.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack128.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack129.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack13.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack130.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack131.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack132.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack133.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack134.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack135.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack136.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack137.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack138.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack139.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack14.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack140.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack141.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack142.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack143.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack144.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack145.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack146.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack147.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack148.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack149.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack15.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack150.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack151.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack152.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack153.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack154.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack155.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack156.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack157.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack158.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack159.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack16.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack160.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack161.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack162.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack163.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack164.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack165.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack166.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack167.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack168.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack169.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack17.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack170.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack171.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack172.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack173.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack174.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack175.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack176.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack177.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack178.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack179.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack18.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack180.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack181.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack182.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack183.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack184.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack185.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack186.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack187.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack188.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack189.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack19.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack190.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack191.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack192.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack193.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack194.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack195.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack196.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack197.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack198.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack199.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack2.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack20.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack200.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack201.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack202.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack203.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack204.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack205.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack206.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack207.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack208.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack209.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack21.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack210.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack211.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack212.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack213.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack214.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack215.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack216.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack217.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack218.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack219.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack22.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack220.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack221.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack222.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack223.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack224.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack225.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack226.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack227.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack228.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack229.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack23.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack230.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack231.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack232.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack233.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack234.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack235.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack236.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack237.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack238.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack239.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack24.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack240.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack241.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack242.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack243.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack244.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack245.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack246.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack25.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack26.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack27.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack28.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack29.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack3.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack30.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack31.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack32.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack33.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack34.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack35.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack36.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack37.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack38.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack39.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack4.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack40.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack41.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack42.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack43.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack44.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack45.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack46.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack47.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack48.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack49.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack5.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack50.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack51.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack52.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack53.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack54.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack55.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack56.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack57.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack58.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack59.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack6.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack60.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack61.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack62.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack63.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack64.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack65.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack66.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack67.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack68.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack69.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack7.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack70.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack71.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack72.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack73.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack74.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack75.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack76.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack77.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack78.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack79.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack8.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack80.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack81.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack82.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack83.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack84.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack85.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack86.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack87.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack88.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack89.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack9.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack90.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack91.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack92.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack93.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack94.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack95.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack96.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack97.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack98.log`
- `Ufw_Force_Stop_Using_Ufw-Init_attack99.log`

---

### Linux Base64 Encoded Shebang In CLI

**Directory:** `base64_shebang_cli`

**Sigma Rule ID:** `fe2f9663-41cb-47e2-b954-8a228f3b9dff`

**Event Counts:**
- Total: 232
- Match Events: 232
- Evasion Events: 0

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 29, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 50, 51, 53, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 88, 89, 90, 91, 92, 93, 95, 96, 97, 98, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 123, 124, 125, 126, 127, 128, 129, 130, 131, 133, 134, 135, 136, 137, 138, 139, 142, 143, 144, 145, 146, 147, 148, 149, 150, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 172, 173, 174, 175, 176, 177, 178, 179, 181, 182, 183, 184, 186, 187, 188, 190, 191, 192, 193, 194, 195, 196, 197, 198, 200, 201, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255

**Log Files:**
- `Linux_Base64_Encoded_Shebang_In_CLI_attack1.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack10.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack100.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack101.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack102.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack103.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack104.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack105.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack106.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack107.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack108.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack109.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack11.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack110.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack111.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack112.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack113.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack114.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack115.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack116.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack117.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack118.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack119.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack12.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack123.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack124.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack125.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack126.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack127.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack128.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack129.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack13.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack130.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack131.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack133.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack134.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack135.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack136.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack137.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack138.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack139.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack14.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack142.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack143.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack144.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack145.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack146.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack147.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack148.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack149.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack15.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack150.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack152.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack153.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack154.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack155.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack156.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack157.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack158.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack159.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack16.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack160.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack161.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack162.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack163.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack164.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack165.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack166.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack167.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack168.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack169.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack17.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack170.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack172.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack173.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack174.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack175.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack176.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack177.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack178.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack179.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack18.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack181.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack182.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack183.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack184.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack186.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack187.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack188.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack19.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack190.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack191.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack192.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack193.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack194.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack195.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack196.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack197.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack198.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack2.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack20.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack200.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack201.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack203.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack204.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack205.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack206.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack207.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack208.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack209.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack21.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack210.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack211.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack212.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack213.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack214.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack215.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack216.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack217.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack218.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack219.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack22.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack220.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack221.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack222.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack223.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack224.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack225.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack226.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack227.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack228.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack229.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack23.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack230.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack231.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack232.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack233.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack234.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack235.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack236.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack237.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack238.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack239.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack24.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack240.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack241.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack242.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack243.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack244.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack245.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack246.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack247.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack248.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack249.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack25.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack250.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack251.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack252.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack253.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack254.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack255.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack26.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack29.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack3.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack32.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack33.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack34.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack35.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack36.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack37.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack38.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack39.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack4.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack40.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack41.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack42.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack43.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack44.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack45.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack46.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack47.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack48.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack5.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack50.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack51.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack53.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack55.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack56.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack57.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack58.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack59.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack6.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack60.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack61.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack62.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack63.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack64.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack65.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack66.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack67.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack68.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack69.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack7.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack70.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack71.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack72.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack73.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack74.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack75.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack76.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack77.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack78.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack79.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack8.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack80.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack81.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack82.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack83.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack84.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack85.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack86.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack88.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack89.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack9.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack90.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack91.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack92.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack93.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack95.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack96.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack97.log`
- `Linux_Base64_Encoded_Shebang_In_CLI_attack98.log`

---

### Crontab Enumeration

**Directory:** `crontab_enumeration`

**Sigma Rule ID:** `403ed92c-b7ec-4edd-9947-5b535ee12d46`

**Event Counts:**
- Total: 230
- Match Events: 30
- Evasion Events: 200

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 123, 127, 130, 138, 149, 181, 182, 184, 185, 187, 188, 190, 191, 192, 193, 194, 195, 196, 197, 198, 200, 201, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 253, 254, 255, 256, 257, 258, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 275, 276, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360

**Log Files:**
- `Crontab_Enumeration_attack1.log`
- `Crontab_Enumeration_attack10.log`
- `Crontab_Enumeration_attack11.log`
- `Crontab_Enumeration_attack12.log`
- `Crontab_Enumeration_attack123.log`
- `Crontab_Enumeration_attack127.log`
- `Crontab_Enumeration_attack13.log`
- `Crontab_Enumeration_attack130.log`
- `Crontab_Enumeration_attack138.log`
- `Crontab_Enumeration_attack14.log`
- `Crontab_Enumeration_attack149.log`
- `Crontab_Enumeration_attack15.log`
- `Crontab_Enumeration_attack16.log`
- `Crontab_Enumeration_attack17.log`
- `Crontab_Enumeration_attack18.log`
- `Crontab_Enumeration_attack181.log`
- `Crontab_Enumeration_attack182.log`
- `Crontab_Enumeration_attack184.log`
- `Crontab_Enumeration_attack185.log`
- `Crontab_Enumeration_attack187.log`
- `Crontab_Enumeration_attack188.log`
- `Crontab_Enumeration_attack19.log`
- `Crontab_Enumeration_attack190.log`
- `Crontab_Enumeration_attack191.log`
- `Crontab_Enumeration_attack192.log`
- `Crontab_Enumeration_attack193.log`
- `Crontab_Enumeration_attack194.log`
- `Crontab_Enumeration_attack195.log`
- `Crontab_Enumeration_attack196.log`
- `Crontab_Enumeration_attack197.log`
- `Crontab_Enumeration_attack198.log`
- `Crontab_Enumeration_attack2.log`
- `Crontab_Enumeration_attack20.log`
- `Crontab_Enumeration_attack200.log`
- `Crontab_Enumeration_attack201.log`
- `Crontab_Enumeration_attack203.log`
- `Crontab_Enumeration_attack204.log`
- `Crontab_Enumeration_attack205.log`
- `Crontab_Enumeration_attack206.log`
- `Crontab_Enumeration_attack207.log`
- `Crontab_Enumeration_attack208.log`
- `Crontab_Enumeration_attack209.log`
- `Crontab_Enumeration_attack21.log`
- `Crontab_Enumeration_attack210.log`
- `Crontab_Enumeration_attack211.log`
- `Crontab_Enumeration_attack212.log`
- `Crontab_Enumeration_attack213.log`
- `Crontab_Enumeration_attack214.log`
- `Crontab_Enumeration_attack215.log`
- `Crontab_Enumeration_attack216.log`
- `Crontab_Enumeration_attack217.log`
- `Crontab_Enumeration_attack218.log`
- `Crontab_Enumeration_attack219.log`
- `Crontab_Enumeration_attack22.log`
- `Crontab_Enumeration_attack220.log`
- `Crontab_Enumeration_attack221.log`
- `Crontab_Enumeration_attack222.log`
- `Crontab_Enumeration_attack223.log`
- `Crontab_Enumeration_attack224.log`
- `Crontab_Enumeration_attack225.log`
- `Crontab_Enumeration_attack226.log`
- `Crontab_Enumeration_attack227.log`
- `Crontab_Enumeration_attack228.log`
- `Crontab_Enumeration_attack229.log`
- `Crontab_Enumeration_attack23.log`
- `Crontab_Enumeration_attack230.log`
- `Crontab_Enumeration_attack231.log`
- `Crontab_Enumeration_attack232.log`
- `Crontab_Enumeration_attack233.log`
- `Crontab_Enumeration_attack234.log`
- `Crontab_Enumeration_attack235.log`
- `Crontab_Enumeration_attack236.log`
- `Crontab_Enumeration_attack237.log`
- `Crontab_Enumeration_attack238.log`
- `Crontab_Enumeration_attack239.log`
- `Crontab_Enumeration_attack24.log`
- `Crontab_Enumeration_attack240.log`
- `Crontab_Enumeration_attack241.log`
- `Crontab_Enumeration_attack242.log`
- `Crontab_Enumeration_attack243.log`
- `Crontab_Enumeration_attack244.log`
- `Crontab_Enumeration_attack245.log`
- `Crontab_Enumeration_attack246.log`
- `Crontab_Enumeration_attack247.log`
- `Crontab_Enumeration_attack248.log`
- `Crontab_Enumeration_attack249.log`
- `Crontab_Enumeration_attack25.log`
- `Crontab_Enumeration_attack250.log`
- `Crontab_Enumeration_attack253.log`
- `Crontab_Enumeration_attack254.log`
- `Crontab_Enumeration_attack255.log`
- `Crontab_Enumeration_attack256.log`
- `Crontab_Enumeration_attack257.log`
- `Crontab_Enumeration_attack258.log`
- `Crontab_Enumeration_attack26.log`
- `Crontab_Enumeration_attack262.log`
- `Crontab_Enumeration_attack263.log`
- `Crontab_Enumeration_attack264.log`
- `Crontab_Enumeration_attack265.log`
- `Crontab_Enumeration_attack266.log`
- `Crontab_Enumeration_attack267.log`
- `Crontab_Enumeration_attack268.log`
- `Crontab_Enumeration_attack269.log`
- `Crontab_Enumeration_attack27.log`
- `Crontab_Enumeration_attack270.log`
- `Crontab_Enumeration_attack271.log`
- `Crontab_Enumeration_attack272.log`
- `Crontab_Enumeration_attack273.log`
- `Crontab_Enumeration_attack275.log`
- `Crontab_Enumeration_attack276.log`
- `Crontab_Enumeration_attack28.log`
- `Crontab_Enumeration_attack281.log`
- `Crontab_Enumeration_attack282.log`
- `Crontab_Enumeration_attack283.log`
- `Crontab_Enumeration_attack284.log`
- `Crontab_Enumeration_attack285.log`
- `Crontab_Enumeration_attack286.log`
- `Crontab_Enumeration_attack287.log`
- `Crontab_Enumeration_attack288.log`
- `Crontab_Enumeration_attack289.log`
- `Crontab_Enumeration_attack29.log`
- `Crontab_Enumeration_attack290.log`
- `Crontab_Enumeration_attack291.log`
- `Crontab_Enumeration_attack292.log`
- `Crontab_Enumeration_attack293.log`
- `Crontab_Enumeration_attack294.log`
- `Crontab_Enumeration_attack295.log`
- `Crontab_Enumeration_attack296.log`
- `Crontab_Enumeration_attack297.log`
- `Crontab_Enumeration_attack298.log`
- `Crontab_Enumeration_attack299.log`
- `Crontab_Enumeration_attack3.log`
- `Crontab_Enumeration_attack30.log`
- `Crontab_Enumeration_attack300.log`
- `Crontab_Enumeration_attack301.log`
- `Crontab_Enumeration_attack302.log`
- `Crontab_Enumeration_attack303.log`
- `Crontab_Enumeration_attack304.log`
- `Crontab_Enumeration_attack305.log`
- `Crontab_Enumeration_attack306.log`
- `Crontab_Enumeration_attack307.log`
- `Crontab_Enumeration_attack308.log`
- `Crontab_Enumeration_attack309.log`
- `Crontab_Enumeration_attack31.log`
- `Crontab_Enumeration_attack310.log`
- `Crontab_Enumeration_attack311.log`
- `Crontab_Enumeration_attack312.log`
- `Crontab_Enumeration_attack313.log`
- `Crontab_Enumeration_attack314.log`
- `Crontab_Enumeration_attack315.log`
- `Crontab_Enumeration_attack316.log`
- `Crontab_Enumeration_attack317.log`
- `Crontab_Enumeration_attack318.log`
- `Crontab_Enumeration_attack319.log`
- `Crontab_Enumeration_attack32.log`
- `Crontab_Enumeration_attack320.log`
- `Crontab_Enumeration_attack321.log`
- `Crontab_Enumeration_attack322.log`
- `Crontab_Enumeration_attack323.log`
- `Crontab_Enumeration_attack324.log`
- `Crontab_Enumeration_attack325.log`
- `Crontab_Enumeration_attack326.log`
- `Crontab_Enumeration_attack327.log`
- `Crontab_Enumeration_attack328.log`
- `Crontab_Enumeration_attack329.log`
- `Crontab_Enumeration_attack33.log`
- `Crontab_Enumeration_attack330.log`
- `Crontab_Enumeration_attack331.log`
- `Crontab_Enumeration_attack332.log`
- `Crontab_Enumeration_attack333.log`
- `Crontab_Enumeration_attack334.log`
- `Crontab_Enumeration_attack335.log`
- `Crontab_Enumeration_attack336.log`
- `Crontab_Enumeration_attack337.log`
- `Crontab_Enumeration_attack338.log`
- `Crontab_Enumeration_attack339.log`
- `Crontab_Enumeration_attack34.log`
- `Crontab_Enumeration_attack340.log`
- `Crontab_Enumeration_attack341.log`
- `Crontab_Enumeration_attack342.log`
- `Crontab_Enumeration_attack343.log`
- `Crontab_Enumeration_attack344.log`
- `Crontab_Enumeration_attack345.log`
- `Crontab_Enumeration_attack346.log`
- `Crontab_Enumeration_attack347.log`
- `Crontab_Enumeration_attack348.log`
- `Crontab_Enumeration_attack349.log`
- `Crontab_Enumeration_attack35.log`
- `Crontab_Enumeration_attack350.log`
- `Crontab_Enumeration_attack351.log`
- `Crontab_Enumeration_attack352.log`
- `Crontab_Enumeration_attack353.log`
- `Crontab_Enumeration_attack354.log`
- `Crontab_Enumeration_attack355.log`
- `Crontab_Enumeration_attack356.log`
- `Crontab_Enumeration_attack357.log`
- `Crontab_Enumeration_attack358.log`
- `Crontab_Enumeration_attack359.log`
- `Crontab_Enumeration_attack36.log`
- `Crontab_Enumeration_attack360.log`
- `Crontab_Enumeration_attack37.log`
- `Crontab_Enumeration_attack38.log`
- `Crontab_Enumeration_attack39.log`
- `Crontab_Enumeration_attack4.log`
- `Crontab_Enumeration_attack40.log`
- `Crontab_Enumeration_attack41.log`
- `Crontab_Enumeration_attack42.log`
- `Crontab_Enumeration_attack43.log`
- `Crontab_Enumeration_attack44.log`
- `Crontab_Enumeration_attack45.log`
- `Crontab_Enumeration_attack46.log`
- `Crontab_Enumeration_attack47.log`
- `Crontab_Enumeration_attack48.log`
- `Crontab_Enumeration_attack49.log`
- `Crontab_Enumeration_attack5.log`
- `Crontab_Enumeration_attack50.log`
- `Crontab_Enumeration_attack51.log`
- `Crontab_Enumeration_attack52.log`
- `Crontab_Enumeration_attack53.log`
- `Crontab_Enumeration_attack54.log`
- `Crontab_Enumeration_attack55.log`
- `Crontab_Enumeration_attack56.log`
- `Crontab_Enumeration_attack57.log`
- `Crontab_Enumeration_attack58.log`
- `Crontab_Enumeration_attack59.log`
- `Crontab_Enumeration_attack6.log`
- `Crontab_Enumeration_attack60.log`
- `Crontab_Enumeration_attack7.log`
- `Crontab_Enumeration_attack8.log`
- `Crontab_Enumeration_attack9.log`

---

### Local System Accounts Discovery - Linux

**Directory:** `local_account`

**Event Counts:**
- Total: 218
- Match Events: 86
- Evasion Events: 132

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218

**Log Files:**
- `Local_System_Accounts_Discovery_-_Linux_attack1.log`
- `Local_System_Accounts_Discovery_-_Linux_attack10.log`
- `Local_System_Accounts_Discovery_-_Linux_attack100.log`
- `Local_System_Accounts_Discovery_-_Linux_attack101.log`
- `Local_System_Accounts_Discovery_-_Linux_attack102.log`
- `Local_System_Accounts_Discovery_-_Linux_attack103.log`
- `Local_System_Accounts_Discovery_-_Linux_attack104.log`
- `Local_System_Accounts_Discovery_-_Linux_attack105.log`
- `Local_System_Accounts_Discovery_-_Linux_attack106.log`
- `Local_System_Accounts_Discovery_-_Linux_attack107.log`
- `Local_System_Accounts_Discovery_-_Linux_attack108.log`
- `Local_System_Accounts_Discovery_-_Linux_attack109.log`
- `Local_System_Accounts_Discovery_-_Linux_attack11.log`
- `Local_System_Accounts_Discovery_-_Linux_attack110.log`
- `Local_System_Accounts_Discovery_-_Linux_attack111.log`
- `Local_System_Accounts_Discovery_-_Linux_attack112.log`
- `Local_System_Accounts_Discovery_-_Linux_attack113.log`
- `Local_System_Accounts_Discovery_-_Linux_attack114.log`
- `Local_System_Accounts_Discovery_-_Linux_attack115.log`
- `Local_System_Accounts_Discovery_-_Linux_attack116.log`
- `Local_System_Accounts_Discovery_-_Linux_attack117.log`
- `Local_System_Accounts_Discovery_-_Linux_attack118.log`
- `Local_System_Accounts_Discovery_-_Linux_attack119.log`
- `Local_System_Accounts_Discovery_-_Linux_attack12.log`
- `Local_System_Accounts_Discovery_-_Linux_attack120.log`
- `Local_System_Accounts_Discovery_-_Linux_attack121.log`
- `Local_System_Accounts_Discovery_-_Linux_attack122.log`
- `Local_System_Accounts_Discovery_-_Linux_attack123.log`
- `Local_System_Accounts_Discovery_-_Linux_attack124.log`
- `Local_System_Accounts_Discovery_-_Linux_attack125.log`
- `Local_System_Accounts_Discovery_-_Linux_attack126.log`
- `Local_System_Accounts_Discovery_-_Linux_attack127.log`
- `Local_System_Accounts_Discovery_-_Linux_attack128.log`
- `Local_System_Accounts_Discovery_-_Linux_attack129.log`
- `Local_System_Accounts_Discovery_-_Linux_attack13.log`
- `Local_System_Accounts_Discovery_-_Linux_attack130.log`
- `Local_System_Accounts_Discovery_-_Linux_attack131.log`
- `Local_System_Accounts_Discovery_-_Linux_attack132.log`
- `Local_System_Accounts_Discovery_-_Linux_attack133.log`
- `Local_System_Accounts_Discovery_-_Linux_attack134.log`
- `Local_System_Accounts_Discovery_-_Linux_attack135.log`
- `Local_System_Accounts_Discovery_-_Linux_attack136.log`
- `Local_System_Accounts_Discovery_-_Linux_attack137.log`
- `Local_System_Accounts_Discovery_-_Linux_attack138.log`
- `Local_System_Accounts_Discovery_-_Linux_attack139.log`
- `Local_System_Accounts_Discovery_-_Linux_attack14.log`
- `Local_System_Accounts_Discovery_-_Linux_attack140.log`
- `Local_System_Accounts_Discovery_-_Linux_attack141.log`
- `Local_System_Accounts_Discovery_-_Linux_attack142.log`
- `Local_System_Accounts_Discovery_-_Linux_attack143.log`
- `Local_System_Accounts_Discovery_-_Linux_attack144.log`
- `Local_System_Accounts_Discovery_-_Linux_attack145.log`
- `Local_System_Accounts_Discovery_-_Linux_attack146.log`
- `Local_System_Accounts_Discovery_-_Linux_attack147.log`
- `Local_System_Accounts_Discovery_-_Linux_attack148.log`
- `Local_System_Accounts_Discovery_-_Linux_attack149.log`
- `Local_System_Accounts_Discovery_-_Linux_attack15.log`
- `Local_System_Accounts_Discovery_-_Linux_attack150.log`
- `Local_System_Accounts_Discovery_-_Linux_attack151.log`
- `Local_System_Accounts_Discovery_-_Linux_attack152.log`
- `Local_System_Accounts_Discovery_-_Linux_attack153.log`
- `Local_System_Accounts_Discovery_-_Linux_attack154.log`
- `Local_System_Accounts_Discovery_-_Linux_attack155.log`
- `Local_System_Accounts_Discovery_-_Linux_attack156.log`
- `Local_System_Accounts_Discovery_-_Linux_attack157.log`
- `Local_System_Accounts_Discovery_-_Linux_attack158.log`
- `Local_System_Accounts_Discovery_-_Linux_attack159.log`
- `Local_System_Accounts_Discovery_-_Linux_attack16.log`
- `Local_System_Accounts_Discovery_-_Linux_attack160.log`
- `Local_System_Accounts_Discovery_-_Linux_attack161.log`
- `Local_System_Accounts_Discovery_-_Linux_attack162.log`
- `Local_System_Accounts_Discovery_-_Linux_attack163.log`
- `Local_System_Accounts_Discovery_-_Linux_attack164.log`
- `Local_System_Accounts_Discovery_-_Linux_attack165.log`
- `Local_System_Accounts_Discovery_-_Linux_attack166.log`
- `Local_System_Accounts_Discovery_-_Linux_attack167.log`
- `Local_System_Accounts_Discovery_-_Linux_attack168.log`
- `Local_System_Accounts_Discovery_-_Linux_attack169.log`
- `Local_System_Accounts_Discovery_-_Linux_attack17.log`
- `Local_System_Accounts_Discovery_-_Linux_attack170.log`
- `Local_System_Accounts_Discovery_-_Linux_attack171.log`
- `Local_System_Accounts_Discovery_-_Linux_attack172.log`
- `Local_System_Accounts_Discovery_-_Linux_attack173.log`
- `Local_System_Accounts_Discovery_-_Linux_attack174.log`
- `Local_System_Accounts_Discovery_-_Linux_attack175.log`
- `Local_System_Accounts_Discovery_-_Linux_attack176.log`
- `Local_System_Accounts_Discovery_-_Linux_attack177.log`
- `Local_System_Accounts_Discovery_-_Linux_attack178.log`
- `Local_System_Accounts_Discovery_-_Linux_attack179.log`
- `Local_System_Accounts_Discovery_-_Linux_attack18.log`
- `Local_System_Accounts_Discovery_-_Linux_attack180.log`
- `Local_System_Accounts_Discovery_-_Linux_attack181.log`
- `Local_System_Accounts_Discovery_-_Linux_attack182.log`
- `Local_System_Accounts_Discovery_-_Linux_attack183.log`
- `Local_System_Accounts_Discovery_-_Linux_attack184.log`
- `Local_System_Accounts_Discovery_-_Linux_attack185.log`
- `Local_System_Accounts_Discovery_-_Linux_attack186.log`
- `Local_System_Accounts_Discovery_-_Linux_attack187.log`
- `Local_System_Accounts_Discovery_-_Linux_attack188.log`
- `Local_System_Accounts_Discovery_-_Linux_attack189.log`
- `Local_System_Accounts_Discovery_-_Linux_attack19.log`
- `Local_System_Accounts_Discovery_-_Linux_attack190.log`
- `Local_System_Accounts_Discovery_-_Linux_attack191.log`
- `Local_System_Accounts_Discovery_-_Linux_attack192.log`
- `Local_System_Accounts_Discovery_-_Linux_attack193.log`
- `Local_System_Accounts_Discovery_-_Linux_attack194.log`
- `Local_System_Accounts_Discovery_-_Linux_attack195.log`
- `Local_System_Accounts_Discovery_-_Linux_attack196.log`
- `Local_System_Accounts_Discovery_-_Linux_attack197.log`
- `Local_System_Accounts_Discovery_-_Linux_attack198.log`
- `Local_System_Accounts_Discovery_-_Linux_attack199.log`
- `Local_System_Accounts_Discovery_-_Linux_attack2.log`
- `Local_System_Accounts_Discovery_-_Linux_attack20.log`
- `Local_System_Accounts_Discovery_-_Linux_attack200.log`
- `Local_System_Accounts_Discovery_-_Linux_attack201.log`
- `Local_System_Accounts_Discovery_-_Linux_attack202.log`
- `Local_System_Accounts_Discovery_-_Linux_attack203.log`
- `Local_System_Accounts_Discovery_-_Linux_attack204.log`
- `Local_System_Accounts_Discovery_-_Linux_attack205.log`
- `Local_System_Accounts_Discovery_-_Linux_attack206.log`
- `Local_System_Accounts_Discovery_-_Linux_attack207.log`
- `Local_System_Accounts_Discovery_-_Linux_attack208.log`
- `Local_System_Accounts_Discovery_-_Linux_attack209.log`
- `Local_System_Accounts_Discovery_-_Linux_attack21.log`
- `Local_System_Accounts_Discovery_-_Linux_attack210.log`
- `Local_System_Accounts_Discovery_-_Linux_attack211.log`
- `Local_System_Accounts_Discovery_-_Linux_attack212.log`
- `Local_System_Accounts_Discovery_-_Linux_attack213.log`
- `Local_System_Accounts_Discovery_-_Linux_attack214.log`
- `Local_System_Accounts_Discovery_-_Linux_attack215.log`
- `Local_System_Accounts_Discovery_-_Linux_attack216.log`
- `Local_System_Accounts_Discovery_-_Linux_attack217.log`
- `Local_System_Accounts_Discovery_-_Linux_attack218.log`
- `Local_System_Accounts_Discovery_-_Linux_attack22.log`
- `Local_System_Accounts_Discovery_-_Linux_attack23.log`
- `Local_System_Accounts_Discovery_-_Linux_attack24.log`
- `Local_System_Accounts_Discovery_-_Linux_attack25.log`
- `Local_System_Accounts_Discovery_-_Linux_attack26.log`
- `Local_System_Accounts_Discovery_-_Linux_attack27.log`
- `Local_System_Accounts_Discovery_-_Linux_attack28.log`
- `Local_System_Accounts_Discovery_-_Linux_attack29.log`
- `Local_System_Accounts_Discovery_-_Linux_attack3.log`
- `Local_System_Accounts_Discovery_-_Linux_attack30.log`
- `Local_System_Accounts_Discovery_-_Linux_attack31.log`
- `Local_System_Accounts_Discovery_-_Linux_attack32.log`
- `Local_System_Accounts_Discovery_-_Linux_attack33.log`
- `Local_System_Accounts_Discovery_-_Linux_attack34.log`
- `Local_System_Accounts_Discovery_-_Linux_attack35.log`
- `Local_System_Accounts_Discovery_-_Linux_attack36.log`
- `Local_System_Accounts_Discovery_-_Linux_attack37.log`
- `Local_System_Accounts_Discovery_-_Linux_attack38.log`
- `Local_System_Accounts_Discovery_-_Linux_attack39.log`
- `Local_System_Accounts_Discovery_-_Linux_attack4.log`
- `Local_System_Accounts_Discovery_-_Linux_attack40.log`
- `Local_System_Accounts_Discovery_-_Linux_attack41.log`
- `Local_System_Accounts_Discovery_-_Linux_attack42.log`
- `Local_System_Accounts_Discovery_-_Linux_attack43.log`
- `Local_System_Accounts_Discovery_-_Linux_attack44.log`
- `Local_System_Accounts_Discovery_-_Linux_attack45.log`
- `Local_System_Accounts_Discovery_-_Linux_attack46.log`
- `Local_System_Accounts_Discovery_-_Linux_attack47.log`
- `Local_System_Accounts_Discovery_-_Linux_attack48.log`
- `Local_System_Accounts_Discovery_-_Linux_attack49.log`
- `Local_System_Accounts_Discovery_-_Linux_attack5.log`
- `Local_System_Accounts_Discovery_-_Linux_attack50.log`
- `Local_System_Accounts_Discovery_-_Linux_attack51.log`
- `Local_System_Accounts_Discovery_-_Linux_attack52.log`
- `Local_System_Accounts_Discovery_-_Linux_attack53.log`
- `Local_System_Accounts_Discovery_-_Linux_attack54.log`
- `Local_System_Accounts_Discovery_-_Linux_attack55.log`
- `Local_System_Accounts_Discovery_-_Linux_attack56.log`
- `Local_System_Accounts_Discovery_-_Linux_attack57.log`
- `Local_System_Accounts_Discovery_-_Linux_attack58.log`
- `Local_System_Accounts_Discovery_-_Linux_attack59.log`
- `Local_System_Accounts_Discovery_-_Linux_attack6.log`
- `Local_System_Accounts_Discovery_-_Linux_attack60.log`
- `Local_System_Accounts_Discovery_-_Linux_attack61.log`
- `Local_System_Accounts_Discovery_-_Linux_attack62.log`
- `Local_System_Accounts_Discovery_-_Linux_attack63.log`
- `Local_System_Accounts_Discovery_-_Linux_attack64.log`
- `Local_System_Accounts_Discovery_-_Linux_attack65.log`
- `Local_System_Accounts_Discovery_-_Linux_attack66.log`
- `Local_System_Accounts_Discovery_-_Linux_attack67.log`
- `Local_System_Accounts_Discovery_-_Linux_attack68.log`
- `Local_System_Accounts_Discovery_-_Linux_attack69.log`
- `Local_System_Accounts_Discovery_-_Linux_attack7.log`
- `Local_System_Accounts_Discovery_-_Linux_attack70.log`
- `Local_System_Accounts_Discovery_-_Linux_attack71.log`
- `Local_System_Accounts_Discovery_-_Linux_attack72.log`
- `Local_System_Accounts_Discovery_-_Linux_attack73.log`
- `Local_System_Accounts_Discovery_-_Linux_attack74.log`
- `Local_System_Accounts_Discovery_-_Linux_attack75.log`
- `Local_System_Accounts_Discovery_-_Linux_attack76.log`
- `Local_System_Accounts_Discovery_-_Linux_attack77.log`
- `Local_System_Accounts_Discovery_-_Linux_attack78.log`
- `Local_System_Accounts_Discovery_-_Linux_attack79.log`
- `Local_System_Accounts_Discovery_-_Linux_attack8.log`
- `Local_System_Accounts_Discovery_-_Linux_attack80.log`
- `Local_System_Accounts_Discovery_-_Linux_attack81.log`
- `Local_System_Accounts_Discovery_-_Linux_attack82.log`
- `Local_System_Accounts_Discovery_-_Linux_attack83.log`
- `Local_System_Accounts_Discovery_-_Linux_attack84.log`
- `Local_System_Accounts_Discovery_-_Linux_attack85.log`
- `Local_System_Accounts_Discovery_-_Linux_attack86.log`
- `Local_System_Accounts_Discovery_-_Linux_attack87.log`
- `Local_System_Accounts_Discovery_-_Linux_attack88.log`
- `Local_System_Accounts_Discovery_-_Linux_attack89.log`
- `Local_System_Accounts_Discovery_-_Linux_attack9.log`
- `Local_System_Accounts_Discovery_-_Linux_attack90.log`
- `Local_System_Accounts_Discovery_-_Linux_attack91.log`
- `Local_System_Accounts_Discovery_-_Linux_attack92.log`
- `Local_System_Accounts_Discovery_-_Linux_attack93.log`
- `Local_System_Accounts_Discovery_-_Linux_attack94.log`
- `Local_System_Accounts_Discovery_-_Linux_attack95.log`
- `Local_System_Accounts_Discovery_-_Linux_attack96.log`
- `Local_System_Accounts_Discovery_-_Linux_attack97.log`
- `Local_System_Accounts_Discovery_-_Linux_attack98.log`
- `Local_System_Accounts_Discovery_-_Linux_attack99.log`

---

### Kaspersky Endpoint Security Stopped Via CommandLine - Linux

**Directory:** `av_kaspersky_av_disabled`

**Sigma Rule ID:** `36388120-b3f1-4ce9-b50b-280d9a7f4c04`

**Event Counts:**
- Total: 215
- Match Events: 144
- Evasion Events: 71

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 101, 102, 104, 105, 106, 108, 109, 113, 114, 115, 116, 118, 120, 121, 124, 125, 128, 129, 130, 132, 133, 134, 135, 136, 137, 138, 139, 140, 143, 144, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252

**Log Files:**
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack1.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack10.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack101.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack102.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack104.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack105.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack106.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack108.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack109.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack11.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack113.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack114.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack115.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack116.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack118.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack12.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack120.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack121.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack124.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack125.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack128.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack129.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack13.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack130.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack132.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack133.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack134.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack135.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack136.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack137.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack138.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack139.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack140.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack143.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack144.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack149.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack150.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack151.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack152.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack153.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack154.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack155.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack156.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack157.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack158.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack159.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack160.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack161.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack162.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack163.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack164.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack165.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack166.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack167.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack168.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack169.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack170.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack171.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack172.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack173.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack174.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack175.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack176.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack177.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack178.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack179.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack180.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack181.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack182.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack183.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack184.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack185.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack186.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack187.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack188.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack189.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack19.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack190.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack191.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack192.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack193.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack194.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack195.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack196.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack197.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack198.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack199.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack2.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack20.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack200.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack201.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack202.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack203.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack204.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack205.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack206.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack207.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack208.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack209.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack21.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack210.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack211.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack212.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack213.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack214.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack215.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack216.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack217.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack218.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack219.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack22.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack220.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack221.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack222.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack223.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack224.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack225.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack226.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack227.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack228.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack229.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack23.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack230.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack231.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack232.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack233.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack234.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack235.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack236.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack237.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack238.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack239.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack24.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack240.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack241.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack242.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack243.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack244.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack245.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack246.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack247.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack248.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack249.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack25.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack250.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack251.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack252.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack26.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack27.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack28.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack29.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack3.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack30.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack31.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack32.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack33.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack34.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack35.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack36.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack37.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack38.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack39.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack4.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack5.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack51.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack52.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack53.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack54.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack55.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack56.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack57.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack58.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack59.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack60.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack61.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack62.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack63.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack64.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack65.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack66.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack67.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack68.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack69.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack70.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack71.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack72.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack73.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack74.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack75.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack76.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack77.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack78.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack79.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack8.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack80.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack81.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack82.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack83.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack84.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack85.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack86.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack87.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack88.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack89.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack9.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack90.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack91.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack92.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack93.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack94.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack95.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack96.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack97.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack98.log`
- `Kaspersky_Endpoint_Security_Stopped_Via_CommandLine_attack99.log`

---

### Clear Linux Logs

**Directory:** `clear_logs`

**Sigma Rule ID:** `80915f59-9b56-4616-9de0-fd0dea6c12fe`

**Event Counts:**
- Total: 210
- Match Events: 195
- Evasion Events: 15

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 42, 43, 44, 45, 46, 47, 51, 52, 53, 55, 56, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 135, 136, 137, 141, 142, 143, 144, 145, 146, 148, 151, 154, 155, 157, 160, 161, 162, 164, 166, 167, 169, 171, 174, 175, 178, 181, 186, 187, 191, 193, 196, 199, 200, 202, 206, 208, 214, 218, 221, 225, 227, 229, 231, 235, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 254, 255, 256, 258, 260, 261, 262, 266, 267, 268, 270, 273, 274, 275, 276, 277, 282, 283, 289, 290, 292, 293, 294, 295, 299, 318, 321, 334, 356

**Log Files:**
- `Clear_Linux_Logs_attack1.log`
- `Clear_Linux_Logs_attack10.log`
- `Clear_Linux_Logs_attack100.log`
- `Clear_Linux_Logs_attack101.log`
- `Clear_Linux_Logs_attack102.log`
- `Clear_Linux_Logs_attack103.log`
- `Clear_Linux_Logs_attack104.log`
- `Clear_Linux_Logs_attack105.log`
- `Clear_Linux_Logs_attack106.log`
- `Clear_Linux_Logs_attack107.log`
- `Clear_Linux_Logs_attack108.log`
- `Clear_Linux_Logs_attack109.log`
- `Clear_Linux_Logs_attack11.log`
- `Clear_Linux_Logs_attack110.log`
- `Clear_Linux_Logs_attack111.log`
- `Clear_Linux_Logs_attack112.log`
- `Clear_Linux_Logs_attack113.log`
- `Clear_Linux_Logs_attack114.log`
- `Clear_Linux_Logs_attack115.log`
- `Clear_Linux_Logs_attack116.log`
- `Clear_Linux_Logs_attack117.log`
- `Clear_Linux_Logs_attack118.log`
- `Clear_Linux_Logs_attack119.log`
- `Clear_Linux_Logs_attack12.log`
- `Clear_Linux_Logs_attack120.log`
- `Clear_Linux_Logs_attack121.log`
- `Clear_Linux_Logs_attack122.log`
- `Clear_Linux_Logs_attack123.log`
- `Clear_Linux_Logs_attack124.log`
- `Clear_Linux_Logs_attack125.log`
- `Clear_Linux_Logs_attack126.log`
- `Clear_Linux_Logs_attack127.log`
- `Clear_Linux_Logs_attack128.log`
- `Clear_Linux_Logs_attack129.log`
- `Clear_Linux_Logs_attack13.log`
- `Clear_Linux_Logs_attack130.log`
- `Clear_Linux_Logs_attack131.log`
- `Clear_Linux_Logs_attack132.log`
- `Clear_Linux_Logs_attack135.log`
- `Clear_Linux_Logs_attack136.log`
- `Clear_Linux_Logs_attack137.log`
- `Clear_Linux_Logs_attack14.log`
- `Clear_Linux_Logs_attack141.log`
- `Clear_Linux_Logs_attack142.log`
- `Clear_Linux_Logs_attack143.log`
- `Clear_Linux_Logs_attack144.log`
- `Clear_Linux_Logs_attack145.log`
- `Clear_Linux_Logs_attack146.log`
- `Clear_Linux_Logs_attack148.log`
- `Clear_Linux_Logs_attack15.log`
- `Clear_Linux_Logs_attack151.log`
- `Clear_Linux_Logs_attack154.log`
- `Clear_Linux_Logs_attack155.log`
- `Clear_Linux_Logs_attack157.log`
- `Clear_Linux_Logs_attack160.log`
- `Clear_Linux_Logs_attack161.log`
- `Clear_Linux_Logs_attack162.log`
- `Clear_Linux_Logs_attack164.log`
- `Clear_Linux_Logs_attack166.log`
- `Clear_Linux_Logs_attack167.log`
- `Clear_Linux_Logs_attack169.log`
- `Clear_Linux_Logs_attack17.log`
- `Clear_Linux_Logs_attack171.log`
- `Clear_Linux_Logs_attack174.log`
- `Clear_Linux_Logs_attack175.log`
- `Clear_Linux_Logs_attack178.log`
- `Clear_Linux_Logs_attack18.log`
- `Clear_Linux_Logs_attack181.log`
- `Clear_Linux_Logs_attack186.log`
- `Clear_Linux_Logs_attack187.log`
- `Clear_Linux_Logs_attack19.log`
- `Clear_Linux_Logs_attack191.log`
- `Clear_Linux_Logs_attack193.log`
- `Clear_Linux_Logs_attack196.log`
- `Clear_Linux_Logs_attack199.log`
- `Clear_Linux_Logs_attack2.log`
- `Clear_Linux_Logs_attack20.log`
- `Clear_Linux_Logs_attack200.log`
- `Clear_Linux_Logs_attack202.log`
- `Clear_Linux_Logs_attack206.log`
- `Clear_Linux_Logs_attack208.log`
- `Clear_Linux_Logs_attack21.log`
- `Clear_Linux_Logs_attack214.log`
- `Clear_Linux_Logs_attack218.log`
- `Clear_Linux_Logs_attack22.log`
- `Clear_Linux_Logs_attack221.log`
- `Clear_Linux_Logs_attack225.log`
- `Clear_Linux_Logs_attack227.log`
- `Clear_Linux_Logs_attack229.log`
- `Clear_Linux_Logs_attack23.log`
- `Clear_Linux_Logs_attack231.log`
- `Clear_Linux_Logs_attack235.log`
- `Clear_Linux_Logs_attack24.log`
- `Clear_Linux_Logs_attack241.log`
- `Clear_Linux_Logs_attack242.log`
- `Clear_Linux_Logs_attack243.log`
- `Clear_Linux_Logs_attack244.log`
- `Clear_Linux_Logs_attack245.log`
- `Clear_Linux_Logs_attack246.log`
- `Clear_Linux_Logs_attack247.log`
- `Clear_Linux_Logs_attack248.log`
- `Clear_Linux_Logs_attack249.log`
- `Clear_Linux_Logs_attack25.log`
- `Clear_Linux_Logs_attack250.log`
- `Clear_Linux_Logs_attack251.log`
- `Clear_Linux_Logs_attack252.log`
- `Clear_Linux_Logs_attack254.log`
- `Clear_Linux_Logs_attack255.log`
- `Clear_Linux_Logs_attack256.log`
- `Clear_Linux_Logs_attack258.log`
- `Clear_Linux_Logs_attack26.log`
- `Clear_Linux_Logs_attack260.log`
- `Clear_Linux_Logs_attack261.log`
- `Clear_Linux_Logs_attack262.log`
- `Clear_Linux_Logs_attack266.log`
- `Clear_Linux_Logs_attack267.log`
- `Clear_Linux_Logs_attack268.log`
- `Clear_Linux_Logs_attack27.log`
- `Clear_Linux_Logs_attack270.log`
- `Clear_Linux_Logs_attack273.log`
- `Clear_Linux_Logs_attack274.log`
- `Clear_Linux_Logs_attack275.log`
- `Clear_Linux_Logs_attack276.log`
- `Clear_Linux_Logs_attack277.log`
- `Clear_Linux_Logs_attack28.log`
- `Clear_Linux_Logs_attack282.log`
- `Clear_Linux_Logs_attack283.log`
- `Clear_Linux_Logs_attack289.log`
- `Clear_Linux_Logs_attack29.log`
- `Clear_Linux_Logs_attack290.log`
- `Clear_Linux_Logs_attack292.log`
- `Clear_Linux_Logs_attack293.log`
- `Clear_Linux_Logs_attack294.log`
- `Clear_Linux_Logs_attack295.log`
- `Clear_Linux_Logs_attack299.log`
- `Clear_Linux_Logs_attack3.log`
- `Clear_Linux_Logs_attack30.log`
- `Clear_Linux_Logs_attack31.log`
- `Clear_Linux_Logs_attack318.log`
- `Clear_Linux_Logs_attack32.log`
- `Clear_Linux_Logs_attack321.log`
- `Clear_Linux_Logs_attack33.log`
- `Clear_Linux_Logs_attack334.log`
- `Clear_Linux_Logs_attack34.log`
- `Clear_Linux_Logs_attack35.log`
- `Clear_Linux_Logs_attack356.log`
- `Clear_Linux_Logs_attack36.log`
- `Clear_Linux_Logs_attack37.log`
- `Clear_Linux_Logs_attack38.log`
- `Clear_Linux_Logs_attack39.log`
- `Clear_Linux_Logs_attack4.log`
- `Clear_Linux_Logs_attack40.log`
- `Clear_Linux_Logs_attack42.log`
- `Clear_Linux_Logs_attack43.log`
- `Clear_Linux_Logs_attack44.log`
- `Clear_Linux_Logs_attack45.log`
- `Clear_Linux_Logs_attack46.log`
- `Clear_Linux_Logs_attack47.log`
- `Clear_Linux_Logs_attack5.log`
- `Clear_Linux_Logs_attack51.log`
- `Clear_Linux_Logs_attack52.log`
- `Clear_Linux_Logs_attack53.log`
- `Clear_Linux_Logs_attack55.log`
- `Clear_Linux_Logs_attack56.log`
- `Clear_Linux_Logs_attack58.log`
- `Clear_Linux_Logs_attack59.log`
- `Clear_Linux_Logs_attack6.log`
- `Clear_Linux_Logs_attack60.log`
- `Clear_Linux_Logs_attack61.log`
- `Clear_Linux_Logs_attack62.log`
- `Clear_Linux_Logs_attack63.log`
- `Clear_Linux_Logs_attack64.log`
- `Clear_Linux_Logs_attack65.log`
- `Clear_Linux_Logs_attack66.log`
- `Clear_Linux_Logs_attack67.log`
- `Clear_Linux_Logs_attack68.log`
- `Clear_Linux_Logs_attack69.log`
- `Clear_Linux_Logs_attack7.log`
- `Clear_Linux_Logs_attack70.log`
- `Clear_Linux_Logs_attack71.log`
- `Clear_Linux_Logs_attack72.log`
- `Clear_Linux_Logs_attack73.log`
- `Clear_Linux_Logs_attack74.log`
- `Clear_Linux_Logs_attack75.log`
- `Clear_Linux_Logs_attack76.log`
- `Clear_Linux_Logs_attack77.log`
- `Clear_Linux_Logs_attack78.log`
- `Clear_Linux_Logs_attack79.log`
- `Clear_Linux_Logs_attack8.log`
- `Clear_Linux_Logs_attack80.log`
- `Clear_Linux_Logs_attack81.log`
- `Clear_Linux_Logs_attack82.log`
- `Clear_Linux_Logs_attack83.log`
- `Clear_Linux_Logs_attack84.log`
- `Clear_Linux_Logs_attack85.log`
- `Clear_Linux_Logs_attack86.log`
- `Clear_Linux_Logs_attack87.log`
- `Clear_Linux_Logs_attack88.log`
- `Clear_Linux_Logs_attack89.log`
- `Clear_Linux_Logs_attack9.log`
- `Clear_Linux_Logs_attack90.log`
- `Clear_Linux_Logs_attack91.log`
- `Clear_Linux_Logs_attack92.log`
- `Clear_Linux_Logs_attack93.log`
- `Clear_Linux_Logs_attack94.log`
- `Clear_Linux_Logs_attack95.log`
- `Clear_Linux_Logs_attack96.log`
- `Clear_Linux_Logs_attack97.log`
- `Clear_Linux_Logs_attack98.log`
- `Clear_Linux_Logs_attack99.log`

---

### DD File Overwrite

**Directory:** `dd_file_overwrite`

**Sigma Rule ID:** `2953194b-e33c-4859-b9e8-05948c167447`

**Event Counts:**
- Total: 206
- Match Events: 106
- Evasion Events: 100

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206

**Log Files:**
- `DD_File_Overwrite_attack1.log`
- `DD_File_Overwrite_attack10.log`
- `DD_File_Overwrite_attack100.log`
- `DD_File_Overwrite_attack101.log`
- `DD_File_Overwrite_attack102.log`
- `DD_File_Overwrite_attack103.log`
- `DD_File_Overwrite_attack104.log`
- `DD_File_Overwrite_attack105.log`
- `DD_File_Overwrite_attack106.log`
- `DD_File_Overwrite_attack107.log`
- `DD_File_Overwrite_attack108.log`
- `DD_File_Overwrite_attack109.log`
- `DD_File_Overwrite_attack11.log`
- `DD_File_Overwrite_attack110.log`
- `DD_File_Overwrite_attack111.log`
- `DD_File_Overwrite_attack112.log`
- `DD_File_Overwrite_attack113.log`
- `DD_File_Overwrite_attack114.log`
- `DD_File_Overwrite_attack115.log`
- `DD_File_Overwrite_attack116.log`
- `DD_File_Overwrite_attack117.log`
- `DD_File_Overwrite_attack118.log`
- `DD_File_Overwrite_attack119.log`
- `DD_File_Overwrite_attack12.log`
- `DD_File_Overwrite_attack120.log`
- `DD_File_Overwrite_attack121.log`
- `DD_File_Overwrite_attack122.log`
- `DD_File_Overwrite_attack123.log`
- `DD_File_Overwrite_attack124.log`
- `DD_File_Overwrite_attack125.log`
- `DD_File_Overwrite_attack126.log`
- `DD_File_Overwrite_attack127.log`
- `DD_File_Overwrite_attack128.log`
- `DD_File_Overwrite_attack129.log`
- `DD_File_Overwrite_attack13.log`
- `DD_File_Overwrite_attack130.log`
- `DD_File_Overwrite_attack131.log`
- `DD_File_Overwrite_attack132.log`
- `DD_File_Overwrite_attack133.log`
- `DD_File_Overwrite_attack134.log`
- `DD_File_Overwrite_attack135.log`
- `DD_File_Overwrite_attack136.log`
- `DD_File_Overwrite_attack137.log`
- `DD_File_Overwrite_attack138.log`
- `DD_File_Overwrite_attack139.log`
- `DD_File_Overwrite_attack14.log`
- `DD_File_Overwrite_attack140.log`
- `DD_File_Overwrite_attack141.log`
- `DD_File_Overwrite_attack142.log`
- `DD_File_Overwrite_attack143.log`
- `DD_File_Overwrite_attack144.log`
- `DD_File_Overwrite_attack145.log`
- `DD_File_Overwrite_attack146.log`
- `DD_File_Overwrite_attack147.log`
- `DD_File_Overwrite_attack148.log`
- `DD_File_Overwrite_attack149.log`
- `DD_File_Overwrite_attack15.log`
- `DD_File_Overwrite_attack150.log`
- `DD_File_Overwrite_attack151.log`
- `DD_File_Overwrite_attack152.log`
- `DD_File_Overwrite_attack153.log`
- `DD_File_Overwrite_attack154.log`
- `DD_File_Overwrite_attack155.log`
- `DD_File_Overwrite_attack156.log`
- `DD_File_Overwrite_attack157.log`
- `DD_File_Overwrite_attack158.log`
- `DD_File_Overwrite_attack159.log`
- `DD_File_Overwrite_attack16.log`
- `DD_File_Overwrite_attack160.log`
- `DD_File_Overwrite_attack161.log`
- `DD_File_Overwrite_attack162.log`
- `DD_File_Overwrite_attack163.log`
- `DD_File_Overwrite_attack164.log`
- `DD_File_Overwrite_attack165.log`
- `DD_File_Overwrite_attack166.log`
- `DD_File_Overwrite_attack167.log`
- `DD_File_Overwrite_attack168.log`
- `DD_File_Overwrite_attack169.log`
- `DD_File_Overwrite_attack17.log`
- `DD_File_Overwrite_attack170.log`
- `DD_File_Overwrite_attack171.log`
- `DD_File_Overwrite_attack172.log`
- `DD_File_Overwrite_attack173.log`
- `DD_File_Overwrite_attack174.log`
- `DD_File_Overwrite_attack175.log`
- `DD_File_Overwrite_attack176.log`
- `DD_File_Overwrite_attack177.log`
- `DD_File_Overwrite_attack178.log`
- `DD_File_Overwrite_attack179.log`
- `DD_File_Overwrite_attack18.log`
- `DD_File_Overwrite_attack180.log`
- `DD_File_Overwrite_attack181.log`
- `DD_File_Overwrite_attack182.log`
- `DD_File_Overwrite_attack183.log`
- `DD_File_Overwrite_attack184.log`
- `DD_File_Overwrite_attack185.log`
- `DD_File_Overwrite_attack186.log`
- `DD_File_Overwrite_attack187.log`
- `DD_File_Overwrite_attack188.log`
- `DD_File_Overwrite_attack189.log`
- `DD_File_Overwrite_attack19.log`
- `DD_File_Overwrite_attack190.log`
- `DD_File_Overwrite_attack191.log`
- `DD_File_Overwrite_attack192.log`
- `DD_File_Overwrite_attack193.log`
- `DD_File_Overwrite_attack194.log`
- `DD_File_Overwrite_attack195.log`
- `DD_File_Overwrite_attack196.log`
- `DD_File_Overwrite_attack197.log`
- `DD_File_Overwrite_attack198.log`
- `DD_File_Overwrite_attack199.log`
- `DD_File_Overwrite_attack2.log`
- `DD_File_Overwrite_attack20.log`
- `DD_File_Overwrite_attack200.log`
- `DD_File_Overwrite_attack201.log`
- `DD_File_Overwrite_attack202.log`
- `DD_File_Overwrite_attack203.log`
- `DD_File_Overwrite_attack204.log`
- `DD_File_Overwrite_attack205.log`
- `DD_File_Overwrite_attack206.log`
- `DD_File_Overwrite_attack21.log`
- `DD_File_Overwrite_attack22.log`
- `DD_File_Overwrite_attack23.log`
- `DD_File_Overwrite_attack24.log`
- `DD_File_Overwrite_attack25.log`
- `DD_File_Overwrite_attack26.log`
- `DD_File_Overwrite_attack27.log`
- `DD_File_Overwrite_attack28.log`
- `DD_File_Overwrite_attack29.log`
- `DD_File_Overwrite_attack3.log`
- `DD_File_Overwrite_attack30.log`
- `DD_File_Overwrite_attack31.log`
- `DD_File_Overwrite_attack32.log`
- `DD_File_Overwrite_attack33.log`
- `DD_File_Overwrite_attack34.log`
- `DD_File_Overwrite_attack35.log`
- `DD_File_Overwrite_attack36.log`
- `DD_File_Overwrite_attack37.log`
- `DD_File_Overwrite_attack38.log`
- `DD_File_Overwrite_attack39.log`
- `DD_File_Overwrite_attack4.log`
- `DD_File_Overwrite_attack40.log`
- `DD_File_Overwrite_attack41.log`
- `DD_File_Overwrite_attack42.log`
- `DD_File_Overwrite_attack43.log`
- `DD_File_Overwrite_attack44.log`
- `DD_File_Overwrite_attack45.log`
- `DD_File_Overwrite_attack46.log`
- `DD_File_Overwrite_attack47.log`
- `DD_File_Overwrite_attack48.log`
- `DD_File_Overwrite_attack49.log`
- `DD_File_Overwrite_attack5.log`
- `DD_File_Overwrite_attack50.log`
- `DD_File_Overwrite_attack51.log`
- `DD_File_Overwrite_attack52.log`
- `DD_File_Overwrite_attack53.log`
- `DD_File_Overwrite_attack54.log`
- `DD_File_Overwrite_attack55.log`
- `DD_File_Overwrite_attack56.log`
- `DD_File_Overwrite_attack57.log`
- `DD_File_Overwrite_attack58.log`
- `DD_File_Overwrite_attack59.log`
- `DD_File_Overwrite_attack6.log`
- `DD_File_Overwrite_attack60.log`
- `DD_File_Overwrite_attack61.log`
- `DD_File_Overwrite_attack62.log`
- `DD_File_Overwrite_attack63.log`
- `DD_File_Overwrite_attack64.log`
- `DD_File_Overwrite_attack65.log`
- `DD_File_Overwrite_attack66.log`
- `DD_File_Overwrite_attack67.log`
- `DD_File_Overwrite_attack68.log`
- `DD_File_Overwrite_attack69.log`
- `DD_File_Overwrite_attack7.log`
- `DD_File_Overwrite_attack70.log`
- `DD_File_Overwrite_attack71.log`
- `DD_File_Overwrite_attack72.log`
- `DD_File_Overwrite_attack73.log`
- `DD_File_Overwrite_attack74.log`
- `DD_File_Overwrite_attack75.log`
- `DD_File_Overwrite_attack76.log`
- `DD_File_Overwrite_attack77.log`
- `DD_File_Overwrite_attack78.log`
- `DD_File_Overwrite_attack79.log`
- `DD_File_Overwrite_attack8.log`
- `DD_File_Overwrite_attack80.log`
- `DD_File_Overwrite_attack81.log`
- `DD_File_Overwrite_attack82.log`
- `DD_File_Overwrite_attack83.log`
- `DD_File_Overwrite_attack84.log`
- `DD_File_Overwrite_attack85.log`
- `DD_File_Overwrite_attack86.log`
- `DD_File_Overwrite_attack87.log`
- `DD_File_Overwrite_attack88.log`
- `DD_File_Overwrite_attack89.log`
- `DD_File_Overwrite_attack9.log`
- `DD_File_Overwrite_attack90.log`
- `DD_File_Overwrite_attack91.log`
- `DD_File_Overwrite_attack92.log`
- `DD_File_Overwrite_attack93.log`
- `DD_File_Overwrite_attack94.log`
- `DD_File_Overwrite_attack95.log`
- `DD_File_Overwrite_attack96.log`
- `DD_File_Overwrite_attack97.log`
- `DD_File_Overwrite_attack98.log`
- `DD_File_Overwrite_attack99.log`

---

### Linux Crypto Mining Indicators

**Directory:** `crypto_mining`

**Sigma Rule ID:** `9069ea3c-b213-4c52-be13-86506a227ab1`

**Event Counts:**
- Total: 186
- Match Events: 30
- Evasion Events: 156

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186

**Log Files:**
- `Linux_Crypto_Mining_Indicators_attack1.log`
- `Linux_Crypto_Mining_Indicators_attack10.log`
- `Linux_Crypto_Mining_Indicators_attack100.log`
- `Linux_Crypto_Mining_Indicators_attack101.log`
- `Linux_Crypto_Mining_Indicators_attack102.log`
- `Linux_Crypto_Mining_Indicators_attack103.log`
- `Linux_Crypto_Mining_Indicators_attack104.log`
- `Linux_Crypto_Mining_Indicators_attack105.log`
- `Linux_Crypto_Mining_Indicators_attack106.log`
- `Linux_Crypto_Mining_Indicators_attack107.log`
- `Linux_Crypto_Mining_Indicators_attack108.log`
- `Linux_Crypto_Mining_Indicators_attack109.log`
- `Linux_Crypto_Mining_Indicators_attack11.log`
- `Linux_Crypto_Mining_Indicators_attack110.log`
- `Linux_Crypto_Mining_Indicators_attack111.log`
- `Linux_Crypto_Mining_Indicators_attack112.log`
- `Linux_Crypto_Mining_Indicators_attack113.log`
- `Linux_Crypto_Mining_Indicators_attack114.log`
- `Linux_Crypto_Mining_Indicators_attack115.log`
- `Linux_Crypto_Mining_Indicators_attack116.log`
- `Linux_Crypto_Mining_Indicators_attack117.log`
- `Linux_Crypto_Mining_Indicators_attack118.log`
- `Linux_Crypto_Mining_Indicators_attack119.log`
- `Linux_Crypto_Mining_Indicators_attack12.log`
- `Linux_Crypto_Mining_Indicators_attack120.log`
- `Linux_Crypto_Mining_Indicators_attack121.log`
- `Linux_Crypto_Mining_Indicators_attack122.log`
- `Linux_Crypto_Mining_Indicators_attack123.log`
- `Linux_Crypto_Mining_Indicators_attack124.log`
- `Linux_Crypto_Mining_Indicators_attack125.log`
- `Linux_Crypto_Mining_Indicators_attack126.log`
- `Linux_Crypto_Mining_Indicators_attack127.log`
- `Linux_Crypto_Mining_Indicators_attack128.log`
- `Linux_Crypto_Mining_Indicators_attack129.log`
- `Linux_Crypto_Mining_Indicators_attack13.log`
- `Linux_Crypto_Mining_Indicators_attack130.log`
- `Linux_Crypto_Mining_Indicators_attack131.log`
- `Linux_Crypto_Mining_Indicators_attack132.log`
- `Linux_Crypto_Mining_Indicators_attack133.log`
- `Linux_Crypto_Mining_Indicators_attack134.log`
- `Linux_Crypto_Mining_Indicators_attack135.log`
- `Linux_Crypto_Mining_Indicators_attack136.log`
- `Linux_Crypto_Mining_Indicators_attack137.log`
- `Linux_Crypto_Mining_Indicators_attack138.log`
- `Linux_Crypto_Mining_Indicators_attack139.log`
- `Linux_Crypto_Mining_Indicators_attack14.log`
- `Linux_Crypto_Mining_Indicators_attack140.log`
- `Linux_Crypto_Mining_Indicators_attack141.log`
- `Linux_Crypto_Mining_Indicators_attack142.log`
- `Linux_Crypto_Mining_Indicators_attack143.log`
- `Linux_Crypto_Mining_Indicators_attack144.log`
- `Linux_Crypto_Mining_Indicators_attack145.log`
- `Linux_Crypto_Mining_Indicators_attack146.log`
- `Linux_Crypto_Mining_Indicators_attack147.log`
- `Linux_Crypto_Mining_Indicators_attack148.log`
- `Linux_Crypto_Mining_Indicators_attack149.log`
- `Linux_Crypto_Mining_Indicators_attack15.log`
- `Linux_Crypto_Mining_Indicators_attack150.log`
- `Linux_Crypto_Mining_Indicators_attack151.log`
- `Linux_Crypto_Mining_Indicators_attack152.log`
- `Linux_Crypto_Mining_Indicators_attack153.log`
- `Linux_Crypto_Mining_Indicators_attack154.log`
- `Linux_Crypto_Mining_Indicators_attack155.log`
- `Linux_Crypto_Mining_Indicators_attack156.log`
- `Linux_Crypto_Mining_Indicators_attack157.log`
- `Linux_Crypto_Mining_Indicators_attack158.log`
- `Linux_Crypto_Mining_Indicators_attack159.log`
- `Linux_Crypto_Mining_Indicators_attack16.log`
- `Linux_Crypto_Mining_Indicators_attack160.log`
- `Linux_Crypto_Mining_Indicators_attack161.log`
- `Linux_Crypto_Mining_Indicators_attack162.log`
- `Linux_Crypto_Mining_Indicators_attack163.log`
- `Linux_Crypto_Mining_Indicators_attack164.log`
- `Linux_Crypto_Mining_Indicators_attack165.log`
- `Linux_Crypto_Mining_Indicators_attack166.log`
- `Linux_Crypto_Mining_Indicators_attack167.log`
- `Linux_Crypto_Mining_Indicators_attack168.log`
- `Linux_Crypto_Mining_Indicators_attack169.log`
- `Linux_Crypto_Mining_Indicators_attack17.log`
- `Linux_Crypto_Mining_Indicators_attack170.log`
- `Linux_Crypto_Mining_Indicators_attack171.log`
- `Linux_Crypto_Mining_Indicators_attack172.log`
- `Linux_Crypto_Mining_Indicators_attack173.log`
- `Linux_Crypto_Mining_Indicators_attack174.log`
- `Linux_Crypto_Mining_Indicators_attack175.log`
- `Linux_Crypto_Mining_Indicators_attack176.log`
- `Linux_Crypto_Mining_Indicators_attack177.log`
- `Linux_Crypto_Mining_Indicators_attack178.log`
- `Linux_Crypto_Mining_Indicators_attack179.log`
- `Linux_Crypto_Mining_Indicators_attack18.log`
- `Linux_Crypto_Mining_Indicators_attack180.log`
- `Linux_Crypto_Mining_Indicators_attack181.log`
- `Linux_Crypto_Mining_Indicators_attack182.log`
- `Linux_Crypto_Mining_Indicators_attack183.log`
- `Linux_Crypto_Mining_Indicators_attack184.log`
- `Linux_Crypto_Mining_Indicators_attack185.log`
- `Linux_Crypto_Mining_Indicators_attack186.log`
- `Linux_Crypto_Mining_Indicators_attack19.log`
- `Linux_Crypto_Mining_Indicators_attack2.log`
- `Linux_Crypto_Mining_Indicators_attack20.log`
- `Linux_Crypto_Mining_Indicators_attack21.log`
- `Linux_Crypto_Mining_Indicators_attack22.log`
- `Linux_Crypto_Mining_Indicators_attack23.log`
- `Linux_Crypto_Mining_Indicators_attack24.log`
- `Linux_Crypto_Mining_Indicators_attack25.log`
- `Linux_Crypto_Mining_Indicators_attack26.log`
- `Linux_Crypto_Mining_Indicators_attack27.log`
- `Linux_Crypto_Mining_Indicators_attack28.log`
- `Linux_Crypto_Mining_Indicators_attack29.log`
- `Linux_Crypto_Mining_Indicators_attack3.log`
- `Linux_Crypto_Mining_Indicators_attack30.log`
- `Linux_Crypto_Mining_Indicators_attack31.log`
- `Linux_Crypto_Mining_Indicators_attack32.log`
- `Linux_Crypto_Mining_Indicators_attack33.log`
- `Linux_Crypto_Mining_Indicators_attack34.log`
- `Linux_Crypto_Mining_Indicators_attack35.log`
- `Linux_Crypto_Mining_Indicators_attack36.log`
- `Linux_Crypto_Mining_Indicators_attack37.log`
- `Linux_Crypto_Mining_Indicators_attack38.log`
- `Linux_Crypto_Mining_Indicators_attack39.log`
- `Linux_Crypto_Mining_Indicators_attack4.log`
- `Linux_Crypto_Mining_Indicators_attack40.log`
- `Linux_Crypto_Mining_Indicators_attack41.log`
- `Linux_Crypto_Mining_Indicators_attack42.log`
- `Linux_Crypto_Mining_Indicators_attack43.log`
- `Linux_Crypto_Mining_Indicators_attack44.log`
- `Linux_Crypto_Mining_Indicators_attack45.log`
- `Linux_Crypto_Mining_Indicators_attack46.log`
- `Linux_Crypto_Mining_Indicators_attack47.log`
- `Linux_Crypto_Mining_Indicators_attack48.log`
- `Linux_Crypto_Mining_Indicators_attack49.log`
- `Linux_Crypto_Mining_Indicators_attack5.log`
- `Linux_Crypto_Mining_Indicators_attack50.log`
- `Linux_Crypto_Mining_Indicators_attack51.log`
- `Linux_Crypto_Mining_Indicators_attack52.log`
- `Linux_Crypto_Mining_Indicators_attack53.log`
- `Linux_Crypto_Mining_Indicators_attack54.log`
- `Linux_Crypto_Mining_Indicators_attack55.log`
- `Linux_Crypto_Mining_Indicators_attack56.log`
- `Linux_Crypto_Mining_Indicators_attack57.log`
- `Linux_Crypto_Mining_Indicators_attack58.log`
- `Linux_Crypto_Mining_Indicators_attack59.log`
- `Linux_Crypto_Mining_Indicators_attack6.log`
- `Linux_Crypto_Mining_Indicators_attack60.log`
- `Linux_Crypto_Mining_Indicators_attack61.log`
- `Linux_Crypto_Mining_Indicators_attack62.log`
- `Linux_Crypto_Mining_Indicators_attack63.log`
- `Linux_Crypto_Mining_Indicators_attack64.log`
- `Linux_Crypto_Mining_Indicators_attack65.log`
- `Linux_Crypto_Mining_Indicators_attack66.log`
- `Linux_Crypto_Mining_Indicators_attack67.log`
- `Linux_Crypto_Mining_Indicators_attack68.log`
- `Linux_Crypto_Mining_Indicators_attack69.log`
- `Linux_Crypto_Mining_Indicators_attack7.log`
- `Linux_Crypto_Mining_Indicators_attack70.log`
- `Linux_Crypto_Mining_Indicators_attack71.log`
- `Linux_Crypto_Mining_Indicators_attack72.log`
- `Linux_Crypto_Mining_Indicators_attack73.log`
- `Linux_Crypto_Mining_Indicators_attack74.log`
- `Linux_Crypto_Mining_Indicators_attack75.log`
- `Linux_Crypto_Mining_Indicators_attack76.log`
- `Linux_Crypto_Mining_Indicators_attack77.log`
- `Linux_Crypto_Mining_Indicators_attack78.log`
- `Linux_Crypto_Mining_Indicators_attack79.log`
- `Linux_Crypto_Mining_Indicators_attack8.log`
- `Linux_Crypto_Mining_Indicators_attack80.log`
- `Linux_Crypto_Mining_Indicators_attack81.log`
- `Linux_Crypto_Mining_Indicators_attack82.log`
- `Linux_Crypto_Mining_Indicators_attack83.log`
- `Linux_Crypto_Mining_Indicators_attack84.log`
- `Linux_Crypto_Mining_Indicators_attack85.log`
- `Linux_Crypto_Mining_Indicators_attack86.log`
- `Linux_Crypto_Mining_Indicators_attack87.log`
- `Linux_Crypto_Mining_Indicators_attack88.log`
- `Linux_Crypto_Mining_Indicators_attack89.log`
- `Linux_Crypto_Mining_Indicators_attack9.log`
- `Linux_Crypto_Mining_Indicators_attack90.log`
- `Linux_Crypto_Mining_Indicators_attack91.log`
- `Linux_Crypto_Mining_Indicators_attack92.log`
- `Linux_Crypto_Mining_Indicators_attack93.log`
- `Linux_Crypto_Mining_Indicators_attack94.log`
- `Linux_Crypto_Mining_Indicators_attack95.log`
- `Linux_Crypto_Mining_Indicators_attack96.log`
- `Linux_Crypto_Mining_Indicators_attack97.log`
- `Linux_Crypto_Mining_Indicators_attack98.log`
- `Linux_Crypto_Mining_Indicators_attack99.log`

---

### File and Directory Discovery - Linux

**Directory:** `file_and_directory_discovery`

**Sigma Rule ID:** `d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72`

**Event Counts:**
- Total: 180
- Match Events: 115
- Evasion Events: 65

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180

**Log Files:**
- `File_and_Directory_Discovery_attack1.log`
- `File_and_Directory_Discovery_attack10.log`
- `File_and_Directory_Discovery_attack100.log`
- `File_and_Directory_Discovery_attack101.log`
- `File_and_Directory_Discovery_attack102.log`
- `File_and_Directory_Discovery_attack103.log`
- `File_and_Directory_Discovery_attack104.log`
- `File_and_Directory_Discovery_attack105.log`
- `File_and_Directory_Discovery_attack106.log`
- `File_and_Directory_Discovery_attack107.log`
- `File_and_Directory_Discovery_attack108.log`
- `File_and_Directory_Discovery_attack109.log`
- `File_and_Directory_Discovery_attack11.log`
- `File_and_Directory_Discovery_attack110.log`
- `File_and_Directory_Discovery_attack111.log`
- `File_and_Directory_Discovery_attack112.log`
- `File_and_Directory_Discovery_attack113.log`
- `File_and_Directory_Discovery_attack114.log`
- `File_and_Directory_Discovery_attack115.log`
- `File_and_Directory_Discovery_attack116.log`
- `File_and_Directory_Discovery_attack117.log`
- `File_and_Directory_Discovery_attack118.log`
- `File_and_Directory_Discovery_attack119.log`
- `File_and_Directory_Discovery_attack12.log`
- `File_and_Directory_Discovery_attack120.log`
- `File_and_Directory_Discovery_attack121.log`
- `File_and_Directory_Discovery_attack122.log`
- `File_and_Directory_Discovery_attack123.log`
- `File_and_Directory_Discovery_attack124.log`
- `File_and_Directory_Discovery_attack125.log`
- `File_and_Directory_Discovery_attack126.log`
- `File_and_Directory_Discovery_attack127.log`
- `File_and_Directory_Discovery_attack128.log`
- `File_and_Directory_Discovery_attack129.log`
- `File_and_Directory_Discovery_attack13.log`
- `File_and_Directory_Discovery_attack130.log`
- `File_and_Directory_Discovery_attack131.log`
- `File_and_Directory_Discovery_attack132.log`
- `File_and_Directory_Discovery_attack133.log`
- `File_and_Directory_Discovery_attack134.log`
- `File_and_Directory_Discovery_attack135.log`
- `File_and_Directory_Discovery_attack136.log`
- `File_and_Directory_Discovery_attack137.log`
- `File_and_Directory_Discovery_attack138.log`
- `File_and_Directory_Discovery_attack139.log`
- `File_and_Directory_Discovery_attack14.log`
- `File_and_Directory_Discovery_attack140.log`
- `File_and_Directory_Discovery_attack141.log`
- `File_and_Directory_Discovery_attack142.log`
- `File_and_Directory_Discovery_attack143.log`
- `File_and_Directory_Discovery_attack144.log`
- `File_and_Directory_Discovery_attack145.log`
- `File_and_Directory_Discovery_attack146.log`
- `File_and_Directory_Discovery_attack147.log`
- `File_and_Directory_Discovery_attack148.log`
- `File_and_Directory_Discovery_attack149.log`
- `File_and_Directory_Discovery_attack15.log`
- `File_and_Directory_Discovery_attack150.log`
- `File_and_Directory_Discovery_attack151.log`
- `File_and_Directory_Discovery_attack152.log`
- `File_and_Directory_Discovery_attack153.log`
- `File_and_Directory_Discovery_attack154.log`
- `File_and_Directory_Discovery_attack155.log`
- `File_and_Directory_Discovery_attack156.log`
- `File_and_Directory_Discovery_attack157.log`
- `File_and_Directory_Discovery_attack158.log`
- `File_and_Directory_Discovery_attack159.log`
- `File_and_Directory_Discovery_attack16.log`
- `File_and_Directory_Discovery_attack160.log`
- `File_and_Directory_Discovery_attack161.log`
- `File_and_Directory_Discovery_attack162.log`
- `File_and_Directory_Discovery_attack163.log`
- `File_and_Directory_Discovery_attack164.log`
- `File_and_Directory_Discovery_attack165.log`
- `File_and_Directory_Discovery_attack166.log`
- `File_and_Directory_Discovery_attack167.log`
- `File_and_Directory_Discovery_attack168.log`
- `File_and_Directory_Discovery_attack169.log`
- `File_and_Directory_Discovery_attack17.log`
- `File_and_Directory_Discovery_attack170.log`
- `File_and_Directory_Discovery_attack171.log`
- `File_and_Directory_Discovery_attack172.log`
- `File_and_Directory_Discovery_attack173.log`
- `File_and_Directory_Discovery_attack174.log`
- `File_and_Directory_Discovery_attack175.log`
- `File_and_Directory_Discovery_attack176.log`
- `File_and_Directory_Discovery_attack177.log`
- `File_and_Directory_Discovery_attack178.log`
- `File_and_Directory_Discovery_attack179.log`
- `File_and_Directory_Discovery_attack18.log`
- `File_and_Directory_Discovery_attack180.log`
- `File_and_Directory_Discovery_attack19.log`
- `File_and_Directory_Discovery_attack2.log`
- `File_and_Directory_Discovery_attack20.log`
- `File_and_Directory_Discovery_attack21.log`
- `File_and_Directory_Discovery_attack22.log`
- `File_and_Directory_Discovery_attack23.log`
- `File_and_Directory_Discovery_attack24.log`
- `File_and_Directory_Discovery_attack25.log`
- `File_and_Directory_Discovery_attack26.log`
- `File_and_Directory_Discovery_attack27.log`
- `File_and_Directory_Discovery_attack28.log`
- `File_and_Directory_Discovery_attack29.log`
- `File_and_Directory_Discovery_attack3.log`
- `File_and_Directory_Discovery_attack30.log`
- `File_and_Directory_Discovery_attack31.log`
- `File_and_Directory_Discovery_attack32.log`
- `File_and_Directory_Discovery_attack33.log`
- `File_and_Directory_Discovery_attack34.log`
- `File_and_Directory_Discovery_attack35.log`
- `File_and_Directory_Discovery_attack36.log`
- `File_and_Directory_Discovery_attack37.log`
- `File_and_Directory_Discovery_attack38.log`
- `File_and_Directory_Discovery_attack39.log`
- `File_and_Directory_Discovery_attack4.log`
- `File_and_Directory_Discovery_attack40.log`
- `File_and_Directory_Discovery_attack41.log`
- `File_and_Directory_Discovery_attack42.log`
- `File_and_Directory_Discovery_attack43.log`
- `File_and_Directory_Discovery_attack44.log`
- `File_and_Directory_Discovery_attack45.log`
- `File_and_Directory_Discovery_attack46.log`
- `File_and_Directory_Discovery_attack47.log`
- `File_and_Directory_Discovery_attack48.log`
- `File_and_Directory_Discovery_attack49.log`
- `File_and_Directory_Discovery_attack5.log`
- `File_and_Directory_Discovery_attack50.log`
- `File_and_Directory_Discovery_attack51.log`
- `File_and_Directory_Discovery_attack52.log`
- `File_and_Directory_Discovery_attack53.log`
- `File_and_Directory_Discovery_attack54.log`
- `File_and_Directory_Discovery_attack55.log`
- `File_and_Directory_Discovery_attack56.log`
- `File_and_Directory_Discovery_attack57.log`
- `File_and_Directory_Discovery_attack58.log`
- `File_and_Directory_Discovery_attack59.log`
- `File_and_Directory_Discovery_attack6.log`
- `File_and_Directory_Discovery_attack60.log`
- `File_and_Directory_Discovery_attack61.log`
- `File_and_Directory_Discovery_attack62.log`
- `File_and_Directory_Discovery_attack63.log`
- `File_and_Directory_Discovery_attack64.log`
- `File_and_Directory_Discovery_attack65.log`
- `File_and_Directory_Discovery_attack66.log`
- `File_and_Directory_Discovery_attack67.log`
- `File_and_Directory_Discovery_attack68.log`
- `File_and_Directory_Discovery_attack69.log`
- `File_and_Directory_Discovery_attack7.log`
- `File_and_Directory_Discovery_attack70.log`
- `File_and_Directory_Discovery_attack71.log`
- `File_and_Directory_Discovery_attack72.log`
- `File_and_Directory_Discovery_attack73.log`
- `File_and_Directory_Discovery_attack74.log`
- `File_and_Directory_Discovery_attack75.log`
- `File_and_Directory_Discovery_attack76.log`
- `File_and_Directory_Discovery_attack77.log`
- `File_and_Directory_Discovery_attack78.log`
- `File_and_Directory_Discovery_attack79.log`
- `File_and_Directory_Discovery_attack8.log`
- `File_and_Directory_Discovery_attack80.log`
- `File_and_Directory_Discovery_attack81.log`
- `File_and_Directory_Discovery_attack82.log`
- `File_and_Directory_Discovery_attack83.log`
- `File_and_Directory_Discovery_attack84.log`
- `File_and_Directory_Discovery_attack85.log`
- `File_and_Directory_Discovery_attack86.log`
- `File_and_Directory_Discovery_attack87.log`
- `File_and_Directory_Discovery_attack88.log`
- `File_and_Directory_Discovery_attack89.log`
- `File_and_Directory_Discovery_attack9.log`
- `File_and_Directory_Discovery_attack90.log`
- `File_and_Directory_Discovery_attack91.log`
- `File_and_Directory_Discovery_attack92.log`
- `File_and_Directory_Discovery_attack93.log`
- `File_and_Directory_Discovery_attack94.log`
- `File_and_Directory_Discovery_attack95.log`
- `File_and_Directory_Discovery_attack96.log`
- `File_and_Directory_Discovery_attack97.log`
- `File_and_Directory_Discovery_attack98.log`
- `File_and_Directory_Discovery_attack99.log`

---

### Shell Invocation via Apt - Linux

**Directory:** `apt_shell_execution`

**Sigma Rule ID:** `bb382fd5-b454-47ea-a264-1828e4c766d6`

**Event Counts:**
- Total: 165
- Match Events: 165
- Evasion Events: 0

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165

**Log Files:**
- `Shell_Invocation_via_Apt_attack1.log`
- `Shell_Invocation_via_Apt_attack10.log`
- `Shell_Invocation_via_Apt_attack100.log`
- `Shell_Invocation_via_Apt_attack101.log`
- `Shell_Invocation_via_Apt_attack102.log`
- `Shell_Invocation_via_Apt_attack103.log`
- `Shell_Invocation_via_Apt_attack104.log`
- `Shell_Invocation_via_Apt_attack105.log`
- `Shell_Invocation_via_Apt_attack106.log`
- `Shell_Invocation_via_Apt_attack107.log`
- `Shell_Invocation_via_Apt_attack108.log`
- `Shell_Invocation_via_Apt_attack109.log`
- `Shell_Invocation_via_Apt_attack11.log`
- `Shell_Invocation_via_Apt_attack110.log`
- `Shell_Invocation_via_Apt_attack111.log`
- `Shell_Invocation_via_Apt_attack112.log`
- `Shell_Invocation_via_Apt_attack113.log`
- `Shell_Invocation_via_Apt_attack114.log`
- `Shell_Invocation_via_Apt_attack115.log`
- `Shell_Invocation_via_Apt_attack116.log`
- `Shell_Invocation_via_Apt_attack117.log`
- `Shell_Invocation_via_Apt_attack118.log`
- `Shell_Invocation_via_Apt_attack119.log`
- `Shell_Invocation_via_Apt_attack12.log`
- `Shell_Invocation_via_Apt_attack120.log`
- `Shell_Invocation_via_Apt_attack121.log`
- `Shell_Invocation_via_Apt_attack122.log`
- `Shell_Invocation_via_Apt_attack123.log`
- `Shell_Invocation_via_Apt_attack124.log`
- `Shell_Invocation_via_Apt_attack125.log`
- `Shell_Invocation_via_Apt_attack126.log`
- `Shell_Invocation_via_Apt_attack127.log`
- `Shell_Invocation_via_Apt_attack128.log`
- `Shell_Invocation_via_Apt_attack129.log`
- `Shell_Invocation_via_Apt_attack13.log`
- `Shell_Invocation_via_Apt_attack130.log`
- `Shell_Invocation_via_Apt_attack131.log`
- `Shell_Invocation_via_Apt_attack132.log`
- `Shell_Invocation_via_Apt_attack133.log`
- `Shell_Invocation_via_Apt_attack134.log`
- `Shell_Invocation_via_Apt_attack135.log`
- `Shell_Invocation_via_Apt_attack136.log`
- `Shell_Invocation_via_Apt_attack137.log`
- `Shell_Invocation_via_Apt_attack138.log`
- `Shell_Invocation_via_Apt_attack139.log`
- `Shell_Invocation_via_Apt_attack14.log`
- `Shell_Invocation_via_Apt_attack140.log`
- `Shell_Invocation_via_Apt_attack141.log`
- `Shell_Invocation_via_Apt_attack142.log`
- `Shell_Invocation_via_Apt_attack143.log`
- `Shell_Invocation_via_Apt_attack144.log`
- `Shell_Invocation_via_Apt_attack145.log`
- `Shell_Invocation_via_Apt_attack146.log`
- `Shell_Invocation_via_Apt_attack147.log`
- `Shell_Invocation_via_Apt_attack148.log`
- `Shell_Invocation_via_Apt_attack149.log`
- `Shell_Invocation_via_Apt_attack15.log`
- `Shell_Invocation_via_Apt_attack150.log`
- `Shell_Invocation_via_Apt_attack151.log`
- `Shell_Invocation_via_Apt_attack152.log`
- `Shell_Invocation_via_Apt_attack153.log`
- `Shell_Invocation_via_Apt_attack154.log`
- `Shell_Invocation_via_Apt_attack155.log`
- `Shell_Invocation_via_Apt_attack156.log`
- `Shell_Invocation_via_Apt_attack157.log`
- `Shell_Invocation_via_Apt_attack158.log`
- `Shell_Invocation_via_Apt_attack159.log`
- `Shell_Invocation_via_Apt_attack16.log`
- `Shell_Invocation_via_Apt_attack160.log`
- `Shell_Invocation_via_Apt_attack161.log`
- `Shell_Invocation_via_Apt_attack162.log`
- `Shell_Invocation_via_Apt_attack163.log`
- `Shell_Invocation_via_Apt_attack164.log`
- `Shell_Invocation_via_Apt_attack165.log`
- `Shell_Invocation_via_Apt_attack17.log`
- `Shell_Invocation_via_Apt_attack18.log`
- `Shell_Invocation_via_Apt_attack19.log`
- `Shell_Invocation_via_Apt_attack2.log`
- `Shell_Invocation_via_Apt_attack20.log`
- `Shell_Invocation_via_Apt_attack21.log`
- `Shell_Invocation_via_Apt_attack22.log`
- `Shell_Invocation_via_Apt_attack23.log`
- `Shell_Invocation_via_Apt_attack24.log`
- `Shell_Invocation_via_Apt_attack25.log`
- `Shell_Invocation_via_Apt_attack26.log`
- `Shell_Invocation_via_Apt_attack27.log`
- `Shell_Invocation_via_Apt_attack28.log`
- `Shell_Invocation_via_Apt_attack29.log`
- `Shell_Invocation_via_Apt_attack3.log`
- `Shell_Invocation_via_Apt_attack30.log`
- `Shell_Invocation_via_Apt_attack31.log`
- `Shell_Invocation_via_Apt_attack32.log`
- `Shell_Invocation_via_Apt_attack33.log`
- `Shell_Invocation_via_Apt_attack34.log`
- `Shell_Invocation_via_Apt_attack35.log`
- `Shell_Invocation_via_Apt_attack36.log`
- `Shell_Invocation_via_Apt_attack37.log`
- `Shell_Invocation_via_Apt_attack38.log`
- `Shell_Invocation_via_Apt_attack39.log`
- `Shell_Invocation_via_Apt_attack4.log`
- `Shell_Invocation_via_Apt_attack40.log`
- `Shell_Invocation_via_Apt_attack41.log`
- `Shell_Invocation_via_Apt_attack42.log`
- `Shell_Invocation_via_Apt_attack43.log`
- `Shell_Invocation_via_Apt_attack44.log`
- `Shell_Invocation_via_Apt_attack45.log`
- `Shell_Invocation_via_Apt_attack46.log`
- `Shell_Invocation_via_Apt_attack47.log`
- `Shell_Invocation_via_Apt_attack48.log`
- `Shell_Invocation_via_Apt_attack49.log`
- `Shell_Invocation_via_Apt_attack5.log`
- `Shell_Invocation_via_Apt_attack50.log`
- `Shell_Invocation_via_Apt_attack51.log`
- `Shell_Invocation_via_Apt_attack52.log`
- `Shell_Invocation_via_Apt_attack53.log`
- `Shell_Invocation_via_Apt_attack54.log`
- `Shell_Invocation_via_Apt_attack55.log`
- `Shell_Invocation_via_Apt_attack56.log`
- `Shell_Invocation_via_Apt_attack57.log`
- `Shell_Invocation_via_Apt_attack58.log`
- `Shell_Invocation_via_Apt_attack59.log`
- `Shell_Invocation_via_Apt_attack6.log`
- `Shell_Invocation_via_Apt_attack60.log`
- `Shell_Invocation_via_Apt_attack61.log`
- `Shell_Invocation_via_Apt_attack62.log`
- `Shell_Invocation_via_Apt_attack63.log`
- `Shell_Invocation_via_Apt_attack64.log`
- `Shell_Invocation_via_Apt_attack65.log`
- `Shell_Invocation_via_Apt_attack66.log`
- `Shell_Invocation_via_Apt_attack67.log`
- `Shell_Invocation_via_Apt_attack68.log`
- `Shell_Invocation_via_Apt_attack69.log`
- `Shell_Invocation_via_Apt_attack7.log`
- `Shell_Invocation_via_Apt_attack70.log`
- `Shell_Invocation_via_Apt_attack71.log`
- `Shell_Invocation_via_Apt_attack72.log`
- `Shell_Invocation_via_Apt_attack73.log`
- `Shell_Invocation_via_Apt_attack74.log`
- `Shell_Invocation_via_Apt_attack75.log`
- `Shell_Invocation_via_Apt_attack76.log`
- `Shell_Invocation_via_Apt_attack77.log`
- `Shell_Invocation_via_Apt_attack78.log`
- `Shell_Invocation_via_Apt_attack79.log`
- `Shell_Invocation_via_Apt_attack8.log`
- `Shell_Invocation_via_Apt_attack80.log`
- `Shell_Invocation_via_Apt_attack81.log`
- `Shell_Invocation_via_Apt_attack82.log`
- `Shell_Invocation_via_Apt_attack83.log`
- `Shell_Invocation_via_Apt_attack84.log`
- `Shell_Invocation_via_Apt_attack85.log`
- `Shell_Invocation_via_Apt_attack86.log`
- `Shell_Invocation_via_Apt_attack87.log`
- `Shell_Invocation_via_Apt_attack88.log`
- `Shell_Invocation_via_Apt_attack89.log`
- `Shell_Invocation_via_Apt_attack9.log`
- `Shell_Invocation_via_Apt_attack90.log`
- `Shell_Invocation_via_Apt_attack91.log`
- `Shell_Invocation_via_Apt_attack92.log`
- `Shell_Invocation_via_Apt_attack93.log`
- `Shell_Invocation_via_Apt_attack94.log`
- `Shell_Invocation_via_Apt_attack95.log`
- `Shell_Invocation_via_Apt_attack96.log`
- `Shell_Invocation_via_Apt_attack97.log`
- `Shell_Invocation_via_Apt_attack98.log`
- `Shell_Invocation_via_Apt_attack99.log`

---

### Decode Base64 Encoded Text

**Directory:** `base64_decode`

**Sigma Rule ID:** `e2072cab-8c9a-459b-b63c-40ae79e27031`

**Event Counts:**
- Total: 158
- Match Events: 66
- Evasion Events: 92

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158

**Log Files:**
- `Decode_Base64_Encoded_Text_attack1.log`
- `Decode_Base64_Encoded_Text_attack10.log`
- `Decode_Base64_Encoded_Text_attack100.log`
- `Decode_Base64_Encoded_Text_attack101.log`
- `Decode_Base64_Encoded_Text_attack102.log`
- `Decode_Base64_Encoded_Text_attack103.log`
- `Decode_Base64_Encoded_Text_attack104.log`
- `Decode_Base64_Encoded_Text_attack105.log`
- `Decode_Base64_Encoded_Text_attack106.log`
- `Decode_Base64_Encoded_Text_attack107.log`
- `Decode_Base64_Encoded_Text_attack108.log`
- `Decode_Base64_Encoded_Text_attack109.log`
- `Decode_Base64_Encoded_Text_attack11.log`
- `Decode_Base64_Encoded_Text_attack110.log`
- `Decode_Base64_Encoded_Text_attack111.log`
- `Decode_Base64_Encoded_Text_attack112.log`
- `Decode_Base64_Encoded_Text_attack113.log`
- `Decode_Base64_Encoded_Text_attack114.log`
- `Decode_Base64_Encoded_Text_attack115.log`
- `Decode_Base64_Encoded_Text_attack116.log`
- `Decode_Base64_Encoded_Text_attack117.log`
- `Decode_Base64_Encoded_Text_attack118.log`
- `Decode_Base64_Encoded_Text_attack119.log`
- `Decode_Base64_Encoded_Text_attack12.log`
- `Decode_Base64_Encoded_Text_attack120.log`
- `Decode_Base64_Encoded_Text_attack121.log`
- `Decode_Base64_Encoded_Text_attack122.log`
- `Decode_Base64_Encoded_Text_attack123.log`
- `Decode_Base64_Encoded_Text_attack124.log`
- `Decode_Base64_Encoded_Text_attack125.log`
- `Decode_Base64_Encoded_Text_attack126.log`
- `Decode_Base64_Encoded_Text_attack127.log`
- `Decode_Base64_Encoded_Text_attack128.log`
- `Decode_Base64_Encoded_Text_attack129.log`
- `Decode_Base64_Encoded_Text_attack13.log`
- `Decode_Base64_Encoded_Text_attack130.log`
- `Decode_Base64_Encoded_Text_attack131.log`
- `Decode_Base64_Encoded_Text_attack132.log`
- `Decode_Base64_Encoded_Text_attack133.log`
- `Decode_Base64_Encoded_Text_attack134.log`
- `Decode_Base64_Encoded_Text_attack135.log`
- `Decode_Base64_Encoded_Text_attack136.log`
- `Decode_Base64_Encoded_Text_attack137.log`
- `Decode_Base64_Encoded_Text_attack138.log`
- `Decode_Base64_Encoded_Text_attack139.log`
- `Decode_Base64_Encoded_Text_attack14.log`
- `Decode_Base64_Encoded_Text_attack140.log`
- `Decode_Base64_Encoded_Text_attack141.log`
- `Decode_Base64_Encoded_Text_attack142.log`
- `Decode_Base64_Encoded_Text_attack143.log`
- `Decode_Base64_Encoded_Text_attack144.log`
- `Decode_Base64_Encoded_Text_attack145.log`
- `Decode_Base64_Encoded_Text_attack146.log`
- `Decode_Base64_Encoded_Text_attack147.log`
- `Decode_Base64_Encoded_Text_attack148.log`
- `Decode_Base64_Encoded_Text_attack149.log`
- `Decode_Base64_Encoded_Text_attack15.log`
- `Decode_Base64_Encoded_Text_attack150.log`
- `Decode_Base64_Encoded_Text_attack151.log`
- `Decode_Base64_Encoded_Text_attack152.log`
- `Decode_Base64_Encoded_Text_attack153.log`
- `Decode_Base64_Encoded_Text_attack154.log`
- `Decode_Base64_Encoded_Text_attack155.log`
- `Decode_Base64_Encoded_Text_attack156.log`
- `Decode_Base64_Encoded_Text_attack157.log`
- `Decode_Base64_Encoded_Text_attack158.log`
- `Decode_Base64_Encoded_Text_attack16.log`
- `Decode_Base64_Encoded_Text_attack17.log`
- `Decode_Base64_Encoded_Text_attack18.log`
- `Decode_Base64_Encoded_Text_attack19.log`
- `Decode_Base64_Encoded_Text_attack2.log`
- `Decode_Base64_Encoded_Text_attack20.log`
- `Decode_Base64_Encoded_Text_attack21.log`
- `Decode_Base64_Encoded_Text_attack22.log`
- `Decode_Base64_Encoded_Text_attack23.log`
- `Decode_Base64_Encoded_Text_attack24.log`
- `Decode_Base64_Encoded_Text_attack25.log`
- `Decode_Base64_Encoded_Text_attack26.log`
- `Decode_Base64_Encoded_Text_attack27.log`
- `Decode_Base64_Encoded_Text_attack28.log`
- `Decode_Base64_Encoded_Text_attack29.log`
- `Decode_Base64_Encoded_Text_attack3.log`
- `Decode_Base64_Encoded_Text_attack30.log`
- `Decode_Base64_Encoded_Text_attack31.log`
- `Decode_Base64_Encoded_Text_attack32.log`
- `Decode_Base64_Encoded_Text_attack33.log`
- `Decode_Base64_Encoded_Text_attack34.log`
- `Decode_Base64_Encoded_Text_attack35.log`
- `Decode_Base64_Encoded_Text_attack36.log`
- `Decode_Base64_Encoded_Text_attack37.log`
- `Decode_Base64_Encoded_Text_attack38.log`
- `Decode_Base64_Encoded_Text_attack39.log`
- `Decode_Base64_Encoded_Text_attack4.log`
- `Decode_Base64_Encoded_Text_attack40.log`
- `Decode_Base64_Encoded_Text_attack41.log`
- `Decode_Base64_Encoded_Text_attack42.log`
- `Decode_Base64_Encoded_Text_attack43.log`
- `Decode_Base64_Encoded_Text_attack44.log`
- `Decode_Base64_Encoded_Text_attack45.log`
- `Decode_Base64_Encoded_Text_attack46.log`
- `Decode_Base64_Encoded_Text_attack47.log`
- `Decode_Base64_Encoded_Text_attack48.log`
- `Decode_Base64_Encoded_Text_attack49.log`
- `Decode_Base64_Encoded_Text_attack5.log`
- `Decode_Base64_Encoded_Text_attack50.log`
- `Decode_Base64_Encoded_Text_attack51.log`
- `Decode_Base64_Encoded_Text_attack52.log`
- `Decode_Base64_Encoded_Text_attack53.log`
- `Decode_Base64_Encoded_Text_attack54.log`
- `Decode_Base64_Encoded_Text_attack55.log`
- `Decode_Base64_Encoded_Text_attack56.log`
- `Decode_Base64_Encoded_Text_attack57.log`
- `Decode_Base64_Encoded_Text_attack58.log`
- `Decode_Base64_Encoded_Text_attack59.log`
- `Decode_Base64_Encoded_Text_attack6.log`
- `Decode_Base64_Encoded_Text_attack60.log`
- `Decode_Base64_Encoded_Text_attack61.log`
- `Decode_Base64_Encoded_Text_attack62.log`
- `Decode_Base64_Encoded_Text_attack63.log`
- `Decode_Base64_Encoded_Text_attack64.log`
- `Decode_Base64_Encoded_Text_attack65.log`
- `Decode_Base64_Encoded_Text_attack66.log`
- `Decode_Base64_Encoded_Text_attack67.log`
- `Decode_Base64_Encoded_Text_attack68.log`
- `Decode_Base64_Encoded_Text_attack69.log`
- `Decode_Base64_Encoded_Text_attack7.log`
- `Decode_Base64_Encoded_Text_attack70.log`
- `Decode_Base64_Encoded_Text_attack71.log`
- `Decode_Base64_Encoded_Text_attack72.log`
- `Decode_Base64_Encoded_Text_attack73.log`
- `Decode_Base64_Encoded_Text_attack74.log`
- `Decode_Base64_Encoded_Text_attack75.log`
- `Decode_Base64_Encoded_Text_attack76.log`
- `Decode_Base64_Encoded_Text_attack77.log`
- `Decode_Base64_Encoded_Text_attack78.log`
- `Decode_Base64_Encoded_Text_attack79.log`
- `Decode_Base64_Encoded_Text_attack8.log`
- `Decode_Base64_Encoded_Text_attack80.log`
- `Decode_Base64_Encoded_Text_attack81.log`
- `Decode_Base64_Encoded_Text_attack82.log`
- `Decode_Base64_Encoded_Text_attack83.log`
- `Decode_Base64_Encoded_Text_attack84.log`
- `Decode_Base64_Encoded_Text_attack85.log`
- `Decode_Base64_Encoded_Text_attack86.log`
- `Decode_Base64_Encoded_Text_attack87.log`
- `Decode_Base64_Encoded_Text_attack88.log`
- `Decode_Base64_Encoded_Text_attack89.log`
- `Decode_Base64_Encoded_Text_attack9.log`
- `Decode_Base64_Encoded_Text_attack90.log`
- `Decode_Base64_Encoded_Text_attack91.log`
- `Decode_Base64_Encoded_Text_attack92.log`
- `Decode_Base64_Encoded_Text_attack93.log`
- `Decode_Base64_Encoded_Text_attack94.log`
- `Decode_Base64_Encoded_Text_attack95.log`
- `Decode_Base64_Encoded_Text_attack96.log`
- `Decode_Base64_Encoded_Text_attack97.log`
- `Decode_Base64_Encoded_Text_attack98.log`
- `Decode_Base64_Encoded_Text_attack99.log`

---

### Capsh Shell Invocation - Linux

**Directory:** `capsh_shell_invocation`

**Sigma Rule ID:** `db1ac3be-f606-4e3a-89e0-9607cbe6b98a`

**Event Counts:**
- Total: 157
- Match Events: 29
- Evasion Events: 128

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 4, 5, 7, 8, 19, 20, 24, 25, 26, 27, 30, 31, 32, 33, 35, 39, 40, 41, 43, 48, 51, 52, 53, 54, 57, 61, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 123, 124, 129, 175, 182, 183, 186, 188, 196, 198, 199, 204, 205, 207, 211, 212, 213, 214, 215, 216, 217, 218, 220, 222, 223, 224, 225, 227, 228, 229, 230, 231, 232, 233, 234, 235, 238, 239, 240, 241, 254, 255, 256, 257, 258, 259, 260, 271, 272, 276, 277, 278, 279, 280, 281, 284, 286, 287, 288, 289, 290, 295, 299, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358

**Log Files:**
- `Capsh_Shell_Invocation_attack123.log`
- `Capsh_Shell_Invocation_attack124.log`
- `Capsh_Shell_Invocation_attack129.log`
- `Capsh_Shell_Invocation_attack175.log`
- `Capsh_Shell_Invocation_attack182.log`
- `Capsh_Shell_Invocation_attack183.log`
- `Capsh_Shell_Invocation_attack186.log`
- `Capsh_Shell_Invocation_attack188.log`
- `Capsh_Shell_Invocation_attack19.log`
- `Capsh_Shell_Invocation_attack196.log`
- `Capsh_Shell_Invocation_attack198.log`
- `Capsh_Shell_Invocation_attack199.log`
- `Capsh_Shell_Invocation_attack20.log`
- `Capsh_Shell_Invocation_attack204.log`
- `Capsh_Shell_Invocation_attack205.log`
- `Capsh_Shell_Invocation_attack207.log`
- `Capsh_Shell_Invocation_attack211.log`
- `Capsh_Shell_Invocation_attack212.log`
- `Capsh_Shell_Invocation_attack213.log`
- `Capsh_Shell_Invocation_attack214.log`
- `Capsh_Shell_Invocation_attack215.log`
- `Capsh_Shell_Invocation_attack216.log`
- `Capsh_Shell_Invocation_attack217.log`
- `Capsh_Shell_Invocation_attack218.log`
- `Capsh_Shell_Invocation_attack220.log`
- `Capsh_Shell_Invocation_attack222.log`
- `Capsh_Shell_Invocation_attack223.log`
- `Capsh_Shell_Invocation_attack224.log`
- `Capsh_Shell_Invocation_attack225.log`
- `Capsh_Shell_Invocation_attack227.log`
- `Capsh_Shell_Invocation_attack228.log`
- `Capsh_Shell_Invocation_attack229.log`
- `Capsh_Shell_Invocation_attack230.log`
- `Capsh_Shell_Invocation_attack231.log`
- `Capsh_Shell_Invocation_attack232.log`
- `Capsh_Shell_Invocation_attack233.log`
- `Capsh_Shell_Invocation_attack234.log`
- `Capsh_Shell_Invocation_attack235.log`
- `Capsh_Shell_Invocation_attack238.log`
- `Capsh_Shell_Invocation_attack239.log`
- `Capsh_Shell_Invocation_attack24.log`
- `Capsh_Shell_Invocation_attack240.log`
- `Capsh_Shell_Invocation_attack241.log`
- `Capsh_Shell_Invocation_attack25.log`
- `Capsh_Shell_Invocation_attack254.log`
- `Capsh_Shell_Invocation_attack255.log`
- `Capsh_Shell_Invocation_attack256.log`
- `Capsh_Shell_Invocation_attack257.log`
- `Capsh_Shell_Invocation_attack258.log`
- `Capsh_Shell_Invocation_attack259.log`
- `Capsh_Shell_Invocation_attack26.log`
- `Capsh_Shell_Invocation_attack260.log`
- `Capsh_Shell_Invocation_attack27.log`
- `Capsh_Shell_Invocation_attack271.log`
- `Capsh_Shell_Invocation_attack272.log`
- `Capsh_Shell_Invocation_attack276.log`
- `Capsh_Shell_Invocation_attack277.log`
- `Capsh_Shell_Invocation_attack278.log`
- `Capsh_Shell_Invocation_attack279.log`
- `Capsh_Shell_Invocation_attack280.log`
- `Capsh_Shell_Invocation_attack281.log`
- `Capsh_Shell_Invocation_attack284.log`
- `Capsh_Shell_Invocation_attack286.log`
- `Capsh_Shell_Invocation_attack287.log`
- `Capsh_Shell_Invocation_attack288.log`
- `Capsh_Shell_Invocation_attack289.log`
- `Capsh_Shell_Invocation_attack290.log`
- `Capsh_Shell_Invocation_attack295.log`
- `Capsh_Shell_Invocation_attack299.log`
- `Capsh_Shell_Invocation_attack30.log`
- `Capsh_Shell_Invocation_attack301.log`
- `Capsh_Shell_Invocation_attack302.log`
- `Capsh_Shell_Invocation_attack303.log`
- `Capsh_Shell_Invocation_attack304.log`
- `Capsh_Shell_Invocation_attack305.log`
- `Capsh_Shell_Invocation_attack306.log`
- `Capsh_Shell_Invocation_attack307.log`
- `Capsh_Shell_Invocation_attack308.log`
- `Capsh_Shell_Invocation_attack309.log`
- `Capsh_Shell_Invocation_attack31.log`
- `Capsh_Shell_Invocation_attack310.log`
- `Capsh_Shell_Invocation_attack311.log`
- `Capsh_Shell_Invocation_attack312.log`
- `Capsh_Shell_Invocation_attack313.log`
- `Capsh_Shell_Invocation_attack314.log`
- `Capsh_Shell_Invocation_attack315.log`
- `Capsh_Shell_Invocation_attack316.log`
- `Capsh_Shell_Invocation_attack317.log`
- `Capsh_Shell_Invocation_attack318.log`
- `Capsh_Shell_Invocation_attack319.log`
- `Capsh_Shell_Invocation_attack32.log`
- `Capsh_Shell_Invocation_attack320.log`
- `Capsh_Shell_Invocation_attack321.log`
- `Capsh_Shell_Invocation_attack322.log`
- `Capsh_Shell_Invocation_attack323.log`
- `Capsh_Shell_Invocation_attack324.log`
- `Capsh_Shell_Invocation_attack325.log`
- `Capsh_Shell_Invocation_attack326.log`
- `Capsh_Shell_Invocation_attack327.log`
- `Capsh_Shell_Invocation_attack328.log`
- `Capsh_Shell_Invocation_attack329.log`
- `Capsh_Shell_Invocation_attack33.log`
- `Capsh_Shell_Invocation_attack330.log`
- `Capsh_Shell_Invocation_attack331.log`
- `Capsh_Shell_Invocation_attack332.log`
- `Capsh_Shell_Invocation_attack333.log`
- `Capsh_Shell_Invocation_attack334.log`
- `Capsh_Shell_Invocation_attack335.log`
- `Capsh_Shell_Invocation_attack336.log`
- `Capsh_Shell_Invocation_attack337.log`
- `Capsh_Shell_Invocation_attack338.log`
- `Capsh_Shell_Invocation_attack339.log`
- `Capsh_Shell_Invocation_attack340.log`
- `Capsh_Shell_Invocation_attack341.log`
- `Capsh_Shell_Invocation_attack342.log`
- `Capsh_Shell_Invocation_attack343.log`
- `Capsh_Shell_Invocation_attack344.log`
- `Capsh_Shell_Invocation_attack345.log`
- `Capsh_Shell_Invocation_attack346.log`
- `Capsh_Shell_Invocation_attack347.log`
- `Capsh_Shell_Invocation_attack348.log`
- `Capsh_Shell_Invocation_attack349.log`
- `Capsh_Shell_Invocation_attack35.log`
- `Capsh_Shell_Invocation_attack350.log`
- `Capsh_Shell_Invocation_attack351.log`
- `Capsh_Shell_Invocation_attack352.log`
- `Capsh_Shell_Invocation_attack353.log`
- `Capsh_Shell_Invocation_attack354.log`
- `Capsh_Shell_Invocation_attack355.log`
- `Capsh_Shell_Invocation_attack356.log`
- `Capsh_Shell_Invocation_attack357.log`
- `Capsh_Shell_Invocation_attack358.log`
- `Capsh_Shell_Invocation_attack39.log`
- `Capsh_Shell_Invocation_attack4.log`
- `Capsh_Shell_Invocation_attack40.log`
- `Capsh_Shell_Invocation_attack41.log`
- `Capsh_Shell_Invocation_attack43.log`
- `Capsh_Shell_Invocation_attack48.log`
- `Capsh_Shell_Invocation_attack5.log`
- `Capsh_Shell_Invocation_attack51.log`
- `Capsh_Shell_Invocation_attack52.log`
- `Capsh_Shell_Invocation_attack53.log`
- `Capsh_Shell_Invocation_attack54.log`
- `Capsh_Shell_Invocation_attack57.log`
- `Capsh_Shell_Invocation_attack61.log`
- `Capsh_Shell_Invocation_attack7.log`
- `Capsh_Shell_Invocation_attack8.log`
- `Capsh_Shell_Invocation_attack81.log`
- `Capsh_Shell_Invocation_attack82.log`
- `Capsh_Shell_Invocation_attack83.log`
- `Capsh_Shell_Invocation_attack84.log`
- `Capsh_Shell_Invocation_attack85.log`
- `Capsh_Shell_Invocation_attack86.log`
- `Capsh_Shell_Invocation_attack87.log`
- `Capsh_Shell_Invocation_attack88.log`
- `Capsh_Shell_Invocation_attack89.log`
- `Capsh_Shell_Invocation_attack90.log`

---

### Linux Shell Pipe to Shell

**Directory:** `susp_pipe_shell`

**Sigma Rule ID:** `880973f3-9708-491c-a77b-2a35a1921158`

**Event Counts:**
- Total: 139
- Match Events: 65
- Evasion Events: 74

**Properties:**
- Evasion Possible: True
- Broken Rule: False
- Edited Fields: `CommandLine`, `Image`, `ParentImage`
- Queried Event Types: Microsoft-Windows-Sysmon_1

**Attack IDs:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140

**Log Files:**
- `Linux_Shell_Pipe_to_Shell_attack1.log`
- `Linux_Shell_Pipe_to_Shell_attack10.log`
- `Linux_Shell_Pipe_to_Shell_attack100.log`
- `Linux_Shell_Pipe_to_Shell_attack101.log`
- `Linux_Shell_Pipe_to_Shell_attack102.log`
- `Linux_Shell_Pipe_to_Shell_attack103.log`
- `Linux_Shell_Pipe_to_Shell_attack104.log`
- `Linux_Shell_Pipe_to_Shell_attack105.log`
- `Linux_Shell_Pipe_to_Shell_attack106.log`
- `Linux_Shell_Pipe_to_Shell_attack107.log`
- `Linux_Shell_Pipe_to_Shell_attack108.log`
- `Linux_Shell_Pipe_to_Shell_attack109.log`
- `Linux_Shell_Pipe_to_Shell_attack11.log`
- `Linux_Shell_Pipe_to_Shell_attack110.log`
- `Linux_Shell_Pipe_to_Shell_attack111.log`
- `Linux_Shell_Pipe_to_Shell_attack112.log`
- `Linux_Shell_Pipe_to_Shell_attack113.log`
- `Linux_Shell_Pipe_to_Shell_attack114.log`
- `Linux_Shell_Pipe_to_Shell_attack115.log`
- `Linux_Shell_Pipe_to_Shell_attack116.log`
- `Linux_Shell_Pipe_to_Shell_attack117.log`
- `Linux_Shell_Pipe_to_Shell_attack118.log`
- `Linux_Shell_Pipe_to_Shell_attack119.log`
- `Linux_Shell_Pipe_to_Shell_attack12.log`
- `Linux_Shell_Pipe_to_Shell_attack120.log`
- `Linux_Shell_Pipe_to_Shell_attack121.log`
- `Linux_Shell_Pipe_to_Shell_attack122.log`
- `Linux_Shell_Pipe_to_Shell_attack123.log`
- `Linux_Shell_Pipe_to_Shell_attack124.log`
- `Linux_Shell_Pipe_to_Shell_attack125.log`
- `Linux_Shell_Pipe_to_Shell_attack126.log`
- `Linux_Shell_Pipe_to_Shell_attack127.log`
- `Linux_Shell_Pipe_to_Shell_attack128.log`
- `Linux_Shell_Pipe_to_Shell_attack129.log`
- `Linux_Shell_Pipe_to_Shell_attack13.log`
- `Linux_Shell_Pipe_to_Shell_attack130.log`
- `Linux_Shell_Pipe_to_Shell_attack131.log`
- `Linux_Shell_Pipe_to_Shell_attack132.log`
- `Linux_Shell_Pipe_to_Shell_attack133.log`
- `Linux_Shell_Pipe_to_Shell_attack134.log`
- `Linux_Shell_Pipe_to_Shell_attack135.log`
- `Linux_Shell_Pipe_to_Shell_attack136.log`
- `Linux_Shell_Pipe_to_Shell_attack137.log`
- `Linux_Shell_Pipe_to_Shell_attack138.log`
- `Linux_Shell_Pipe_to_Shell_attack139.log`
- `Linux_Shell_Pipe_to_Shell_attack140.log`
- `Linux_Shell_Pipe_to_Shell_attack15.log`
- `Linux_Shell_Pipe_to_Shell_attack16.log`
- `Linux_Shell_Pipe_to_Shell_attack17.log`
- `Linux_Shell_Pipe_to_Shell_attack18.log`
- `Linux_Shell_Pipe_to_Shell_attack19.log`
- `Linux_Shell_Pipe_to_Shell_attack2.log`
- `Linux_Shell_Pipe_to_Shell_attack20.log`
- `Linux_Shell_Pipe_to_Shell_attack21.log`
- `Linux_Shell_Pipe_to_Shell_attack22.log`
- `Linux_Shell_Pipe_to_Shell_attack23.log`
- `Linux_Shell_Pipe_to_Shell_attack24.log`
- `Linux_Shell_Pipe_to_Shell_attack25.log`
- `Linux_Shell_Pipe_to_Shell_attack26.log`
- `Linux_Shell_Pipe_to_Shell_attack27.log`
- `Linux_Shell_Pipe_to_Shell_attack28.log`
- `Linux_Shell_Pipe_to_Shell_attack29.log`
- `Linux_Shell_Pipe_to_Shell_attack3.log`
- `Linux_Shell_Pipe_to_Shell_attack30.log`
- `Linux_Shell_Pipe_to_Shell_attack31.log`
- `Linux_Shell_Pipe_to_Shell_attack32.log`
- `Linux_Shell_Pipe_to_Shell_attack33.log`
- `Linux_Shell_Pipe_to_Shell_attack34.log`
- `Linux_Shell_Pipe_to_Shell_attack35.log`
- `Linux_Shell_Pipe_to_Shell_attack36.log`
- `Linux_Shell_Pipe_to_Shell_attack37.log`
- `Linux_Shell_Pipe_to_Shell_attack38.log`
- `Linux_Shell_Pipe_to_Shell_attack39.log`
- `Linux_Shell_Pipe_to_Shell_attack4.log`
- `Linux_Shell_Pipe_to_Shell_attack40.log`
- `Linux_Shell_Pipe_to_Shell_attack41.log`
- `Linux_Shell_Pipe_to_Shell_attack42.log`
- `Linux_Shell_Pipe_to_Shell_attack43.log`
- `Linux_Shell_Pipe_to_Shell_attack44.log`
- `Linux_Shell_Pipe_to_Shell_attack45.log`
- `Linux_Shell_Pipe_to_Shell_attack46.log`
- `Linux_Shell_Pipe_to_Shell_attack47.log`
- `Linux_Shell_Pipe_to_Shell_attack48.log`
- `Linux_Shell_Pipe_to_Shell_attack49.log`
- `Linux_Shell_Pipe_to_Shell_attack5.log`
- `Linux_Shell_Pipe_to_Shell_attack50.log`
- `Linux_Shell_Pipe_to_Shell_attack51.log`
- `Linux_Shell_Pipe_to_Shell_attack52.log`
- `Linux_Shell_Pipe_to_Shell_attack53.log`
- `Linux_Shell_Pipe_to_Shell_attack54.log`
- `Linux_Shell_Pipe_to_Shell_attack55.log`
- `Linux_Shell_Pipe_to_Shell_attack56.log`
- `Linux_Shell_Pipe_to_Shell_attack57.log`
- `Linux_Shell_Pipe_to_Shell_attack58.log`
- `Linux_Shell_Pipe_to_Shell_attack59.log`
- `Linux_Shell_Pipe_to_Shell_attack6.log`
- `Linux_Shell_Pipe_to_Shell_attack60.log`
- `Linux_Shell_Pipe_to_Shell_attack61.log`
- `Linux_Shell_Pipe_to_Shell_attack62.log`
- `Linux_Shell_Pipe_to_Shell_attack63.log`
- `Linux_Shell_Pipe_to_Shell_attack64.log`
- `Linux_Shell_Pipe_to_Shell_attack65.log`
- `Linux_Shell_Pipe_to_Shell_attack66.log`
- `Linux_Shell_Pipe_to_Shell_attack67.log`
- `Linux_Shell_Pipe_to_Shell_attack68.log`
- `Linux_Shell_Pipe_to_Shell_attack69.log`
- `Linux_Shell_Pipe_to_Shell_attack7.log`
- `Linux_Shell_Pipe_to_Shell_attack70.log`
- `Linux_Shell_Pipe_to_Shell_attack71.log`
- `Linux_Shell_Pipe_to_Shell_attack72.log`
- `Linux_Shell_Pipe_to_Shell_attack73.log`
- `Linux_Shell_Pipe_to_Shell_attack74.log`
- `Linux_Shell_Pipe_to_Shell_attack75.log`
- `Linux_Shell_Pipe_to_Shell_attack76.log`
- `Linux_Shell_Pipe_to_Shell_attack77.log`
- `Linux_Shell_Pipe_to_Shell_attack78.log`
- `Linux_Shell_Pipe_to_Shell_attack79.log`
- `Linux_Shell_Pipe_to_Shell_attack8.log`
- `Linux_Shell_Pipe_to_Shell_attack80.log`
- `Linux_Shell_Pipe_to_Shell_attack81.log`
- `Linux_Shell_Pipe_to_Shell_attack82.log`
- `Linux_Shell_Pipe_to_Shell_attack83.log`
- `Linux_Shell_Pipe_to_Shell_attack84.log`
- `Linux_Shell_Pipe_to_Shell_attack85.log`
- `Linux_Shell_Pipe_to_Shell_attack86.log`
- `Linux_Shell_Pipe_to_Shell_attack87.log`
- `Linux_Shell_Pipe_to_Shell_attack88.log`
- `Linux_Shell_Pipe_to_Shell_attack89.log`
- `Linux_Shell_Pipe_to_Shell_attack9.log`
- `Linux_Shell_Pipe_to_Shell_attack90.log`
- `Linux_Shell_Pipe_to_Shell_attack91.log`
- `Linux_Shell_Pipe_to_Shell_attack92.log`
- `Linux_Shell_Pipe_to_Shell_attack93.log`
- `Linux_Shell_Pipe_to_Shell_attack94.log`
- `Linux_Shell_Pipe_to_Shell_attack95.log`
- `Linux_Shell_Pipe_to_Shell_attack96.log`
- `Linux_Shell_Pipe_to_Shell_attack97.log`
- `Linux_Shell_Pipe_to_Shell_attack98.log`
- `Linux_Shell_Pipe_to_Shell_attack99.log`

---

### At Command

**Directory:** `at_command`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Auditctl Clear Rules

**Directory:** `auditctl_clear_rules`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Bash Interactive Shell

**Directory:** `bash_interactive_shell`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Bpf Kprob Tracing Enabled

**Directory:** `bpf_kprob_tracing_enabled`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Chattr Immutable Removal

**Directory:** `chattr_immutable_removal`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Chroot Execution

**Directory:** `chroot_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Clear Syslog

**Directory:** `clear_syslog`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Clipboard Collection

**Directory:** `clipboard_collection`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Cp Passwd Or Shadow Tmp

**Directory:** `cp_passwd_or_shadow_tmp`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Curl Usage

**Directory:** `curl_usage`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Curl Wget Exec Tmp

**Directory:** `curl_wget_exec_tmp`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Dd Process Injection

**Directory:** `dd_process_injection`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Doas Execution

**Directory:** `doas_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Env Shell Invocation

**Directory:** `env_shell_invocation`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Esxcli Network Discovery

**Directory:** `esxcli_network_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Esxcli Permission Change Admin

**Directory:** `esxcli_permission_change_admin`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Esxcli Storage Discovery

**Directory:** `esxcli_storage_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Esxcli Syslog Config Change

**Directory:** `esxcli_syslog_config_change`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Esxcli System Discovery

**Directory:** `esxcli_system_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Esxcli User Account Creation

**Directory:** `esxcli_user_account_creation`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Esxcli Vm Discovery

**Directory:** `esxcli_vm_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Esxcli Vm Kill

**Directory:** `esxcli_vm_kill`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Esxcli Vsan Discovery

**Directory:** `esxcli_vsan_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### File Deletion

**Directory:** `file_deletion`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Gcc Shell Execution

**Directory:** `gcc_shell_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Git Shell Execution

**Directory:** `git_shell_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Groupdel

**Directory:** `groupdel`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Install Root Certificate

**Directory:** `install_root_certificate`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Install Suspicioua Packages

**Directory:** `install_suspicioua_packages`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Install Suspicious Packages

**Directory:** `install_suspicious_packages`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Iptables Flush Ufw

**Directory:** `iptables_flush_ufw`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Malware Gobrat Grep Payload Discovery

**Directory:** `malware_gobrat_grep_payload_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Mkfifo Named Pipe Creation

**Directory:** `mkfifo_named_pipe_creation`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Mkfifo Named Pipe Creation Susp Location

**Directory:** `mkfifo_named_pipe_creation_susp_location`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Mount Hidepid

**Directory:** `mount_hidepid`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Netcat Reverse Shell

**Directory:** `netcat_reverse_shell`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Nice Shell Execution

**Directory:** `nice_shell_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Nohup

**Directory:** `nohup`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Nohup Susp Execution

**Directory:** `nohup_susp_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Omigod Scx Runasprovider Executescript

**Directory:** `omigod_scx_runasprovider_executescript`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Perl Reverse Shell

**Directory:** `perl_reverse_shell`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Php Reverse Shell

**Directory:** `php_reverse_shell`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Pnscan Binary Cli Pattern

**Directory:** `pnscan_binary_cli_pattern`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Proxy Connection

**Directory:** `proxy_connection`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Pua Trufflehog

**Directory:** `pua_trufflehog`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Python Http Server Execution

**Directory:** `python_http_server_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Python Pty Spawn

**Directory:** `python_pty_spawn`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Python Reverse Shell

**Directory:** `python_reverse_shell`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Python Shell Os System

**Directory:** `python_shell_os_system`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Remote Access Tools Teamviewer Incoming Connection

**Directory:** `remote_access_tools_teamviewer_incoming_connection`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Remote System Discovery

**Directory:** `remote_system_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Remove Package

**Directory:** `remove_package`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Rsync Shell Execution

**Directory:** `rsync_shell_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Rsync Shell Spawn

**Directory:** `rsync_shell_spawn`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Ruby Reverse Shell

**Directory:** `ruby_reverse_shell`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Schedule Task Job Cron

**Directory:** `schedule_task_job_cron`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Security Software Discovery

**Directory:** `security_software_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Security Tools Disabling

**Directory:** `security_tools_disabling`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Services Stop And Disable

**Directory:** `services_stop_and_disable`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Setgid Setuid

**Directory:** `setgid_setuid`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Ssh Shell Execution

**Directory:** `ssh_shell_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Ssm Agent Abuse

**Directory:** `ssm_agent_abuse`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Chmod Directories

**Directory:** `susp_chmod_directories`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Container Residence Discovery

**Directory:** `susp_container_residence_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Curl Fileupload

**Directory:** `susp_curl_fileupload`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Curl Useragent

**Directory:** `susp_curl_useragent`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Dockerenv Recon

**Directory:** `susp_dockerenv_recon`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Execution Tmp Folder

**Directory:** `susp_execution_tmp_folder`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Find Execution

**Directory:** `susp_find_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Git Clone

**Directory:** `susp_git_clone`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp History Delete

**Directory:** `susp_history_delete`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp History Recon

**Directory:** `susp_history_recon`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Hktl Execution

**Directory:** `susp_hktl_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Inod Listing

**Directory:** `susp_inod_listing`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Interactive Bash

**Directory:** `susp_interactive_bash`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Java Children

**Directory:** `susp_java_children`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Network Utilities Execution

**Directory:** `susp_network_utilities_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Process Reading Sudoers

**Directory:** `susp_process_reading_sudoers`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Recon Indicators

**Directory:** `susp_recon_indicators`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Sensitive File Access

**Directory:** `susp_sensitive_file_access`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Shell Child Process From Parent Tmp Folder

**Directory:** `susp_shell_child_process_from_parent_tmp_folder`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Susp Shell Script Exec From Susp Location

**Directory:** `susp_shell_script_exec_from_susp_location`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### System Info Discovery

**Directory:** `system_info_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### System Network Connections Discovery

**Directory:** `system_network_connections_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### System Network Discovery

**Directory:** `system_network_discovery`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Systemctl Mask Power Settings

**Directory:** `systemctl_mask_power_settings`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Touch Susp

**Directory:** `touch_susp`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Triple Cross Rootkit Execve Hijack

**Directory:** `triple_cross_rootkit_execve_hijack`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Triple Cross Rootkit Install

**Directory:** `triple_cross_rootkit_install`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Userdel

**Directory:** `userdel`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Usermod Susp Group

**Directory:** `usermod_susp_group`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Vim Shell Execution

**Directory:** `vim_shell_execution`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Webshell Detection

**Directory:** `webshell_detection`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Wget Download Suspicious Directory

**Directory:** `wget_download_suspicious_directory`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

### Xterm Reverse Shell

**Directory:** `xterm_reverse_shell`

**Event Counts:**
- Total: 0
- Match Events: 0
- Evasion Events: 0

**Properties:**
- Evasion Possible: False
- Broken Rule: False
- Queried Event Types: Microsoft-Windows-Sysmon_1

---

