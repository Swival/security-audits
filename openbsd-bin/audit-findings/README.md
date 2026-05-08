# OpenBSD Userland Audit Findings (Extended)

Extended security audit of OpenBSD userland programs, daemons, and libraries that ship with the base system. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 300** -- High: 108, Medium: 189, Low: 3

Findings are numbered per component, so some numbers are reused across the different tables below.

## Findings

### acme-client

| # | Finding | Severity |
|---|---------|----------|
| [087](087-missing-challenge-error-object-dereferences-null.md) | Missing challenge error object dereferences NULL | Medium |
| [168](168-unbounded-response-headers-exhaust-memory.md) | Unbounded response headers exhaust memory | Medium |
| [169](169-unbounded-response-body-exhausts-memory.md) | Unbounded response body exhausts memory | Medium |

### amd

| # | Finding | Severity |
|---|---------|----------|
| [144](144-export-paths-escape-host-mount-root.md) | Export paths escape host mount root | High |
| [288](288-unbounded-groups-xdr-recursion.md) | Unbounded groups XDR recursion | Medium |
| [289](289-unbounded-exports-xdr-recursion.md) | Unbounded exports XDR recursion | Medium |

### atactl

| # | Finding | Severity |
|---|---------|----------|
| [025](025-smart-summary-log-index-reads-past-stack-buffer.md) | SMART summary log index reads past stack buffer | Medium |
| [026](026-smart-selftest-log-index-reads-past-stack-buffer.md) | SMART selftest log index reads past stack buffer | Medium |

### awk

| # | Finding | Severity |
|---|---------|----------|
| [071](071-csv-split-allocates-one-byte-too-few.md) | CSV split allocates one byte too few | Medium |

### bgpd

| # | Finding | Severity |
|---|---------|----------|
| [029](029-pfkey-failure-downgrades-rtr-authentication.md) | PFKEY failure downgrades RTR authentication | Medium |
| [030](030-tcp-md5-failure-downgrades-rtr-authentication.md) | TCP MD5 failure downgrades RTR authentication | Medium |
| [034](034-outbound-tcp-md5-failure-is-ignored.md) | Outbound TCP MD5 failure is ignored | High |
| [046](046-rtr-negotiation-ignores-configured-minimum-version.md) | RTR negotiation ignores configured minimum version | Medium |
| [059](059-extended-updates-accepted-without-negotiation.md) | Extended UPDATEs accepted without negotiation | Medium |
| [145](145-evpn-label-length-overflows-vni-stack-local.md) | EVPN label length overflows VNI stack local | High |
| [211](211-as4-path-merge-wraps-heap-allocation-length.md) | AS4_PATH merge wraps heap allocation length | High |
| [339](339-flowspec-routes-bypass-inbound-filters.md) | Flowspec routes bypass inbound and outbound filters | High |

### bgplgd

| # | Finding | Severity |
|---|---------|----------|
| [035](035-invalid-fastcgi-version-exits-daemon.md) | Invalid FastCGI version exits daemon | High |
| [036](036-repeated-empty-params-spawn-repeated-cgi-children.md) | Repeated empty params spawn repeated CGI children | High |

### cdio

| # | Finding | Severity |
|---|---------|----------|
| [260](260-malicious-cddb-reply-grows-track-title-without-bound.md) | Malicious CDDB reply grows track title without bound | Medium |
| [278](278-device-controlled-block-descriptor-length-indexes-past-stack.md) | Device-controlled block descriptor length indexes past stack buffer | High |
| [279](279-device-controlled-mode-length-exposes-stack-beyond-buffer.md) | Device-controlled mode length exposes stack beyond buffer | Medium |

### ctfconv / ctfdump

| # | Finding | Severity |
|---|---------|----------|
| [280](280-ctf-payload-length-includes-header.md) | CTF payload length includes header | Medium |
| [307](307-self-referential-anonymous-types-exhaust-comparator-stack.md) | Self-referential anonymous types exhaust comparator stack | Medium |
| [308](308-deep-used-type-chains-exhaust-reference-stack.md) | Deep used type chains exhaust reference stack | Medium |
| [329](329-section-name-compare-reads-past-string-table.md) | Section-name compare reads past string table | Medium |
| [330](330-malformed-symbol-entry-size-causes-out-of-bounds-read.md) | Malformed symbol entry size causes out-of-bounds read | Medium |

### deroff

| # | Finding | Severity |
|---|---------|----------|
| [281](281-path-max-so-name-overflows-fname.md) | PATH_MAX .so name overflows fname | Medium |
| [282](282-nested-so-overflows-include-stack.md) | Nested .so overflows include stack | Medium |

### dhcp6leased

| # | Finding | Severity |
|---|---------|----------|
| [189](189-invalid-ia-prefix-length-terminates-engine.md) | Invalid IA_PREFIX length terminates engine | High |
| [190](190-unknown-dhcpv6-message-type-terminates-engine.md) | Unknown DHCPv6 message type terminates engine | High |

### dhcpd

| # | Finding | Severity |
|---|---------|----------|
| [199](199-server-hostname-quote-injection-corrupts-lease-database-synt.md) | Hostname quote injection corrupts lease database syntax | Medium |
| [238](238-dhcpdecline-can-abandon-another-client-s-lease.md) | DHCPDECLINE can abandon another client's lease | Medium |
| [239](239-missing-sync-key-falls-back-to-known-hmac-key.md) | Missing sync key falls back to known HMAC key | High |
| [262](262-duplicate-classless-route-requests-overflow-priority-list.md) | Duplicate classless route requests overflow priority list | High |

### dhcrelay6

| # | Finding | Severity |
|---|---------|----------|
| [126](126-truncated-bpf-packet-desynchronizes-receive-buffer.md) | Truncated BPF packet desynchronizes receive buffer | Medium |
| [240](240-short-relay-reply-underflows-option-parser-length.md) | Short relay-reply underflows option parser length | High |
| [313](313-short-ipv6-payload-permits-udp-out-of-bounds-read.md) | Short IPv6 payload permits UDP out-of-bounds read | High |

### dump / restore

| # | Finding | Severity |
|---|---------|----------|
| [070](070-ts-bits-map-size-can-overflow-prior-allocation.md) | TS_BITS map size can overflow prior allocation | High |
| [191](191-out-of-range-directory-inode-null-dereference.md) | Out-of-range directory inode null dereference | Medium |
| [192](192-directory-record-length-permits-header-overread.md) | Directory record length permits header overread | Medium |
| [194](194-unterminated-dump-names-reach-strcmp.md) | Unterminated dump names reach strcmp | Medium |
| [195](195-unchecked-entry-table-size-repositions-table-outside-file.md) | Unchecked entry table size repositions table outside file | High |
| [196](196-unchecked-string-table-size-repositions-entries-outside-file.md) | Unchecked string table size repositions entries outside file | High |
| [221](221-remote-rmt-peer-controls-read-size-past-caller-limit.md) | Remote rmt peer controls read size past caller limit | High |

### dvmrpd

| # | Finding | Severity |
|---|---------|----------|
| [171](171-truncated-report-overreads-netmask.md) | Truncated report overreads netmask | High |
| [172](172-truncated-route-entry-overreads-netid.md) | Truncated route entry overreads netid | High |
| [314](314-short-probe-payload-causes-out-of-bounds-read.md) | Short probe payload causes out-of-bounds read | High |

### eigrpd

| # | Finding | Severity |
|---|---------|----------|
| [173](173-peer-metric-bandwidth-divides-by-zero.md) | Peer metric bandwidth divides by zero | High |
| [290](290-ipv4-header-length-underflows-packet-length.md) | IPv4 header length underflows packet length | High |

### ftp

| # | Finding | Severity |
|---|---------|----------|
| [006](006-mdtm-success-reply-scans-past-string-terminator.md) | MDTM success reply scans past string terminator | Medium |
| [042](042-remote-http-response-line-exhausts-memory.md) | Remote HTTP response line exhausts memory | Medium |
| [072](072-active-data-socket-trusts-first-peer.md) | Active data socket trusts first peer | High |
| [227](227-mapped-remote-filename-overflows-output-buffer.md) | Mapped remote filename overflows output buffer | High |

### gencat

| # | Finding | Severity |
|---|---------|----------|
| [283](283-delset-double-frees-first-message-string.md) | delset double-frees first message string | Medium |

### gprof

| # | Finding | Severity |
|---|---------|----------|
| [228](228-symbol-table-size-is-not-bounded-by-mapped-file.md) | Symbol table size is not bounded by mapped file | Medium |
| [229](229-arm-symbol-name-offset-is-not-bounded-by-string-table.md) | ARM symbol name offset is not bounded by string table | Medium |

### hostapd

| # | Finding | Severity |
|---|---------|----------|
| [200](200-radiotap-offset-omitted-from-frame-length-check.md) | Radiotap offset omitted from frame length check | Medium |
| [241](241-route-roaming-checks-wrong-mac-table.md) | Route roaming checks wrong MAC table | Medium |

### indent

| # | Finding | Severity |
|---|---------|----------|
| [139](139-backup-file-creation-follows-attacker-symlink.md) | Backup file creation follows attacker symlink | Medium |
| [284](284-high-bit-source-byte-indexes-outside-chartype.md) | High-bit source byte indexes outside chartype | Medium |

### infocmp

| # | Finding | Severity |
|---|---------|----------|
| [160](160-capped-crosslinks-are-iterated-past-storage.md) | Capped crosslinks are iterated past storage | Medium |

### installboot

| # | Finding | Severity |
|---|---------|----------|
| [077](077-zero-gpt-partition-size-divides-by-zero.md) | Zero GPT partition size divides by zero (i386) | Medium |
| [078](078-excessive-gpt-partition-count-overflows-stack-array.md) | Excessive GPT partition count overflows stack array (i386) | Medium |
| [079](079-tiny-gpt-partition-size-inflates-copy-length.md) | Tiny GPT partition size inflates copy length (i386) | Medium |
| [127](127-gpt-partition-count-overflows-stack-array.md) | GPT partition count overflows stack array (EFI) | Medium |
| [128](128-zero-gpt-partition-size-divides-by-zero.md) | Zero GPT partition size divides by zero (EFI) | Medium |

### ipcs

| # | Finding | Severity |
|---|---------|----------|
| [140](140-crafted-kvm-dump-writes-past-message-queue-array.md) | Crafted KVM dump writes past message queue array | Medium |

### iscsid

| # | Finding | Severity |
|---|---------|----------|
| [080](080-check-condition-sense-length-out-of-bounds-read.md) | CHECK CONDITION sense length out-of-bounds read | Medium |

### iked

| # | Finding | Severity |
|---|---------|----------|
| [027](027-remote-ip-identity-length-overflows-stack-sockaddr.md) | Remote IP identity length overflows stack sockaddr | High |
| [032](032-stale-ocsp-good-status-accepted-when-tolerance-is-zero.md) | Stale OCSP GOOD status accepted when tolerance is zero | High |
| [033](033-ocsp-nonce-absence-is-accepted.md) | OCSP nonce absence is accepted | High |
| [085](085-zero-length-bundle-certificate-becomes-bogus-x509-pointer.md) | Zero-length bundle certificate becomes bogus X509 pointer | High |
| [086](086-unbounded-recursive-transform-parsing.md) | Unbounded recursive transform parsing | High |
| [120](120-unchecked-procfd-target-indexes-peer-arrays.md) | Unchecked procfd target indexes peer arrays | High |
| [222](222-curve25519-accepts-low-order-public-keys.md) | Curve25519 accepts low-order public keys | High |

### isakmpd

| # | Finding | Severity |
|---|---------|----------|
| [041](041-keynote-assertion-signature-check-verifies-wrong-buffer.md) | KeyNote assertion signature check verifies wrong buffer | High |
| [121](121-notify-spi-length-is-not-bounded-by-payload-length.md) | NOTIFY SPI length is not bounded by payload length | High |
| [136](136-short-quick-mode-hash-under-allocates-prf-buffer.md) | Short quick mode HASH under-allocates PRF buffer | High |
| [137](137-short-final-quick-mode-hash-under-allocates-prf-buffer.md) | Quick mode HASH(3) under-allocates PRF buffer | High |
| [154](154-peer-attribute-list-wraps-response-allocation-length.md) | Peer attribute list wraps response allocation length | High |
| [155](155-non-rsa-certificate-double-free.md) | Non-RSA certificate double free | High |
| [223](223-directory-opened-before-broker-authorization.md) | Directory opened before broker authorization | Low |
| [270](270-short-remote-id-causes-out-of-bounds-read.md) | Short remote ID causes out-of-bounds read | High |
| [277](277-key-rr-length-unchecked-before-header-reads.md) | KEY RR length unchecked before header reads | Medium |
| [328](328-short-blowfish-ciphertext-underflows-decrypt-pointer.md) | Short Blowfish ciphertext underflows decrypt pointer | High |

### ksh

| # | Finding | Severity |
|---|---------|----------|
| [008](008-restricted-shell-enoexec-fallback-runs-unrestricted-interpre.md) | Restricted shell ENOEXEC fallback runs unrestricted interpreter | High |
| [023](023-restricted-shell-sources-env-before-restriction.md) | Restricted shell sources ENV before restriction | High |

### last

| # | Finding | Severity |
|---|---------|----------|
| [204](204-unterminated-ut-line-escapes-fixed-field.md) | Unterminated ut_line escapes fixed field | Medium |

### ldap

| # | Finding | Severity |
|---|---------|----------|
| [109](109-cancelled-queued-requests-leak-namespace-queue-quota.md) | Cancelled queued requests leak namespace queue quota | Medium |
| [161](161-malformed-response-control-dereferences-missing-subelements.md) | Malformed response control dereferences missing subelements | Medium |
| [162](162-malformed-page-control-dereferences-missing-cookie-field.md) | Malformed page control dereferences missing cookie field | Medium |
| [341](341-time-validator-ignores-bytes-after-nul.md) | Time validator ignores bytes after NUL | Medium |

### ldpd

| # | Finding | Severity |
|---|---------|----------|
| [090](090-revoked-ldp-md5-auth-entries-survive-reload.md) | Revoked LDP MD5 auth entries survive reload | High |
| [242](242-zero-length-pw-sub-tlv-causes-infinite-parse-loop.md) | Zero-length PW sub-TLV causes infinite parse loop | High |

### less

| # | Finding | Severity |
|---|---------|----------|
| [122](122-old-lesskey-command-without-action-reads-past-buffer.md) | Old lesskey command without action reads past buffer | Medium |
| [123](123-unterminated-a-extra-string-reads-beyond-lesskey-buffer.md) | Unterminated A_EXTRA string reads beyond lesskey buffer | Medium |
| [124](124-long-lesskey-edit-prefix-overflows-usercmd-stack-buffer.md) | Long lesskey edit prefix overflows usercmd stack buffer | Medium |

### libagentx

| # | Finding | Severity |
|---|---------|----------|
| [024](024-getbulk-non-repeater-offset-writes-past-varbind-array.md) | GETBULK non-repeater offset writes past varbind array | High |
| [064](064-missing-string-padding-validation-underflows-pdu-parser-leng.md) | Missing string padding validation underflows PDU parser length | High |

### libedit

| # | Finding | Severity |
|---|---------|----------|
| [258](258-unknown-settc-name-writes-past-t-val.md) | Unknown settc name writes past t_val | Medium |

### libevent

| # | Finding | Severity |
|---|---------|----------|
| [269](269-overlong-tag-varint-shifts-past-word-width.md) | Overlong tag varint shifts past word width | Medium |

### libfuse

| # | Finding | Severity |
|---|---------|----------|
| [104](104-failed-lookups-retain-allocated-vnodes.md) | Failed lookups retain allocated vnodes | Medium |

### libkeynote

| # | Finding | Severity |
|---|---------|----------|
| [132](132-unterminated-assertion-reads-past-buffer.md) | Unterminated assertion reads past buffer | Medium |
| [133](133-oversized-assertion-file-overflows-resized-buffer.md) | Oversized assertion file overflows resized buffer | High |
| [134](134-embedded-nul-truncates-assertion-copy.md) | Embedded NUL truncates assertion copy | Medium |
| [272](272-dsa-private-key-created-with-umask-derived-permissions.md) | DSA private key created with umask-derived permissions | Medium |
| [273](273-rsa-private-key-created-with-umask-derived-permissions.md) | RSA private key created with umask-derived permissions | Medium |
| [306](306-non-rsa-x509-public-key-crashes-decoding.md) | Non-RSA X509 public key crashes decoding | Medium |

### libsndio

| # | Finding | Severity |
|---|---------|----------|
| [084](084-oversized-data-length-desynchronizes-sndio-client.md) | Oversized DATA length desynchronizes sndio client | Medium |
| [274](274-zero-mixer-maxval-divides-client-reads.md) | Zero mixer maxval divides client reads | Medium |
| [275](275-mixer-channel-count-overflows-fixed-volume-array.md) | Mixer channel count overflows fixed volume array | Medium |

### libusbhid

| # | Finding | Severity |
|---|---------|----------|
| [276](276-hid-usage-table-wildcard-name-is-used-as-snprintf-format.md) | HID usage table wildcard name is used as snprintf format | Medium |

### ldomctl / ldomd

| # | Finding | Severity |
|---|---------|----------|
| [291](291-unchecked-name-offset-drives-out-of-bounds-string-read.md) | Unchecked name offset drives out-of-bounds string read | Medium |
| [292](292-string-property-offset-permits-unbounded-scan.md) | String property offset permits unbounded scan | Medium |
| [293](293-data-property-length-permits-out-of-bounds-copy.md) | Data property length permits out-of-bounds copy | Medium |
| [294](294-short-mdstore-reply-reads-past-packet.md) | Short mdstore reply reads past packet | Medium |
| [295](295-mdstore-list-parser-trusts-peer-payload-length.md) | mdstore list parser trusts peer payload length | Medium |
| [297](297-receive-length-overflows-caller-buffer.md) | Receive length overflows caller buffer | High |
| [298](298-malformed-packet-type-accepted-as-data.md) | Malformed packet type accepted as data | Medium |
| [299](299-short-var-config-frame-reads-past-buffer.md) | Short var-config frame reads past buffer | Medium |
| [342](342-pri-data-fragment-length-overflows-receive-buffer.md) | PRI_DATA fragment length overflows receive buffer | High |

### lldpd

| # | Finding | Severity |
|---|---------|----------|
| [146](146-unauthenticated-lldp-frames-create-unbounded-msap-state.md) | Unauthenticated LLDP frames create unbounded MSAP state | Medium |

### locate

| # | Finding | Severity |
|---|---------|----------|
| [331](331-decoded-database-path-overflows-stack-buffer.md) | Decoded database path overflows stack buffer | High |

### login

| # | Finding | Severity |
|---|---------|----------|
| [028](028-forced-login-root-instance-grants-root-context.md) | Forced login root instance grants root context | High |

### lpd

| # | Finding | Severity |
|---|---------|----------|
| [004](004-control-file-omitting-job-name-crashes-banner-printing.md) | Missing job name crashes banner printing | Medium |
| [147](147-ipv6-host-authorization-compares-only-32-bits.md) | IPv6 host authorization compares only 32 bits | High |
| [344](344-control-bytes-index-past-banner-glyph-table.md) | Control bytes index past banner glyph table | Medium |
| [345](345-blank-banner-line-underreads-output-buffer.md) | Blank banner line underreads output buffer | Medium |

### mg

| # | Finding | Severity |
|---|---------|----------|
| [105](105-newline-filenames-forge-dired-entries.md) | Newline filenames forge dired entries | Medium |
| [141](141-quoted-bind-key-sequence-overflows-key-buffer.md) | Quoted bind key sequence overflows key buffer | Medium |
| [142](142-empty-bind-key-sequence-underflows-key-count.md) | Empty bind key sequence underflows key count | Medium |
| [205](205-unquoted-directory-path-reaches-popen-shell.md) | Unquoted directory path reaches popen shell | Medium |

### mopd

| # | Finding | Severity |
|---|---------|----------|
| [129](129-unchecked-mop-info-length-overreads-packet-data.md) | Unchecked MOP info length overreads packet data | Medium |
| [201](201-short-802-3-length-underflows-dump-loop-bound.md) | Short 802.3 length underflows dump loop bound | Medium |
| [212](212-zero-header-elf32-file-writes-before-section-array.md) | Zero-header ELF32 file writes before section array | Medium |
| [213](213-final-tlv-causes-out-of-bounds-type-read.md) | Final TLV causes out-of-bounds type read | Medium |
| [316](316-software-id-length-overflows-stack-buffer.md) | Software ID length overflows stack buffer | High |

### mrouted / mrinfo

| # | Finding | Severity |
|---|---------|----------|
| [243](243-truncated-legacy-neighbor-tuple-overreads-packet.md) | Truncated legacy neighbor tuple overreads packet | Medium |
| [244](244-empty-route-report-indexes-before-stack-route-array.md) | Empty route report indexes before stack route array | High |

### mtrace

| # | Finding | Severity |
|---|---------|----------|
| [110](110-overlong-mtrace-reply-reaches-fixed-hop-arrays.md) | Overlong mtrace reply reaches fixed hop arrays | High |
| [111](111-passive-mtrace-accepts-unbounded-hop-count.md) | Passive mtrace accepts unbounded hop count | High |

### mv

| # | Finding | Severity |
|---|---------|----------|
| [102](102-source-symlink-race-leaks-privileged-file-contents.md) | Source symlink race leaks privileged file contents | Medium |

### nm

| # | Finding | Severity |
|---|---------|----------|
| [073](073-archive-long-name-offset-reads-outside-name-table.md) | Archive long-name offset reads outside name table | Medium |
| [074](074-sysv-archive-index-count-walks-outside-mmap.md) | SysV archive index count walks outside mmap | Medium |
| [332](332-non-multiple-symbol-table-size-underallocates-output-array.md) | Non-multiple symbol table size underallocates output array | Medium |
| [333](333-unterminated-section-name-table-reaches-strcmp.md) | Unterminated section-name table reaches strcmp | Low |

### npppd

| # | Finding | Severity |
|---|---------|----------|
| [081](081-multicast-path-sends-plaintext-after-mppe-encryption.md) | Multicast path sends plaintext after MPPE encryption | High |
| [082](082-interface-name-filter-always-authorizes-forbidden-interfaces.md) | Interface name filter always authorizes forbidden interfaces | High |
| [083](083-prefix-only-path-check-permits-directory-traversal.md) | Prefix-only path check permits directory traversal | Medium |
| [092](092-chap-username-permits-authentication-log-field-injection.md) | CHAP username permits authentication log field injection | Medium |
| [112](112-failed-ppp-bind-is-marked-established.md) | Failed PPP bind is marked established | Medium |
| [113](113-confrej-mru-length-underflows-packet-read.md) | ConfRej MRU length underflows packet read | Medium |
| [148](148-short-disconnect-imsg-causes-out-of-bounds-read.md) | Short DISCONNECT imsg causes out-of-bounds read | Medium |
| [149](149-truncated-pap-header-reads-past-packet.md) | Truncated PAP header reads past packet | Medium |
| [150](150-missing-service-tag-logs-uninitialized-stack-bytes.md) | Missing service tag logs uninitialized stack bytes | Medium |
| [202](202-descriptor-exhaustion-never-pauses-accept-loop.md) | Descriptor exhaustion never pauses accept loop | Medium |
| [245](245-required-ipsec-policy-failure-still-starts-listener.md) | Required IPsec policy failure still starts listener | High |
| [246](246-oversized-ipcp-reject-leaks-stack.md) | Oversized IPCP reject leaks stack | High |
| [247](247-short-ac-cookie-triggers-out-of-bounds-read.md) | Short AC-Cookie triggers out-of-bounds read | Medium |
| [248](248-zero-length-pptp-control-packet-stalls-parser.md) | Zero-length PPTP control packet stalls parser | High |
| [317](317-short-mppe-frame-bypasses-minimum-length-check.md) | Short MPPE frame bypasses minimum length check | High |
| [318](318-uninitialized-ppp-start-status-bytes-sent-to-control-clients.md) | Uninitialized PPP_START status bytes sent to control clients | Medium |
| [319](319-uninitialized-ppp-stop-status-bytes-sent-to-control-clients.md) | Uninitialized PPP_STOP status bytes sent to control clients | Medium |

### ocspcheck

| # | Finding | Severity |
|---|---------|----------|
| [093](093-ocsp-unknown-status-accepted.md) | OCSP UNKNOWN status accepted | High |
| [175](175-unbounded-http-header-buffering.md) | Unbounded HTTP header buffering | Medium |
| [176](176-unbounded-http-body-buffering.md) | Unbounded HTTP body buffering | Medium |

### openssl

| # | Finding | Severity |
|---|---------|----------|
| [043](043-xmpp-starttls-response-writes-past-buffer.md) | XMPP STARTTLS response writes past buffer | Medium |
| [163](163-ecparam-check-exits-success-after-failed-curve-validation.md) | ecparam check exits success after failed curve validation | High |
| [309](309-crl-signature-verification-exits-successfully-on-failure.md) | CRL signature verification exits successfully on failure | High |
| [310](310-client-ptr-can-terminate-listener.md) | Client PTR forward lookup can terminate listener | Medium |

### ospfd / ospf6d

| # | Finding | Severity |
|---|---------|----------|
| [214](214-neighbor-deletion-resets-replay-counter.md) | Neighbor deletion resets replay counter | High |
| [300](300-inter-area-prefix-lsa-inflates-prefix-parser-bounds.md) | Inter-area prefix LSA inflates prefix parser bounds | High |
| [320](320-zero-length-lsa-causes-unbounded-update-parsing.md) | Zero-length LSA causes unbounded update parsing | High |

### patch

| # | Finding | Severity |
|---|---------|----------|
| [164](164-revision-scan-reads-past-mmaped-file.md) | Revision scan reads past mmaped file | Medium |
| [230](230-normal-append-marker-underwrites-hunk-header.md) | Normal append marker underwrites hunk header | Medium |

### pax / tar

| # | Finding | Severity |
|---|---------|----------|
| [103](103-symlink-cycle-hangs-tar-directory-extraction.md) | Symlink cycle hangs tar directory extraction | Medium |
| [237](237-preserved-header-pathname-reaches-filesystem-writes.md) | Preserved header pathname reaches filesystem writes | Medium |

### pcidump

| # | Finding | Severity |
|---|---------|----------|
| [060](060-cyclic-pci-capability-list-causes-infinite-dump-loop.md) | Cyclic PCI capability list causes infinite dump loop | Medium |
| [061](061-cyclic-pcie-enhanced-capability-list-causes-infinite-dump-lo.md) | Cyclic PCIe enhanced capability list causes infinite dump loop | Medium |

### pkgconf

| # | Finding | Severity |
|---|---------|----------|
| [165](165-missing-conflict-dependency-unrefs-null-package.md) | Missing conflict dependency unrefs null package | Medium |
| [311](311-exact-size-expansion-writes-past-stack-buffer.md) | Exact-size expansion writes past stack buffer | High |

### pppd

| # | Finding | Severity |
|---|---------|----------|
| [094](094-report-capture-overflows-report-buffer.md) | REPORT capture overflows report buffer | High |
| [114](114-short-ipcp-nak-reads-past-packet-buffer.md) | Short IPCP nak reads past packet buffer | Medium |
| [115](115-short-ipcp-reject-reads-past-packet-buffer.md) | Short IPCP reject reads past packet buffer | Medium |
| [116](116-zero-length-nak-option-loops-forever.md) | Zero-length IPCP nak option loops forever | Medium |
| [215](215-malformed-cbcp-option-length-causes-out-of-bounds-read.md) | Malformed CBCP option length causes out-of-bounds read | Medium |

### radiusd

| # | Finding | Severity |
|---|---------|----------|
| [020](020-stale-username-selects-authenticate-rule.md) | Stale username selects authenticate rule | Medium |
| [062](062-reject-path-reads-uninitialized-auth-flags.md) | Reject path reads uninitialized auth flags | Medium |
| [151](151-module-start-runs-before-privilege-drop-enforcement.md) | Module start runs before privilege-drop enforcement | High |
| [216](216-ms-chap-chap-length-drives-username-overread.md) | MS-CHAP chap length drives username overread | High |

### rbootd

| # | Finding | Severity |
|---|---------|----------|
| [263](263-rmpconn-leak-on-connection-cleanup.md) | RMPCONN leak on connection cleanup | Medium |

### rdist / rdistd

| # | Finding | Severity |
|---|---------|----------|
| [007](007-recursive-notice-responses-exhaust-stack.md) | Recursive notice responses exhaust stack | Medium |
| [044](044-nested-directory-commands-overflow-saved-target-stack.md) | Nested directory commands overflow saved target stack | High |
| [052](052-remove-query-escapes-source-tree.md) | remove query escapes source tree | Low |

### relayd

| # | Finding | Severity |
|---|---------|----------|
| [011](011-transfer-encoding-and-content-length-forwarded-after-chunked.md) | Transfer-Encoding and Content-Length forwarded after chunked selection | High |
| [012](012-duplicate-content-length-forwarded-while-last-value-controls.md) | Duplicate Content-Length enables request smuggling | High |
| [037](037-dns-response-validation-skips-responder-address-on-session-s.md) | DNS response validation skips responder address on session socket | Medium |
| [130](130-peer-process-indexes-fd-arrays-without-bounds-checks.md) | Peer process indexes fd arrays without bounds checks | High |

### ripd

| # | Finding | Severity |
|---|---------|----------|
| [249](249-short-rip-packet-reads-past-authentication-header.md) | Short RIP packet reads past authentication header | Medium |
| [250](250-short-simple-auth-packet-reads-past-buffer.md) | Short simple-auth packet reads past buffer | Medium |
| [251](251-short-md5-auth-packet-reads-past-buffer.md) | Short MD5-auth packet reads past buffer | Medium |

### route6d

| # | Finding | Severity |
|---|---------|----------|
| [178](178-oversized-rip-request-overreads-reply-buffer.md) | Oversized RIPng request overreads reply buffer | High |

### rpc.bootparamd

| # | Finding | Severity |
|---|---------|----------|
| [179](179-unauthenticated-dump-request-writes-through-null-response-po.md) | Unauthenticated dump request writes through null response pointer | Medium |

### rpc.lockd

| # | Finding | Severity |
|---|---------|----------|
| [203](203-remote-filehandle-length-causes-heap-over-read-in-lock-compa.md) | Remote filehandle length causes heap over-read in lock comparison | High |

### rpcinfo

| # | Finding | Severity |
|---|---------|----------|
| [166](166-udp-version-mismatch-range-drives-four-billion-probe-loop.md) | UDP version mismatch range drives four-billion probe loop | Medium |
| [167](167-tcp-version-mismatch-range-drives-four-billion-probe-loop.md) | TCP version mismatch range drives four-billion probe loop | Medium |

### rpki-client

| # | Finding | Severity |
|---|---------|----------|
| [013](013-oversized-http-response-line-aborts-client.md) | Oversized HTTP response line aborts client | Medium |
| [014](014-oversized-proxy-response-line-aborts-client.md) | Oversized proxy response line aborts client | Medium |
| [021](021-shortlist-host-prefix-bypass.md) | Shortlist host prefix bypass | Medium |
| [047](047-rrdp-delete-accepts-sibling-repository-prefix.md) | RRDP delete accepts sibling repository prefix | Medium |
| [099](099-cached-delta-skips-notification-delta-cap.md) | Cached delta skips notification delta cap | Medium |
| [264](264-equal-boundary-ip-ranges-bypass-overlap-rejection.md) | Equal-boundary IP ranges bypass overlap rejection | High |

### rsync

| # | Finding | Severity |
|---|---------|----------|
| [206](206-int32-min-token-overflows-signed-negation.md) | INT32_MIN token overflows signed negation | Medium |
| [285](285-peer-checksum-length-overflows-block-digest-buffer.md) | Peer checksum length overflows block digest buffer | Medium |
| [334](334-oversized-remote-identifier-aborts-rsync.md) | Oversized remote identifier aborts rsync | Medium |
| [335](335-unbounded-identifier-list-exhausts-memory.md) | Unbounded identifier list exhausts memory | Medium |

### sasyncd

| # | Finding | Severity |
|---|---------|----------|
| [321](321-cleartext-padding-length-underflows-decrypted-message-length.md) | Cleartext padding length underflows decrypted message length | High |

### showmount

| # | Finding | Severity |
|---|---------|----------|
| [207](207-unbounded-mount-dump-allocation.md) | Unbounded mount dump allocation | Medium |
| [208](208-unbounded-exports-allocation.md) | Unbounded exports allocation | Medium |
| [209](209-attacker-shaped-dump-tree-overflows-recursion.md) | Attacker-shaped dump tree overflows recursion | Medium |

### signify

| # | Finding | Severity |
|---|---------|----------|
| [233](233-ed25519-verifier-accepts-noncanonical-s.md) | Ed25519 verifier accepts noncanonical S | Medium |
| [336](336-unterminated-gzip-header-exhausts-verifier-memory.md) | Unterminated gzip header exhausts verifier memory | Medium |

### slaacd

| # | Finding | Severity |
|---|---------|----------|
| [224](224-soii-ra-prefix-length-kills-slaacd.md) | SOII RA prefix length kills slaacd | Medium |

### slowcgi

| # | Finding | Severity |
|---|---------|----------|
| [038](038-malformed-fastcgi-version-exits-daemon.md) | Malformed FastCGI version exits daemon | High |
| [039](039-pre-request-stdin-records-exhaust-memory.md) | Pre-request stdin records exhaust memory | Medium |

### snmpd

| # | Finding | Severity |
|---|---------|----------|
| [017](017-extra-df-metric-triplets-index-past-row-array.md) | Extra df metric triplets index past row array | Medium |
| [068](068-padded-agentx-string-length-advances-past-pdu.md) | Padded AgentX string length advances past PDU | High |
| [131](131-peer-supplied-instance-indexes-descriptor-table-out-of-bound.md) | Peer-supplied instance indexes descriptor table out of bounds | Medium |
| [252](252-snmp-ipaddr-formatter-reads-past-short-ber-string.md) | SNMP IPADDR formatter reads past short BER string | Medium |
| [253](253-legacy-snmp-ipaddr-formatter-reads-past-short-ber-string.md) | Legacy SNMP IPADDR formatter reads past short BER string | Medium |
| [312](312-malformed-ipaddress-reads-past-ber-buffer.md) | Malformed IpAddress reads past BER buffer | Medium |

### sndiod

| # | Finding | Severity |
|---|---------|----------|
| [065](065-disallowed-stream-mode-becomes-runnable.md) | Disallowed stream mode becomes runnable | Medium |

### spell

| # | Finding | Severity |
|---|---------|----------|
| [286](286-prefix-derivation-overflows-stack-buffer.md) | Prefix derivation overflows stack buffer | Medium |

### ssh / sshd / ssh-keygen

| # | Finding | Severity |
|---|---------|----------|
| [003](003-streamlocal-remote-forwards-bypass-forwarding-acls.md) | Streamlocal remote forwards bypass forwarding ACLs | High |
| [009](009-recursive-scp-download-accepts-unexpected-peer-filenames.md) | Recursive SCP download accepts unexpected peer filenames | High |
| [018](018-malformed-hello-extension-leaks-name-allocation.md) | Malformed HELLO extension leaks name allocation | Medium |
| [019](019-malformed-forward-request-leaks-address-strings.md) | Malformed forward request leaks address strings | Medium |
| [045](045-write-capable-open-bypasses-request-restrictions.md) | Write-capable open bypasses request restrictions | Medium |
| [053](053-resident-fido-application-traverses-downloaded-key-path.md) | Resident FIDO application traverses downloaded key path | Medium |
| [055](055-unbounded-rsa-attribute-length-allocation.md) | Unbounded RSA attribute length allocation | Medium |
| [056](056-unbounded-ed25519-attribute-length-allocation.md) | Unbounded Ed25519 attribute length allocation | Medium |
| [076](076-unpopulated-ec-order-bypasses-subgroup-check.md) | Unpopulated EC order bypasses subgroup check | High |
| [107](107-system-rhosts-negative-entries-do-not-stop-later-user-file-a.md) | System rhosts negative entries do not stop later user-file acceptance | High |
| [108](108-compressed-ssh-packet-inflates-without-size-limit.md) | Compressed SSH packet inflates without size limit | High |
| [143](143-unbounded-pre-identification-banner-loop.md) | Unbounded pre-identification banner loop | Medium |
| [197](197-shake256-xof-skips-first-output-block.md) | SHAKE256 XOF skips first output block | Medium |

### syslogd

| # | Finding | Severity |
|---|---------|----------|
| [015](015-tls-listener-reverts-to-plaintext-after-accept-deferral.md) | TLS listener reverts to plaintext after accept deferral | High |

### talk

| # | Finding | Severity |
|---|---------|----------|
| [234](234-udp-control-reply-source-is-not-authenticated.md) | UDP control reply source is not authenticated | Medium |
| [235](235-unexpected-host-accepted-for-talk-session.md) | Unexpected host accepted for talk session | Medium |

### tftp / tftp-proxy

| # | Finding | Severity |
|---|---------|----------|
| [117](117-unauthenticated-tftp-requests-create-unbounded-proxy-state.md) | Unauthenticated TFTP requests create unbounded proxy state | Medium |
| [236](236-unterminated-oack-value-reaches-strlen.md) | Unterminated OACK value reaches strlen | Medium |

### tic

| # | Finding | Severity |
|---|---------|----------|
| [271](271-aix-acs-chars-stack-off-by-one.md) | AIX acs_chars stack off-by-one | Medium |

### traceroute

| # | Finding | Severity |
|---|---------|----------|
| [180](180-verbose-ipv6-packet-dump-overreads-reply-buffer.md) | Verbose IPv6 packet dump overreads reply buffer | Medium |
| [181](181-asn-txt-parser-scans-past-dns-rdata.md) | ASN TXT parser scans past DNS RDATA | Medium |
| [348](348-short-ipv4-icmp-error-reads-embedded-header-out-of-bounds.md) | Short IPv4 ICMP error reads embedded header out of bounds | Medium |

### ul

| # | Finding | Severity |
|---|---------|----------|
| [287](287-tab-expansion-writes-past-line-buffer.md) | Tab expansion writes past line buffer | Medium |

### unwind

| # | Finding | Severity |
|---|---------|----------|
| [001](001-short-transfer-rdata-underflows-decompression-bounds.md) | Short transfer RDATA underflows decompression bounds | High |
| [002](002-doq-ipv6-local-address-reconstruction-overflows-address-fiel.md) | DoQ IPv6 local address reconstruction overflows address field | High |
| [157](157-compressed-dname-lowercasing-reads-past-packet-end.md) | Compressed dname lowercasing reads past packet end | Medium |
| [158](158-compressed-dname-comparison-reads-past-packet-end.md) | Compressed dname comparison reads past packet end | Medium |
| [159](159-dnssec-failures-fall-back-to-non-validating-asr-after-networ.md) | DNSSEC BOGUS responses fall back to non-validating ASR | High |
| [182](182-resolver-info-messages-overflow-fixed-status-array.md) | Resolver info messages overflow fixed status array | Medium |
| [183](183-short-resolver-info-message-overreads-imsg-payload.md) | Short resolver info message overreads imsg payload | Medium |
| [184](184-autoconf-message-string-read-lacks-payload-bounds.md) | Autoconf message string read lacks payload bounds | Medium |
| [225](225-keyword-token-uses-data-limit-for-fixed-heap-buffer.md) | Keyword token uses data limit for fixed heap buffer | High |
| [226](226-data-token-parsing-ignores-caller-buffer-limit.md) | Data token parsing ignores caller buffer limit | High |

### user (usermod / useradd)

| # | Finding | Severity |
|---|---------|----------|
| [063](063-account-lock-omits-shell-marker-for-long-shells.md) | Account lock omits shell marker for long shells | High |

### vmd

| # | Finding | Severity |
|---|---------|----------|
| [022](022-child-instance-uid-inherits-gid.md) | Child instance UID inherits GID | Medium |
| [048](048-invalid-virtqueue-gpa-aborts-vm-process.md) | Invalid virtqueue GPA aborts VM process | Medium |
| [049](049-unchecked-virtqueue-ring-offsets-escape-mapped-vring.md) | Unchecked virtqueue ring offsets escape mapped vring | High |
| [050](050-oversized-entropy-descriptor-aborts-vm-process.md) | Oversized entropy descriptor aborts VM process | Medium |
| [152](152-unbounded-wait-notifications-exhaust-control-memory.md) | Unbounded wait notifications exhaust control memory | Medium |
| [218](218-unchecked-elf64-section-name-offset.md) | Unchecked ELF64 section name offset | Medium |
| [219](219-unchecked-elf32-section-name-table-index.md) | Unchecked ELF32 section-name table index | Medium |
| [265](265-notify-queue-bounds-check-allows-one-past-queue-access.md) | Notify queue bounds check allows one-past-queue access | High |
| [266](266-avail-ring-descriptor-index-is-not-bounds-checked.md) | Avail ring descriptor index is not bounds checked | High |
| [267](267-guest-notify-index-escapes-virtqueue-array.md) | Guest notify index escapes virtqueue array | High |
| [268](268-zero-length-response-descriptor-hangs-read-10-processing.md) | Zero-length response descriptor hangs READ_10 processing | Medium |
| [302](302-dhcp-option-loop-reads-past-packet-buffer.md) | DHCP option loop reads past packet buffer | Medium |
| [303](303-guest-pit-period-can-become-zero-timeout-host-event-loop.md) | Guest PIT period can become zero-timeout host event loop | High |
| [304](304-guest-rtc-rate-zero-triggers-negative-shift.md) | Guest RTC rate zero triggers negative shift | Medium |
| [305](305-short-backing-read-writes-uninitialized-heap-into-guest-disk.md) | Short backing read writes uninitialized heap into guest disk | High |
| [346](346-fw-cfg-file-directory-leaks-per-request.md) | FW_CFG file directory leaks per request | High |

### watch

| # | Finding | Severity |
|---|---------|----------|
| [210](210-nul-output-stalls-parser-loop.md) | NUL output stalls parser loop | Medium |

### ypbind

| # | Finding | Severity |
|---|---------|----------|
| [069](069-domain-slash-check-scans-pointer-bytes.md) | Domain slash check scans pointer bytes | High |

### ypldap

| # | Finding | Severity |
|---|---------|----------|
| [100](100-oversized-client-imsg-overwrites-stack-request.md) | Oversized client imsg overwrites stack request | High |
| [186](186-malformed-controls-dereference-missing-child.md) | Malformed controls dereference missing child | Medium |
| [187](187-page-control-parser-dereferences-absent-value.md) | Page control parser dereferences absent value | Medium |
| [188](188-invalid-page-control-ber-dereferences-null-parse-tree.md) | Invalid page control BER dereferences null parse tree | Medium |

### ypserv

| # | Finding | Severity |
|---|---------|----------|
| [255](255-malformed-acl-netmask-installs-allow-all.md) | Malformed ACL netmask installs allow-all | High |
| [256](256-malformed-securenet-entry-precedes-deny-all.md) | Malformed securenet entry precedes deny-all | High |
| [257](257-dot-dot-escapes-yp-map-root.md) | dot-dot escapes YP map root | High |
| [323](323-unchecked-match-value-allocation.md) | Unchecked MATCH value allocation | Medium |
| [324](324-unchecked-next-key-allocation.md) | Unchecked NEXT key allocation | Medium |
| [325](325-unknown-rpc-procedure-terminates-service.md) | Unknown RPC procedure terminates service | Medium |
| [326](326-malformed-rpc-arguments-terminate-service.md) | Malformed RPC arguments terminate service | Medium |
| [327](327-ypproc-xfr-ignores-host-acl-before-spawning-helper.md) | YPPROC_XFR ignores host ACL before spawning helper | Medium |

### zic

| # | Finding | Severity |
|---|---------|----------|
| [118](118-zone-name-escapes-output-directory.md) | Zone name escapes output directory | High |
| [119](119-link-target-escapes-output-directory.md) | Link target escapes output directory | High |
