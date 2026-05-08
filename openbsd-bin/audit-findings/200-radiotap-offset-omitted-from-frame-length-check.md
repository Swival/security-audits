# Radiotap Offset Omitted From Frame Length Check

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`usr.sbin/hostapd/apme.c:325`

## Summary

`hostapd_apme_frame()` accepts radiotap-captured packets after `hostapd_apme_offset()` returns a nonzero radiotap header length, but its short-frame check validates the total captured length instead of the remaining 802.11 frame length. A captured packet can therefore contain a valid radiotap header plus fewer than `sizeof(struct ieee80211_frame)` bytes of 802.11 data, causing later reads through `wh` to access beyond the captured packet buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `hostapd` captures attacker-controlled wireless frames.
- The AP monitor path is configured with `DLT_IEEE802_11_RADIO`.
- An unauthenticated wireless transmitter can cause short 802.11 frames with radiotap headers to be captured.

## Proof

`hostapd_apme_input()` reads BPF data and passes `bp + hdrlen` with `caplen` to `hostapd_apme_frame()`.

For radiotap captures, `hostapd_apme_offset()` parses `rh->it_len` and returns `rh_len` whenever the packet length is greater than the radiotap header length. It does not require that a complete 802.11 header follows the radiotap header.

`hostapd_apme_frame()` then computes:

```c
wh = (struct ieee80211_frame *)(buf + offset);
```

but originally checked only:

```c
if (len < sizeof(struct ieee80211_frame))
	return;
```

This compares the complete captured packet length, including the radiotap header, against the 802.11 header size.

A packet such as `rh_len = 64` and `caplen = 65` or `66` satisfies `len > rh_len` and `len >= sizeof(struct ieee80211_frame)`, while leaving only 1 or 2 captured bytes after `buf + offset`. Later accesses to `wh->i_fc`, `wh->i_addr2`, `wh->i_addr3`, and `wh->i_addr1` can read beyond the captured packet.

## Why This Is A Real Bug

The pointer `wh` is based on `buf + offset`, so all dereferences of `wh` require at least `sizeof(struct ieee80211_frame)` bytes after `offset`, not merely within the total packet. In the radiotap case, `offset` is attacker-influenced through the captured radiotap length. Because the old check did not subtract `offset`, malformed short captures can pass validation and drive out-of-bounds reads in the unprivileged `hostapd` child, producing an attacker-controlled denial-of-service condition.

## Fix Requirement

Validate that `len - offset >= sizeof(struct ieee80211_frame)` before constructing or dereferencing `wh`.

## Patch Rationale

The patch changes the short-frame check to validate the number of bytes remaining after the link-layer offset:

```c
if (len - offset < sizeof(struct ieee80211_frame))
	return;
```

It also moves assignment of `wh` until after the bounds check. This ensures `wh` is only formed when a complete 802.11 header is present after the radiotap header.

`hostapd_apme_offset()` already rejects negative offsets, unsupported DLTs, invalid radiotap versions, radiotap headers shorter than the fixed header, and packets where `len <= rh_len`, so `len - offset` is safe for the accepted path.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/hostapd/apme.c b/usr.sbin/hostapd/apme.c
index d478eac..d8df3a7 100644
--- a/usr.sbin/hostapd/apme.c
+++ b/usr.sbin/hostapd/apme.c
@@ -348,11 +348,11 @@ hostapd_apme_frame(struct hostapd_apme *apme, u_int8_t *buf, u_int len)
 
 	if ((offset = hostapd_apme_offset(apme, buf, len)) < 0)
 		return;
-	wh = (struct ieee80211_frame *)(buf + offset);
 
 	/* Ignore short frames or fragments */
-	if (len < sizeof(struct ieee80211_frame))
+	if (len - offset < sizeof(struct ieee80211_frame))
 		return;
+	wh = (struct ieee80211_frame *)(buf + offset);
 
 	/* Handle received frames */
 	if ((hostapd_handle_input(apme, buf, len) ==
```