# JSONP Callback Parameter Injects JavaScript

## Classification

Injection, medium severity. Confidence: certain.

## Affected Locations

`src/proxy/requestsession.cpp:535`

## Summary

JSONP handling accepted an attacker-controlled `callback` query parameter, percent-decoded it, and concatenated it directly into an `application/javascript` response without validating that it was a safe JavaScript callback name. A callback such as `alert(1)//` caused the emitted response to begin with executable attacker-controlled JavaScript.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- A route enables `autoCrossOrigin`.
- JSONP handling is enabled by the route configuration.
- A remote client can request the JSONP-enabled route and supply the callback query parameter.

## Proof

`RequestSession::start()` applies JSONP when `autoCrossOrigin` is enabled and reaches `tryApplyJsonp()`.

`tryApplyJsonp()` reads the callback query item, percent-decodes it, and previously only rejected empty or malformed percent encoding before assigning it to `jsonpCallback`.

`makeJsonpStart()` then directly built executable JavaScript:

```cpp
QByteArray out = "/**/" + jsonpCallback + "(";
```

`doResponseUpdate()` sent the wrapped response with:

```cpp
Content-Type: application/javascript
```

A callback value such as `alert(1)//` produced a response beginning:

```javascript
/**/alert(1)//(
```

This executes attacker-controlled JavaScript syntax rather than only invoking a constrained callback identifier.

## Why This Is A Real Bug

The callback value crosses directly from remote request input into an executable JavaScript response context. Percent-decoding is not sufficient sanitization for JavaScript syntax. Because the response is served as `application/javascript`, injected characters such as parentheses and comments alter code structure and allow arbitrary script emission on JSONP-enabled routes.

## Fix Requirement

Validate the decoded callback against a strict JavaScript identifier/member-expression allowlist before storing it in `jsonpCallback` or using it in response generation.

## Patch Rationale

The patch adds `validJsonpCallback()` and calls it immediately after the callback value is selected from either the request parameter or configured default callback.

The validator allows only ASCII JavaScript identifier-like segments separated by dots:

- First character of each segment: `A-Z`, `a-z`, `_`, or `$`
- Subsequent characters: `A-Z`, `a-z`, `0-9`, `_`, or `$`
- Dot separators only between non-empty segments
- Empty callbacks, trailing dots, leading dots, and syntax characters such as `(`, `)`, `/`, `;`, `[`, and `]` are rejected

Invalid callbacks now fail with `400 Bad Request` and `Invalid callback parameter.` before any JavaScript response wrapping occurs.

## Residual Risk

None

## Patch

```diff
diff --git a/src/proxy/requestsession.cpp b/src/proxy/requestsession.cpp
index 142653ce..3a6e9d2f 100644
--- a/src/proxy/requestsession.cpp
+++ b/src/proxy/requestsession.cpp
@@ -106,6 +106,29 @@ static bool validMethod(const QString &in) {
     return true;
 }
 
+static bool validJsonpCallback(const QByteArray &in) {
+    if (in.isEmpty())
+        return false;
+
+    bool expectStart = true;
+    for (int n = 0; n < in.size(); ++n) {
+        char c = in[n];
+
+        if (expectStart) {
+            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '$'))
+                return false;
+
+            expectStart = false;
+        } else if (c == '.') {
+            expectStart = true;
+        } else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
+                     (c >= '0' && c <= '9') || c == '_' || c == '$'))
+            return false;
+    }
+
+    return !expectStart;
+}
+
 static QByteArray serializeJsonString(const QString &s) {
     QByteArray tmp = QJsonDocument(QJsonArray::fromVariantList(VariantList() << s))
                          .toJson(QJsonDocument::Compact);
@@ -628,6 +651,14 @@ public:
         } else
             callback = config.defaultCallback;
 
+        if (!validJsonpCallback(callback)) {
+            log_debug("requestsession: id=%s invalid callback parameter, rejecting",
+                      rid.second.data());
+            *ok = false;
+            *errorMessage = "Invalid callback parameter.";
+            return false;
+        }
+
         QString method;
         if (query.hasQueryItem("_method")) {
             method = QString::fromLatin1(
```