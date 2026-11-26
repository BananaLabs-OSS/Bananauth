package main

import (
	"fmt"
	"html"
	"strings"
)

const sessionsVerificationSubject = "Your Sessions verification code"

// sessionsVerificationHTML uses the Sessions transactional email shell for
// sign-in codes. The original plain-text part is retained by the sender.
func sessionsVerificationHTML(subject, message string) string {
	if subject != sessionsVerificationSubject {
		return ""
	}
	var body strings.Builder
	fmt.Fprintf(&body, `<h1 style="margin:0 0 8px;font-family:'Plus Jakarta Sans',system-ui,-apple-system,sans-serif;font-size:26px;font-weight:700;color:#EAEEF6;letter-spacing:-.4px;line-height:1.2;">%s</h1>`, html.EscapeString(subject))
	for _, line := range strings.Split(message, "\n") {
		if line != "" {
			fmt.Fprintf(&body, `<p style="margin:0 0 16px;font-family:'Plus Jakarta Sans',system-ui,-apple-system,sans-serif;font-size:15px;color:#B7C0D0;line-height:1.55;">%s</p>`, html.EscapeString(line))
		}
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" style="height:100%%;margin:0;">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><meta name="color-scheme" content="dark"><meta name="supported-color-schemes" content="dark"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet"><style>@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');:root{color-scheme:dark;supported-color-schemes:dark;}</style></head>
<body style="margin:0;padding:0;height:100%%;background:#0E1119;font-family:'Plus Jakarta Sans',system-ui,-apple-system,sans-serif;color:#B7C0D0;-webkit-font-smoothing:antialiased;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#0E1119;height:100%%;min-height:100vh;">
  <tr><td align="center" style="padding:48px 16px 0;vertical-align:top;">
    <table role="presentation" width="540" cellpadding="0" cellspacing="0" style="max-width:540px;width:100%%;">
      <tr><td style="padding-bottom:22px;">
        <span style="font-family:'Plus Jakarta Sans',system-ui,-apple-system,sans-serif;font-size:18px;font-weight:700;color:#EAEEF6;letter-spacing:-.3px;">Sessions</span>
      </td></tr>
      <tr><td style="background:#161B26;border:1px solid #232B3D;border-radius:16px;padding:32px 32px 28px;">
        %s
      </td></tr>
    </table>
  </td></tr>
  <tr><td align="center" style="padding:20px 16px 36px;vertical-align:bottom;">
    <p style="margin:0;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:11px;color:#5A6478;letter-spacing:.04em;">sessions.gg &middot; MonkeyLabs LLC</p>
  </td></tr>
</table>
</body>
</html>`, body.String())
}
