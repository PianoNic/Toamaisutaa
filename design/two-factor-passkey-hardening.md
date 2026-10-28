# Two-factor and passkey hardening (#399)

Seven smaller items, all re-verified against the code before changing it; all seven held.

1. **`RequiredForAll` enforced nothing.** It wrote `toa_2fa_required` and nothing read it. A result
   handler now answers such a token 403 `two_factor_enrolment_required` everywhere except the
   enrolment endpoints (TOTP status, begin, confirm; passkey list and registration), which carry an
   `AllowsPendingTwoFactorEnrolment` marker. It is a result handler, like the admin one, because an
   endpoint naming its own policy skips the fallback, and it writes the 403 itself rather than
   `Forbid`, whose `OnForbidden` log would explain it as a missing role.
2. **Lockout off with two-factor on** left only the per-address rate limit on code guessing. Startup
   refuses it. The rate-limit test that switched lockout off to isolate the limiter now raises the
   threshold out of reach instead.
3. **The passkey counter** was written unconditionally, so two assertions verified at once against
   the same stored value could land in either order and move it back. `ExecuteUpdate` now keeps the
   larger of the two.
4. **The TOTP ciphertext was not bound to its user.** New and rewrapped secrets pass the user id as
   AES-GCM associated data and mark the key version with `:u`. Unmarked rows still decrypt and are
   rewritten bound on their next use; stripping the mark to pass a bound row off as old fails, since
   the tag covers the id. A swapped row is refused with a plain log line rather than a 500. A test
   pins the enrolment's own binding, since the first mutation run showed the rewrap-on-read backstop
   hid it; removing both reddens the copied-row test.
5. **Disabling two-factor or regenerating codes took only a code.** Both now take the current
   password too, or a recent sign-in for an account with none. `ITwoFactorService` gained a required
   `TwoFactorEnrolmentProof` parameter on both, so a caller has to decide what it proves. Breaking.
6. **Removing a passkey took only the password, even with TOTP.** It now takes a code there, the same
   rule #394 set for registering.
7. **Anonymous `/assertion/begin` writes a row per call and cleanup was opt-in.** Startup refuses
   passkeys without `AddToamaisutaaTokenCleanup()`.

Ten mutations; each reddens its own test, item 4's as described.
