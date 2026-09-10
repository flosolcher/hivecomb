**Subject:** False-positive spam detection on `hivecomb-win32-x64-msvc`

I am publishing a napi-rs native Node.js addon. napi-rs splits a native addon into one
root package plus one package per platform, holding the prebuilt binary; the names are
generated from the root package name and the Rust target triple, and the root declares
them as `optionalDependencies`.

Five platform packages were published from the same account, with the same granular
access token, in the same CI run within about 90 seconds. Four succeeded:

- `hivecomb-linux-x64-gnu`      0.1.0  (published)
- `hivecomb-linux-arm64-gnu`    0.1.0  (published)
- `hivecomb-darwin-x64`         0.1.0  (published)
- `hivecomb-darwin-arm64`       0.1.0  (published)

The fifth is refused:

- `hivecomb-win32-x64-msvc`     0.1.0

```
npm error code E403
npm error 403 403 Forbidden - PUT https://registry.npmjs.org/hivecomb-win32-x64-msvc
  - Package name triggered spam detection; if you believe this is in error,
    please contact support at https://npmjs.com/support
```

Retried four times over 35 hours — immediately, after 74 minutes, after 18 hours and
again the next day — refused identically each time, so it is not rate limiting and it
is not clearing on its own.

Because napi-rs stops at the first failed platform package, the root package
`hivecomb` has never been published either. `npm i hivecomb` currently finds nothing,
while four packages that nobody installs directly are live.

Three explanations were checked and none of them fit:

- **Not the binary.** The four packages that published carry equally unsigned
  binaries — the Linux `.so` and macOS `.dylib` are not code-signed or notarised
  either, and they were accepted in the same run. The error names the package
  *name*, not the contents.
- **Not a name collision.** A registry search for `hivecomb` returns only the four
  packages above. Nothing resembling `hivecomb-win32-x64-msvc` exists.
- **Not the unscoped `*-win32-x64-msvc` shape.** Of 249 packages matching that
  suffix, 37 are unscoped — roughly the same proportion as for `*-linux-x64-gnu`
  (39 of 239) and `*-darwin-arm64` (34 of 250), both of which this account
  published without incident.

Could the block on `hivecomb-win32-x64-msvc` be lifted? The four sibling packages
published without incident and follow the same naming pattern, which suggests a false
positive rather than anything about the account or the content.

Source, for reference: https://github.com/flosolcher/hivecomb
The same release is published on crates.io and PyPI as hivecomb 0.1.0.
