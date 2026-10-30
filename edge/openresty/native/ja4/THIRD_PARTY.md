# ngx_http_cdnca_ja4_module: third-party notice

`cdnca_ja4.c` is an independent C implementation of **JA4** (TLS client
fingerprinting) written from the FoxIO specification
[`technical_details/JA4.md`](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
(checked 2026-10-17). No FoxIO source code is copied. The unit test uses the
specification's worked example (`t13d1516h2_8daaf6152771_e5627efa2ab1`) and
its no-signature-algorithm variant (`..._6d807ffa2a79`) as test vectors.

JA4 is licensed by FoxIO under the BSD 3-Clause license (`LICENSE-JA4` in the
FoxIO repository); FoxIO states it has no patent claims and does not plan to
pursue patent coverage for JA4 TLS client fingerprinting. JA4 and JA4+ are
FoxIO trademarks.

**Only JA4 is implemented.** JA4+ methods (JA4S, JA4H, JA4L, JA4LS, JA4X,
JA4SSH, JA4T, JA4TS, JA4D, JA4N and later ones) are patent-pending and
licensed under the FoxIO License 1.1, which does not permit monetization
without an OEM license. Do not add them to this module or to cdnca products
without a separate license decision.

Specification choices: the ALPN marker follows JA4.md (hex of the first and
last byte when either end is not ASCII alphanumeric); FoxIO's Rust tool
instead maps non-ASCII characters to `9`. Both agree for every ALPN value in
practical use (`h2`, `http/1.1`, `h3`). QUIC ClientHellos are not
fingerprinted (HTTP/3 requests see an empty `$cdnca_ja4`).

```
THIS LICENSE IS FOR JA4 ONLY (TLS CLIENT FINGERPRINTING) AND NOT FOR THE REST OF JA4+ (JA4PLUS). THE JA4+ LICENSE IS HERE: https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE
THE JA4+ LICENSE FAQ IS HERE: https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md

Copyright (c) 2026 FoxIO
All rights reserved.
Software: JA4 (TLS client fingerprinting)

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

* Neither the name of FoxIO nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
