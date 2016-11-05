// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_SSL_PLATFORM_KEY_UTIL_H_
#define NET_SSL_SSL_PLATFORM_KEY_UTIL_H_

#include <stddef.h>

#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/ssl/ssl_private_key.h"

namespace base {
class SingleThreadTaskRunner;
}

namespace net {

class X509Certificate;

// Returns a task runner to serialize all private key operations on a single
// background thread to avoid problems with buggy smartcards. Its underlying
// Thread is non-joinable and as such provides
// TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN semantics.
scoped_refptr<base::SingleThreadTaskRunner> GetSSLPlatformKeyTaskRunner();

// Determines the key type and maximum signature length of |certificate|'s
// public key.
NET_EXPORT_PRIVATE bool GetClientCertInfo(const X509Certificate* certificate,
                                          SSLPrivateKey::Type* out_type,
                                          size_t* out_max_length);

}  // namespace net

#endif  // NET_SSL_SSL_PLATFORM_KEY_UTIL_H_
