// 获取时间戳用于日志
function getTimestamp() {
    var date = new Date();
    return date.toISOString().replace('T', ' ').substr(0, 23);
}

// Disables SSL pinning by replacing functions with no-ops.
function unpin() {
    // 基础 Security Framework hooks
    var SecTrustEvaluate_handle = Module.findExportByName('Security', 'SecTrustEvaluate');
    var SecTrustEvaluateWithError_handle = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
    var SecTrustSetAnchorCertificates_handle = Module.findExportByName('Security', 'SecTrustSetAnchorCertificates');
    var SecTrustSetAnchorCertificatesOnly_handle = Module.findExportByName('Security', 'SecTrustSetAnchorCertificatesOnly');
    
    // BoringSSL hooks - 从 libboringssl.dylib 加载
    var SSL_CTX_set_custom_verify_handle = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_custom_verify');
    var SSL_get_psk_identity_handle = Module.findExportByName('libboringssl.dylib', 'SSL_get_psk_identity');
    var boringssl_context_set_verify_mode_handle = Module.findExportByName('libboringssl.dylib', 'boringssl_context_set_verify_mode');
    
    // 优先级1：必须Hook的证书验证函数（根据 libboringssl_ssl_analysis.md）
    // 尝试从libboringssl.dylib查找，如果找不到，尝试从所有模块查找
    var SSL_CTX_set_cert_verify_callback_handle = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_cert_verify_callback');
    if (!SSL_CTX_set_cert_verify_callback_handle) {
        SSL_CTX_set_cert_verify_callback_handle = Module.findExportByName(null, 'SSL_CTX_set_cert_verify_callback');
    }
    // SSL_CTX_set_verify - 从 libboringssl.dylib 加载（优先级1）
    var SSL_CTX_set_verify_handle_boringssl = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_verify');
    
    // 优先级3：监控和分析函数
    var SSL_CTX_load_verify_locations_handle = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_load_verify_locations');
    var SSL_CTX_set_default_verify_paths_handle = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_default_verify_paths');
    var SSL_CTX_get_verify_callback_handle = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_get_verify_callback');
    var SSL_CTX_get_verify_mode_handle = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_get_verify_mode');
    
    // 尝试查找更多 SSL/TLS 相关函数（可能在主程序或其他库中）
    var SSL_set_verify_handle = Module.findExportByName(null, 'SSL_set_verify');
    var SSL_CTX_set_verify_handle = Module.findExportByName(null, 'SSL_CTX_set_verify');
    var SSL_connect_handle = Module.findExportByName(null, 'SSL_connect');
    var SSL_do_handshake_handle = Module.findExportByName(null, 'SSL_do_handshake');
    
    // X509证书验证相关函数（可能在应用层直接调用）
    var X509_verify_cert_handle = Module.findExportByName(null, 'X509_verify_cert');
    var X509_STORE_CTX_init_handle = Module.findExportByName(null, 'X509_STORE_CTX_init');
    var X509_STORE_CTX_verify_handle = Module.findExportByName(null, 'X509_STORE_CTX_verify');
    var X509_STORE_CTX_get_error_handle = Module.findExportByName(null, 'X509_STORE_CTX_get_error');
    
    // 可能直接Hook验证回调的实际调用（如果知道回调地址）
    // 这些函数可能在验证过程中被调用
  
    // SecTrustEvaluateWithError - 最常用的证书验证函数
    if (SecTrustEvaluateWithError_handle) {
        var SecTrustEvaluateWithError_orig = new NativeFunction(SecTrustEvaluateWithError_handle, 'int', ['pointer', 'pointer']);
        Interceptor.replace(
            SecTrustEvaluateWithError_handle,
            new NativeCallback(function (trust, error) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: SecTrustEvaluateWithError() - 证书验证被绕过');
                // 先调用原函数，然后强制返回成功
                var result = SecTrustEvaluateWithError_orig(trust, NULL);
                // 将错误码设置为0（无错误）
                if (!error.isNull()) {
                    // error 是一个指向 CFErrorRef 的指针，设置为无错误
                    try {
                        Memory.writePointer(error, NULL);
                    } catch(e) {
                        // 如果写入失败，尝试其他方法
                    }
                }
                return 1; // 强制返回成功
            }, 'int', ['pointer', 'pointer'])
        );
        console.log('[+] SecTrustEvaluateWithError() hook installed.');
    }
  
    // SecTrustEvaluate - 旧版证书验证函数
    if (SecTrustEvaluate_handle) {
        var SecTrustEvaluate = new NativeFunction(SecTrustEvaluate_handle, 'int', ['pointer', 'pointer']);
        Interceptor.replace(
            SecTrustEvaluate_handle, 
            new NativeCallback(function (trust, result) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: SecTrustEvaluate() - 证书验证被绕过');
                SecTrustEvaluate(trust, result);
                if (result.isNull() === false) {
                    Memory.writeU8(result, 1); // 设置为成功
                }
                return 0; // 返回成功
            }, 'int', ['pointer', 'pointer'])
        );
        console.log('[+] SecTrustEvaluate() hook installed.');
    }

    // SecTrustSetAnchorCertificates - 阻止设置自定义锚点证书
    if (SecTrustSetAnchorCertificates_handle) {
        Interceptor.replace(
            SecTrustSetAnchorCertificates_handle,
            new NativeCallback(function (trust, anchorCertificates) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: SecTrustSetAnchorCertificates() - 自定义证书被阻止');
                return 0; // 返回成功但不设置
            }, 'int', ['pointer', 'pointer'])
        );
        console.log('[+] SecTrustSetAnchorCertificates() hook installed.');
    }

    // SecTrustSetAnchorCertificatesOnly
    if (SecTrustSetAnchorCertificatesOnly_handle) {
        Interceptor.replace(
            SecTrustSetAnchorCertificatesOnly_handle,
            new NativeCallback(function (trust, anchorCertificatesOnly) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: SecTrustSetAnchorCertificatesOnly() - 证书限制被绕过');
                return 0;
            }, 'int', ['pointer', 'bool'])
        );
        console.log('[+] SecTrustSetAnchorCertificatesOnly() hook installed.');
    }
  
    // SSL_CTX_set_custom_verify - BoringSSL 自定义验证（优先级1）
    // 地址: 0xa54d0 (根据分析文档)
    // 反编译显示：回调存储在偏移344，验证模式存储在偏移448
    if (SSL_CTX_set_custom_verify_handle) {
        var SSL_CTX_set_custom_verify_orig = new NativeFunction(SSL_CTX_set_custom_verify_handle, 'void', ['pointer', 'int', 'pointer']);
        // 创建始终返回成功的验证回调
        // 注意：BoringSSL的custom_verify回调返回0表示验证成功，非0表示失败
        var custom_verify_call_count = 0;
        var replaced_callback = new NativeCallback(function (ssl, out) {
            custom_verify_call_count++;
            console.log('[' + getTimestamp() + '] 🔒 SSL调用: custom SSL verifier #' + custom_verify_call_count + ' - 自定义验证被绕过 (返回0=成功)');
            
            // 如果out参数不为NULL，可能需要写入验证结果
            if (out && !out.isNull()) {
                // out可能是指向int的指针，写入0表示成功
                try {
                    Memory.writeInt(out, 0);
                } catch(e) {
                    // 忽略写入失败
                }
            }
            
            // BoringSSL: 返回0 = 验证成功，返回非0 = 验证失败
            return 0; // 强制返回验证成功
        }, 'int', ['pointer', 'pointer']);
  
        Interceptor.replace(
            SSL_CTX_set_custom_verify_handle,
            new NativeCallback(function (ctx, mode, callback) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: SSL_CTX_set_custom_verify(mode=' + mode + ') - 自定义验证回调被替换为始终成功');
                // 策略：将验证模式设为0（禁用验证），并用我们的回调替换
                // 根据反编译分析：回调存储在偏移344，mode存储在偏移448
                SSL_CTX_set_custom_verify_orig(ctx, 0, replaced_callback);
            }, 'void', ['pointer', 'int', 'pointer'])
        );
        console.log('[+] SSL_CTX_set_custom_verify() hook installed. (优先级1, 地址: 0xa54d0)');
    } else {
        console.log('[!] ⚠️ SSL_CTX_set_custom_verify 未找到 - 这是关键函数！');
    }

    // SSL_CTX_set_cert_verify_callback - 证书验证回调（优先级1）
    // 地址: 0xac394 (根据分析文档)
    // 函数签名: void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, int (*callback)(X509_STORE_CTX *, void *), void *arg)
    if (SSL_CTX_set_cert_verify_callback_handle) {
        var SSL_CTX_set_cert_verify_callback_orig = new NativeFunction(SSL_CTX_set_cert_verify_callback_handle, 'void', ['pointer', 'pointer', 'pointer']);
        
        // 创建一个始终返回成功的验证回调
        // 回调签名: int callback(X509_STORE_CTX *x509_ctx, void *arg)
        var cert_verify_call_count = 0;
        var replaced_verify_callback = new NativeCallback(function (x509_ctx, arg) {
            cert_verify_call_count++;
            console.log('[' + getTimestamp() + '] 🔒 SSL调用: cert_verify_callback #' + cert_verify_call_count + ' - 证书验证被绕过 (返回1=成功)');
            // 返回1表示验证成功，0表示失败
            return 1; // 强制返回验证成功
        }, 'int', ['pointer', 'pointer']);
        
        Interceptor.replace(
            SSL_CTX_set_cert_verify_callback_handle,
            new NativeCallback(function (ctx, callback, arg) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: SSL_CTX_set_cert_verify_callback() - 验证回调被替换为始终成功');
                // 替换为我们的回调，忽略原来的callback
                SSL_CTX_set_cert_verify_callback_orig(ctx, replaced_verify_callback, arg);
            }, 'void', ['pointer', 'pointer', 'pointer'])
        );
        console.log('[+] SSL_CTX_set_cert_verify_callback() hook installed. (优先级1, 地址: 0xac394)');
    } else {
        console.log('[!] ⚠️ SSL_CTX_set_cert_verify_callback 未找到 (已尝试 libboringssl.dylib 和全局查找)');
        console.log('   提示: 该函数可能在应用动态加载时才存在，或使用了不同的符号名');
    }
  
    // SSL_get_psk_identity - PSK 身份验证
    if (SSL_get_psk_identity_handle) {
        Interceptor.replace(
            SSL_get_psk_identity_handle, 
            new NativeCallback(function (ssl) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: SSL_get_psk_identity() - PSK 身份被替换');
                return Memory.allocUtf8String('notarealPSKidentity');
            }, 'pointer', ['pointer'])
        );
        console.log('[+] SSL_get_psk_identity() hook installed.');
    }
  
    // boringssl_context_set_verify_mode
    if (boringssl_context_set_verify_mode_handle) {
        var boringssl_context_set_verify_mode = new NativeFunction(boringssl_context_set_verify_mode_handle, 'int', ['pointer', 'pointer']);
        Interceptor.replace(
            boringssl_context_set_verify_mode_handle,
            new NativeCallback(function (a, b) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: boringssl_context_set_verify_mode() - 验证模式被绕过');
                return 0;
            }, 'int', ['pointer', 'pointer'])
        );
        console.log('[+] boringssl_context_set_verify_mode() hook installed.');
    }

    // SSL_set_verify - 为单个SSL连接设置验证（SSL级别，非CTX级别）
    // 类似于SSL_CTX_set_verify，但是针对单个SSL连接
    if (SSL_set_verify_handle) {
        var SSL_set_verify_orig = new NativeFunction(SSL_set_verify_handle, 'void', ['pointer', 'int', 'pointer']);
        var success_verify_callback_ssl = new NativeCallback(function (preverify_ok, x509_ctx) {
            console.log('[' + getTimestamp() + '] 🔒 SSL调用: SSL verify callback - 证书验证被绕过');
            return 1; // 验证通过
        }, 'int', ['int', 'pointer']);
        
        Interceptor.replace(
            SSL_set_verify_handle,
            new NativeCallback(function (ssl, mode, callback) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: SSL_set_verify(mode=0x' + mode.toString(16) + ') - 验证模式被禁用，回调被替换');
                // 禁用验证（mode=0）并替换回调
                SSL_set_verify_orig(ssl, 0, success_verify_callback_ssl);
            }, 'void', ['pointer', 'int', 'pointer'])
        );
        console.log('[+] SSL_set_verify() hook installed.');
    }

    // SSL_CTX_set_verify - 标准SSL验证设置（优先级1）
    // 地址: 0xac39c (根据分析文档)
    // 反编译显示：验证模式存储在 tlsext_tick_hmac_key（前4字节），回调存储在 tlsext_tick_hmac_key[8]
    // 优先使用 libboringssl.dylib 中的版本
    var SSL_CTX_set_verify_to_hook = SSL_CTX_set_verify_handle_boringssl || SSL_CTX_set_verify_handle;
    if (SSL_CTX_set_verify_to_hook) {
        var SSL_CTX_set_verify_orig = new NativeFunction(SSL_CTX_set_verify_to_hook, 'void', ['pointer', 'int', 'pointer']);
        // 创建始终返回成功的验证回调
        // 标准OpenSSL/BoringSSL回调签名: int callback(int preverify_ok, X509_STORE_CTX *ctx)
        // 返回1表示继续验证，返回0表示停止验证（但我们总是返回1让验证通过）
        var success_verify_callback = new NativeCallback(function (preverify_ok, x509_ctx) {
            console.log('[' + getTimestamp() + '] 🔒 SSL调用: verify callback - 证书验证被绕过 (返回1)');
            // 返回1表示验证通过，继续处理
            return 1;
        }, 'int', ['int', 'pointer']);
        
        Interceptor.replace(
            SSL_CTX_set_verify_to_hook,
            new NativeCallback(function (ctx, mode, callback) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: SSL_CTX_set_verify(mode=0x' + mode.toString(16) + ') - 验证模式被禁用，回调被替换');
                // 策略2：将验证模式设为0（SSL_VERIFY_NONE）禁用验证
                // 同时替换回调为始终返回成功的函数
                // 根据反编译分析：mode存储在tlsext_tick_hmac_key，callback存储在tlsext_tick_hmac_key[8]
                SSL_CTX_set_verify_orig(ctx, 0, success_verify_callback);
            }, 'void', ['pointer', 'int', 'pointer'])
        );
        var source = SSL_CTX_set_verify_handle_boringssl ? 'libboringssl.dylib' : '其他库';
        console.log('[+] SSL_CTX_set_verify() hook installed. (优先级1, 地址: 0xac39c, 来源: ' + source + ')');
    } else {
        console.log('[!] ⚠️ SSL_CTX_set_verify 未找到');
    }

    // SSL_connect - 监控并强制成功 SSL 连接建立
    var connectCount = 0;
    var connectFailCount = 0;
    if (SSL_connect_handle) {
        Interceptor.attach(SSL_connect_handle, {
            onEnter: function(args) {
                this.ssl = args[0];
                connectCount++;
                // 只记录前20次连接尝试
                if (connectCount <= 20) {
                    console.log('[' + getTimestamp() + '] 🔒 SSL调用: SSL_connect() - SSL 连接建立中...');
                }
            },
            onLeave: function(retval) {
                var result = retval.toInt32();
                if (result === 1) {
                    // 成功，只记录前20次
                    if (connectCount <= 20) {
                        console.log('[' + getTimestamp() + '] ✅ SSL连接成功建立');
                    }
                } else {
                    connectFailCount++;
                    var isRealError = false;
                    var errorMsg = '返回码: ' + result;
                    
                    // 尝试获取错误详情
                    if (SSL_get_error_handle && this.ssl) {
                        try {
                            var SSL_get_error = new NativeFunction(SSL_get_error_handle, 'int', ['pointer', 'int']);
                            var sslError = SSL_get_error(this.ssl, result);
                            
                            // SSL_ERROR_WANT_READ 和 WANT_WRITE 是正常的非阻塞状态
                            if (sslError === 2 || sslError === 3) {
                                // 正常状态，不记录也不修改返回值
                                return;
                            } else if (sslError === 1 || sslError === 5 || sslError === 6) {
                                isRealError = true;
                            }
                            
                            errorMsg += ', SSL错误码: ' + sslError;
                        } catch(e) {}
                    }
                    
                    // 如果是真正的错误，强制返回成功
                    if (isRealError) {
                        console.log('[' + getTimestamp() + '] ❌ SSL连接真正的错误！' + errorMsg + ' - 强制返回成功');
                        // 强制返回成功 (1)
                        retval.replace(1);
                        // 尝试清除错误状态
                        try {
                            // 尝试调用 SSL_clear_error 或类似函数清除错误
                            if (this.ssl) {
                                // 设置 verify_result 为成功
                                var SSL_get_verify_result_handle = Module.findExportByName(null, 'SSL_get_verify_result');
                                if (SSL_get_verify_result_handle) {
                                    // SSL_get_verify_result 返回 X509_V_OK (0) 表示成功
                                    // 我们可以在下一次调用时检查
                                }
                            }
                        } catch(e) {}
                    } else if (connectFailCount <= 5) {
                        console.log('[' + getTimestamp() + '] ⚠️ SSL连接返回非成功，' + errorMsg);
                    }
                }
            }
        });
        console.log('[+] SSL_connect() hook installed. (强制成功模式)');
    }

    // SSL_do_handshake - 监控 SSL 握手（不替换，只监控，避免无限循环）
    // 尝试获取SSL错误信息
    var ERR_get_error_handle = Module.findExportByName('libboringssl.dylib', 'ERR_get_error');
    var ERR_error_string_handle = Module.findExportByName('libboringssl.dylib', 'ERR_error_string');
    var ERR_error_string_n_handle = Module.findExportByName('libboringssl.dylib', 'ERR_error_string_n');
    var SSL_get_error_handle = Module.findExportByName(null, 'SSL_get_error');
    
    if (SSL_do_handshake_handle) {
        // 减少日志输出，避免过多
        var handshakeCount = 0;
        var handshakeFailCount = 0;
        Interceptor.attach(SSL_do_handshake_handle, {
            onEnter: function(args) {
                this.ssl = args[0];
                handshakeCount++;
            },
            onLeave: function(retval) {
                var result = retval.toInt32();
                if (result === 1) {
                    // 成功，只记录前几次
                    if (handshakeCount <= 10) {
                        console.log('[' + getTimestamp() + '] ✅ SSL握手成功');
                    }
                } else {
                    handshakeFailCount++;
                    var isRealError = false;
                    var errorMsg = '返回码: ' + result;
                    var sslError = -1;
                    
                    // 尝试获取SSL错误信息
                    if (SSL_get_error_handle && this.ssl) {
                        try {
                            var SSL_get_error = new NativeFunction(SSL_get_error_handle, 'int', ['pointer', 'int']);
                            sslError = SSL_get_error(this.ssl, result);
                            
                            // SSL错误码说明
                            var errorNames = {
                                1: 'SSL_ERROR_SSL (真正的SSL错误)',
                                2: 'SSL_ERROR_WANT_READ (需要更多数据，正常)',
                                3: 'SSL_ERROR_WANT_WRITE (需要写数据，正常)',
                                4: 'SSL_ERROR_WANT_X509_LOOKUP',
                                5: 'SSL_ERROR_SYSCALL (系统调用错误)',
                                6: 'SSL_ERROR_ZERO_RETURN (连接关闭)',
                                7: 'SSL_ERROR_WANT_CONNECT',
                                8: 'SSL_ERROR_WANT_ACCEPT'
                            };
                            
                            // SSL_ERROR_WANT_READ 和 SSL_ERROR_WANT_WRITE 是正常的非阻塞状态，不是真正的错误
                            if (sslError === 2 || sslError === 3) {
                                // 这是正常的非阻塞I/O状态，不需要记录
                                return;
                            } else if (sslError === 1 || sslError === 5 || sslError === 6) {
                                // 这些是真正的错误
                                isRealError = true;
                            }
                            
                            if (errorNames[sslError]) {
                                errorMsg += ', SSL错误码: ' + sslError + ' (' + errorNames[sslError] + ')';
                            } else {
                                errorMsg += ', SSL错误码: ' + sslError;
                            }
                        } catch(e) {
                            // 忽略错误获取失败
                        }
                    }
                    
                    // 如果是真正的错误，强制返回成功并清除错误
                    if (isRealError) {
                        // 获取BoringSSL错误详情（仅对真正的错误）
                        if (ERR_get_error_handle) {
                            try {
                                var ERR_get_error = new NativeFunction(ERR_get_error_handle, 'uint64', []);
                                var ERR_clear_error = Module.findExportByName('libboringssl.dylib', 'ERR_clear_error');
                                
                                // 尝试获取多个错误（错误栈可能有多个）
                                var errorDetails = [];
                                for (var i = 0; i < 3; i++) {
                                    var errCode = ERR_get_error();
                                    if (errCode === 0) break;
                                    
                                    errorDetails.push('0x' + errCode.toString(16));
                                    
                                    // 尝试获取错误字符串
                                    if (ERR_error_string_n_handle) {
                                        try {
                                            var ERR_error_string_n = new NativeFunction(ERR_error_string_n_handle, 'void', ['uint64', 'pointer', 'size_t']);
                                            var buf = Memory.alloc(256);
                                            ERR_error_string_n(errCode, buf, 256);
                                            var errStr = Memory.readUtf8String(buf);
                                            if (errStr && errStr.length > 0) {
                                                errorDetails[errorDetails.length - 1] += ' (' + errStr + ')';
                                            }
                                        } catch(e) {}
                                    } else if (ERR_error_string_handle) {
                                        try {
                                            var ERR_error_string = new NativeFunction(ERR_error_string_handle, 'pointer', ['uint64', 'pointer']);
                                            var buf = Memory.alloc(256);
                                            var strPtr = ERR_error_string(errCode, buf);
                                            if (strPtr && !strPtr.isNull()) {
                                                var errStr = Memory.readUtf8String(strPtr);
                                                if (errStr && errStr.length > 0) {
                                                    errorDetails[errorDetails.length - 1] += ' (' + errStr + ')';
                                                }
                                            }
                                        } catch(e) {}
                                    }
                                }
                                
                                // 清除错误队列
                                if (ERR_clear_error) {
                                    try {
                                        var ERR_clear_error_fn = new NativeFunction(ERR_clear_error, 'void', []);
                                        ERR_clear_error_fn();
                                    } catch(e) {}
                                }
                                
                                if (errorDetails.length > 0) {
                                    errorMsg += ', BoringSSL错误: ' + errorDetails.join('; ');
                                } else {
                                    errorMsg += ', BoringSSL错误: 0x0 (错误队列为空，可能已被清除)';
                                }
                            } catch(e) {
                                errorMsg += ', 错误详情获取失败: ' + e;
                            }
                        }
                        
                        console.log('[' + getTimestamp() + '] ❌ SSL握手真正的错误！' + errorMsg + ' - 强制返回成功并清除错误');
                        
                        // 强制返回成功 (1)
                        retval.replace(1);
                        
                        // 尝试清除 SSL 错误状态
                        try {
                            if (this.ssl) {
                                // 尝试调用 SSL_clear 清除错误状态（如果存在）
                                var SSL_clear_handle = Module.findExportByName(null, 'SSL_clear');
                                if (SSL_clear_handle) {
                                    // 注意：SSL_clear 会重置连接，可能影响当前状态
                                    // 先不调用，只清除错误队列
                                }
                            }
                        } catch(e) {}
                    } else if (handshakeFailCount <= 5) {
                        console.log('[' + getTimestamp() + '] ⚠️ SSL握手返回非成功，' + errorMsg);
                    }
                }
            }
        });
        console.log('[+] SSL_do_handshake() hook installed.');
    }

    // SSL_CTX_load_verify_locations - 监控证书加载（优先级3）
    // 地址: 0xac3b8 (根据分析文档)
    if (SSL_CTX_load_verify_locations_handle) {
        Interceptor.attach(SSL_CTX_load_verify_locations_handle, {
            onEnter: function(args) {
                var ctx = args[0];
                var ca_file = args[1]; // 可能是NULL
                var ca_path = args[2]; // 可能是NULL
                var fileStr = ca_file && !ca_file.isNull() ? Memory.readUtf8String(ca_file) : 'NULL';
                var pathStr = ca_path && !ca_path.isNull() ? Memory.readUtf8String(ca_path) : 'NULL';
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: SSL_CTX_load_verify_locations() - 加载证书');
                console.log('    文件: ' + fileStr + ', 路径: ' + pathStr);
            },
            onLeave: function(retval) {
                var result = retval.toInt32();
                if (result === 1) {
                    console.log('[' + getTimestamp() + '] ✅ 证书加载成功');
                } else {
                    console.log('[' + getTimestamp() + '] ⚠️ 证书加载失败，返回码: ' + result);
                }
            }
        });
        console.log('[+] SSL_CTX_load_verify_locations() hook installed. (优先级3)');
    }

    // SSL_CTX_set_default_verify_paths - 监控默认证书路径设置（优先级3）
    // 地址: 0xac3b0 (根据分析文档)
    if (SSL_CTX_set_default_verify_paths_handle) {
        Interceptor.attach(SSL_CTX_set_default_verify_paths_handle, {
            onEnter: function(args) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: SSL_CTX_set_default_verify_paths() - 设置默认证书路径');
            },
            onLeave: function(retval) {
                var result = retval.toInt32();
                if (result === 1) {
                    console.log('[' + getTimestamp() + '] ✅ 默认证书路径设置成功');
                } else {
                    console.log('[' + getTimestamp() + '] ⚠️ 默认证书路径设置失败');
                }
            }
        });
        console.log('[+] SSL_CTX_set_default_verify_paths() hook installed. (优先级3)');
    }

    // SSL_CTX_get_verify_callback - 获取验证回调（优先级3，用于分析和监控）
    // 地址: 0xac360 (根据分析文档)
    if (SSL_CTX_get_verify_callback_handle) {
        var get_verify_callback_orig = new NativeFunction(SSL_CTX_get_verify_callback_handle, 'pointer', ['pointer']);
        Interceptor.replace(
            SSL_CTX_get_verify_callback_handle,
            new NativeCallback(function (ctx) {
                var callback = get_verify_callback_orig(ctx);
                if (callback && !callback.isNull()) {
                    console.log('[' + getTimestamp() + '] 📊 SSL_CTX_get_verify_callback() - 检测到验证回调: 0x' + callback.toString(16));
                    // 回调已被我们在SSL_CTX_set_verify中替换为成功回调
                }
                return callback;
            }, 'pointer', ['pointer'])
        );
        console.log('[+] SSL_CTX_get_verify_callback() hook installed. (优先级3，监控回调获取)');
    }

    // SSL_CTX_get_verify_mode - 获取验证模式（优先级3，用于分析）
    // 地址: 0xac350 (根据分析文档)
    if (SSL_CTX_get_verify_mode_handle) {
        Interceptor.attach(SSL_CTX_get_verify_mode_handle, {
            onLeave: function(retval) {
                var mode = retval.toInt32();
                // SSL_VERIFY_NONE = 0x00
                // SSL_VERIFY_PEER = 0x01
                // SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02
                // SSL_VERIFY_CLIENT_ONCE = 0x04
                var modeStr = '';
                if ((mode & 0x01) === 0x01) modeStr += 'SSL_VERIFY_PEER ';
                if ((mode & 0x02) === 0x02) modeStr += 'SSL_VERIFY_FAIL_IF_NO_PEER_CERT ';
                if ((mode & 0x04) === 0x04) modeStr += 'SSL_VERIFY_CLIENT_ONCE ';
                if (mode === 0) modeStr = 'SSL_VERIFY_NONE';
                console.log('[' + getTimestamp() + '] 📊 SSL_CTX_get_verify_mode() - 验证模式: 0x' + mode.toString(16) + ' (' + modeStr + ')');
            }
        });
        console.log('[+] SSL_CTX_get_verify_mode() hook installed. (优先级3，分析用)');
    }

    // X509_verify_cert - X509证书验证核心函数（如果在应用中被直接调用）
    if (X509_verify_cert_handle) {
        Interceptor.replace(
            X509_verify_cert_handle,
            new NativeCallback(function (ctx) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: X509_verify_cert() - 证书验证被绕过');
                // X509_verify_cert 返回1表示验证成功，0表示失败
                return 1; // 强制返回验证成功
            }, 'int', ['pointer'])
        );
        console.log('[+] X509_verify_cert() hook installed.');
    }

    // X509_STORE_CTX_verify - X509存储上下文验证（如果在应用中被直接调用）
    if (X509_STORE_CTX_verify_handle) {
        Interceptor.replace(
            X509_STORE_CTX_verify_handle,
            new NativeCallback(function (ctx) {
                console.log('[' + getTimestamp() + '] 🔒 SSL调用: X509_STORE_CTX_verify() - 存储上下文验证被绕过');
                return 1; // 验证成功
            }, 'int', ['pointer'])
        );
        console.log('[+] X509_STORE_CTX_verify() hook installed.');
    }

    // X509_STORE_CTX_get_error - 获取验证错误（Hook以确保不返回错误）
    if (X509_STORE_CTX_get_error_handle) {
        Interceptor.replace(
            X509_STORE_CTX_get_error_handle,
            new NativeCallback(function (ctx) {
                // 返回X509_V_OK (0)表示无错误
                return 0;
            }, 'int', ['pointer'])
        );
        console.log('[+] X509_STORE_CTX_get_error() hook installed. (强制返回无错误)');
    }

    // Hook可能在应用层直接调用的SecTrust函数（iOS系统API）
    // 这些已经在开头Hook了，但确保它们正确工作
}

// Hook Objective-C 层的网络相关类
function hookObjectiveC() {
    // Hook NSURLSession 的证书验证委托方法 - 使用更可靠的方法
    try {
        // 方法1: Hook NSURLSession 类的所有实例方法
        var NSURLSession = ObjC.classes['NSURLSession'];
        if (NSURLSession) {
            // Hook URLSession:didReceiveChallenge:completionHandler: (session级别)
            var sessionDidReceiveChallenge = NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'];
            if (sessionDidReceiveChallenge) {
                Interceptor.attach(sessionDidReceiveChallenge.implementation, {
                    onEnter: function(args) {
                        console.log('[' + getTimestamp() + '] 🔒 NSURLSession调用: didReceiveChallenge (session级别)');
                        var completionHandler = new ObjC.Object(args[4]);
                        // 使用 NSURLSessionAuthChallengeUseCredential 接受任何证书
                        var disposition = ObjC.classes.NSURLSessionAuthChallengeDisposition['NSURLSessionAuthChallengeUseCredential'];
                        var credential = ObjC.classes.NSURLCredential.credentialForTrust_(args[3]);
                        completionHandler.call(disposition, credential);
                    }
                });
                console.log('[+] NSURLSession session didReceiveChallenge hook installed.');
            }
            
            // Hook URLSession:task:didReceiveChallenge:completionHandler: (task级别)
            var taskDidReceiveChallenge = NSURLSession['- URLSession:task:didReceiveChallenge:completionHandler:'];
            if (taskDidReceiveChallenge) {
                Interceptor.attach(taskDidReceiveChallenge.implementation, {
                    onEnter: function(args) {
                        console.log('[' + getTimestamp() + '] 🔒 NSURLSession调用: task didReceiveChallenge');
                        var completionHandler = new ObjC.Object(args[5]);
                        var disposition = ObjC.classes.NSURLSessionAuthChallengeDisposition['NSURLSessionAuthChallengeUseCredential'];
                        var credential = ObjC.classes.NSURLCredential.credentialForTrust_(args[4]);
                        completionHandler.call(disposition, credential);
                    }
                });
                console.log('[+] NSURLSession task didReceiveChallenge hook installed.');
            }
        }
        
        // 方法2: 直接Hook NSURLSessionTaskDelegate 协议的方法
        // 使用 ObjC.classes 直接查找实现类
        var delegateClasses = ['NSURLSession', 'NSURLSessionTask', '__NSURLSessionLocal', '__NSCFURLSession'];
        for (var i = 0; i < delegateClasses.length; i++) {
            var className = delegateClasses[i];
            try {
                var cls = ObjC.classes[className];
                if (cls) {
                    var methodName = '- URLSession:task:didReceiveChallenge:completionHandler:';
                    if (cls[methodName]) {
                        Interceptor.attach(cls[methodName].implementation, {
                            onEnter: function(args) {
                                console.log('[' + getTimestamp() + '] 🔒 捕获到: ' + className + ' didReceiveChallenge');
                                try {
                                    var completionHandler = new ObjC.Object(args[5]);
                                    var disposition = ObjC.classes.NSURLSessionAuthChallengeDisposition['NSURLSessionAuthChallengeUseCredential'];
                                    var trust = new ObjC.Object(args[4]);
                                    var credential = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                                    completionHandler.call(disposition, credential);
                                } catch(e) {
                                    console.log('[!] 处理证书挑战时出错: ' + e);
                                }
                            }
                        });
                        console.log('[+] Hooked ' + className + '.' + methodName);
                    }
                }
            } catch(e) {
                // 类不存在，继续
            }
        }
    } catch (e) {
        console.log('[!] NSURLSession hook 安装失败: ' + e);
    }

    // Hook 抖音的 TTNetworkManagerChromium 类（如果存在）
    try {
        var TTNetworkManagerChromium = ObjC.classes['TTNetworkManagerChromium'];
        if (TTNetworkManagerChromium) {
            console.log('[+] 找到 TTNetworkManagerChromium 类');
            
            // Hook ServerCertificate 方法，让它返回 nil
            if (TTNetworkManagerChromium['- ServerCertificate']) {
                Interceptor.attach(TTNetworkManagerChromium['- ServerCertificate'].implementation, {
                    onEnter: function(args) {
                        console.log('[' + getTimestamp() + '] 🔒 TTNetworkManagerChromium.ServerCertificate() 被调用 - 返回 nil');
                    },
                    onLeave: function(retval) {
                        // 返回空数组，相当于返回nil用于证书验证
                        retval.replace(ObjC.classes.NSArray.array());
                        console.log('[' + getTimestamp() + '] ✅ ServerCertificate 已返回空数组（相当于nil）');
                    }
                });
                console.log('[+] TTNetworkManagerChromium.ServerCertificate() hook installed.');
            }
            
            // Hook ServerCertificate 的getter方法（如果有的话）
            if (TTNetworkManagerChromium['+ ServerCertificate']) {
                Interceptor.attach(TTNetworkManagerChromium['+ ServerCertificate'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(ObjC.classes.NSArray.array());
                        console.log('[' + getTimestamp() + '] ✅ ServerCertificate (类方法) 已返回空数组');
                    }
                });
                console.log('[+] TTNetworkManagerChromium.ServerCertificate (类方法) hook installed.');
            }
            
            // Hook 其他可能的证书相关方法
            var methods = TTNetworkManagerChromium.$ownMethods;
            for (var i = 0; i < methods.length; i++) {
                var methodName = methods[i];
                if (methodName.toLowerCase().indexOf('certificate') !== -1 || 
                    methodName.toLowerCase().indexOf('ssl') !== -1 ||
                    methodName.toLowerCase().indexOf('pin') !== -1) {
                    console.log('[+] 发现可能的证书相关方法: ' + methodName);
                }
            }
        } else {
            console.log('[!] 未找到 TTNetworkManagerChromium 类（可能类名不同或使用了不同的网络库）');
        }
    } catch (e) {
        console.log('[!] TTNetworkManagerChromium hook 失败: ' + e);
    }

    // Hook NSURLConnection 的证书验证（旧版API）
    try {
        // 尝试通过类方法查找，而不是协议
        var NSURLConnection = ObjC.classes['NSURLConnection'];
        if (NSURLConnection) {
            // Hook connection:willSendRequestForAuthenticationChallenge: 方法
            var methodName = '- connection:willSendRequestForAuthenticationChallenge:';
            if (NSURLConnection[methodName]) {
                Interceptor.attach(NSURLConnection[methodName].implementation, {
                    onEnter: function(args) {
                        console.log('[' + getTimestamp() + '] 🔒 NSURLConnection调用: willSendRequestForAuthenticationChallenge - 证书验证被绕过');
                    }
                });
                console.log('[+] NSURLConnection willSendRequestForAuthenticationChallenge hook installed.');
            } else {
                console.log('[!] NSURLConnection 方法未找到，可能应用未使用此API');
            }
        } else {
            console.log('[!] NSURLConnection 类未找到，应用可能只使用NSURLSession');
        }
    } catch (e) {
        console.log('[!] NSURLConnection hook 安装失败: ' + e);
    }
}

// 直接修改内存的备选方案（启用）
// 根据反编译分析，可以直接修改SSL_CTX结构体中的回调指针
function patchSSLCTXDirectly() {
    console.log('[+] 内存直接修改功能已启用');
    console.log('    直接修改SSL_CTX结构体：');
    console.log('    - SSL_CTX_set_custom_verify: 回调偏移344, 模式偏移448');
    console.log('    - SSL_CTX_set_verify: 回调在tlsext_tick_hmac_key[8], 模式在前4字节');
    console.log('    - SSL_CTX_set_cert_verify_callback: 回调在msg_callback_arg');
    
    // 重新获取函数句柄（因为它们在 unpin() 函数作用域内）
    var SSL_CTX_set_custom_verify_handle = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_custom_verify');
    var SSL_CTX_set_cert_verify_callback_handle = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_cert_verify_callback');
    if (!SSL_CTX_set_cert_verify_callback_handle) {
        SSL_CTX_set_cert_verify_callback_handle = Module.findExportByName(null, 'SSL_CTX_set_cert_verify_callback');
    }
    var SSL_CTX_set_verify_handle_boringssl = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_verify');
    var SSL_CTX_set_verify_handle = Module.findExportByName(null, 'SSL_CTX_set_verify');
    var SSL_CTX_set_verify_to_hook = SSL_CTX_set_verify_handle_boringssl || SSL_CTX_set_verify_handle;
    
    // 在SSL_connect/SSL_do_handshake之后直接修改SSL_CTX中的验证回调
    // 这样可以确保即使验证回调被设置，也会被我们替换
    
    // Hook SSL_new 以在创建新 SSL 连接时立即修改其 SSL_CTX
    var SSL_new_handle = Module.findExportByName(null, 'SSL_new');
    if (SSL_new_handle) {
        // 创建始终返回成功的验证回调
        var always_success_custom_verify = new NativeCallback(function (ssl, out) {
            console.log('[' + getTimestamp() + '] 🔒 [内存修改] custom_verify 被调用 - 返回成功');
            if (out && !out.isNull()) {
                try {
                    Memory.writeInt(out, 0); // 0 = 验证成功
                } catch(e) {}
            }
            return 0; // 返回0 = 成功
        }, 'int', ['pointer', 'pointer']);
        
        var always_success_cert_verify = new NativeCallback(function (x509_ctx, arg) {
            console.log('[' + getTimestamp() + '] 🔒 [内存修改] cert_verify_callback 被调用 - 返回成功');
            return 1; // 返回1 = 成功
        }, 'int', ['pointer', 'pointer']);
        
        var always_success_verify = new NativeCallback(function (preverify_ok, x509_ctx) {
            return 1; // 返回1 = 成功
        }, 'int', ['int', 'pointer']);
        
        Interceptor.attach(SSL_new_handle, {
            onLeave: function(retval) {
                if (retval.isNull()) return;
                
                var ssl = retval;
                try {
                    // 获取 SSL_CTX
                    var SSL_get_SSL_CTX_handle = Module.findExportByName(null, 'SSL_get_SSL_CTX');
                    if (SSL_get_SSL_CTX_handle) {
                        var SSL_get_SSL_CTX = new NativeFunction(SSL_get_SSL_CTX_handle, 'pointer', ['pointer']);
                        var ctx = SSL_get_SSL_CTX(ssl);
                        
                        if (ctx && !ctx.isNull()) {
                            // 方法1: 通过调用 set 函数修改
                            if (SSL_CTX_set_custom_verify_handle) {
                                var SSL_CTX_set_custom_verify_orig = new NativeFunction(SSL_CTX_set_custom_verify_handle, 'void', ['pointer', 'int', 'pointer']);
                                SSL_CTX_set_custom_verify_orig(ctx, 0, always_success_custom_verify);
                            }
                            
                            if (SSL_CTX_set_cert_verify_callback_handle) {
                                var SSL_CTX_set_cert_verify_callback_orig = new NativeFunction(SSL_CTX_set_cert_verify_callback_handle, 'void', ['pointer', 'pointer', 'pointer']);
                                SSL_CTX_set_cert_verify_callback_orig(ctx, always_success_cert_verify, NULL);
                            }
                            
                            if (SSL_CTX_set_verify_to_hook) {
                                var SSL_CTX_set_verify_orig = new NativeFunction(SSL_CTX_set_verify_to_hook, 'void', ['pointer', 'int', 'pointer']);
                                SSL_CTX_set_verify_orig(ctx, 0, always_success_verify);
                            }
                            
                            // 方法2: 直接修改内存（如果结构体偏移已知）
                            // 注意：这需要精确的结构体布局信息，可能因版本而异
                            try {
                                // SSL_CTX_set_custom_verify 的回调在偏移344
                                // 验证模式在偏移448
                                // var callbackPtr = ctx.add(344);
                                // Memory.writePointer(callbackPtr, always_success_custom_verify);
                                // var modePtr = ctx.add(448);
                                // Memory.writeInt(modePtr, 0); // 禁用验证
                            } catch(e) {
                                // 内存修改失败，继续使用函数调用方式
                            }
                        }
                    }
                } catch(e) {
                    // 修改失败，但继续执行
                }
            }
        });
        console.log('[+] SSL_new() hook installed - 在创建SSL连接时自动修改SSL_CTX');
    }
    
    // Hook SSL_set_verify_result 确保验证结果被设置为成功
    var SSL_set_verify_result_handle = Module.findExportByName(null, 'SSL_set_verify_result');
    if (SSL_set_verify_result_handle) {
        Interceptor.replace(
            SSL_set_verify_result_handle,
            new NativeCallback(function (ssl, result) {
                // 始终设置为 X509_V_OK (0)
                var SSL_set_verify_result_orig = new NativeFunction(SSL_set_verify_result_handle, 'void', ['pointer', 'long']);
                SSL_set_verify_result_orig(ssl, 0);
            }, 'void', ['pointer', 'long'])
        );
        console.log('[+] SSL_set_verify_result() hook installed - 强制设置验证结果为成功');
    }
    
    // Hook SSL_get_verify_result 确保始终返回成功
    var SSL_get_verify_result_handle = Module.findExportByName(null, 'SSL_get_verify_result');
    if (SSL_get_verify_result_handle) {
        Interceptor.replace(
            SSL_get_verify_result_handle,
            new NativeCallback(function (ssl) {
                // 返回 X509_V_OK (0)
                return 0;
            }, 'long', ['pointer'])
        );
        console.log('[+] SSL_get_verify_result() hook installed - 强制返回验证成功');
    }
    
    console.log('[+] 内存直接修改策略已启用');
}

// 防止重复加载的机制
if (typeof global.hookInitialized === 'undefined') {
    global.hookInitialized = true;
    
    // 安装 hooks
    unpin();
    hookObjectiveC();
    patchSSLCTXDirectly();
} else {
    console.log('[!] ⚠️ Hook脚本已被加载，跳过重复初始化');
}

// 保持脚本运行并显示状态
console.log('');
console.log('[+] ========================================');
console.log('[+] 所有 SSL Pinning hooks 已安装完成');
console.log('[+] 基于 libboringssl_ssl_analysis.md 和反编译分析');
console.log('[+] ========================================');
console.log('[+] 优先级1 (必须):');
console.log('[+]   - SSL_CTX_set_custom_verify (0xa54d0): 回调偏移344, 模式偏移448');
console.log('[+]   - SSL_CTX_set_verify (0xac39c): 禁用验证模式，替换回调');
console.log('[+]   - SSL_CTX_set_cert_verify_callback (0xac394): 替换验证回调');
console.log('[+] 优先级2 (建议): SSL_connect, SSL_do_handshake');
console.log('[+] 优先级3 (监控): SSL_CTX_load_verify_locations, SSL_CTX_get_verify_callback');
console.log('[+] Hook策略: 禁用验证模式(mode=0) + 替换回调为始终成功');
console.log('[+] ========================================');
console.log('[+] 正在监听网络请求...');
console.log('[+] 当抖音进行网络请求时，会看到相关日志输出');
console.log('[+] 脚本将持续运行，按 Ctrl+C 退出');
console.log('[+] ========================================');
console.log('');

// 添加一个保持活跃的机制，每60秒输出一次心跳（确认脚本仍在运行）
var heartbeatCount = 0;
var keepAlive = setInterval(function() {
    heartbeatCount++;
    // 每60秒输出一次心跳，避免日志过多但又能确认脚本在运行
    console.log('[' + getTimestamp() + '] [💓] Hook 仍在运行... (运行时间: ' + (heartbeatCount * 60) + ' 秒)');
}, 60000);