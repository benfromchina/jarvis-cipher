package com.stark.jarvis.cipher;

/**
 * 解密异常
 *
 * @author <a href="mailto:mengbin@hotmail.com">Ben</a>
 * @since 1.0.0, 2025/8/14
 */
public class DecryptionException extends RuntimeException {

    private static final long serialVersionUID = -5608899043313238977L;

    public DecryptionException(String message, Throwable throwable) {
        super(message, throwable);
    }

}
