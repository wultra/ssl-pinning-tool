/*
 * Copyright 2018 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.wultra.security.ssl.pinning.errorhandling;

/**
 * Exception thrown when fingerprint signature fails.
 */
public class FingerprintSignatureException extends Exception {

    /**
     * Default constructor.
     */
    public FingerprintSignatureException() {
        super();
    }

    /**
     * Constructor with error message.
     * @param message Error message.
     */
    public FingerprintSignatureException(String message) {
        super(message);
    }

    /**
     * Constructor with error message and cause.
     * @param message Error message.
     * @param cause Cause.
     */
    public FingerprintSignatureException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructor with cause.
     * @param cause Cause.
     */
    public FingerprintSignatureException(Throwable cause) {
        super(cause);
    }

}