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
package com.wultra.security.ssl.pinning.model;

/**
 * Class representing certificate information record used in SSL pinning tool.
 */
public class CertificateInfo {

    private String name;
    private String fingerprint;
    private long expires;
    private String signature;

    /**
     * Default constructor.
     */
    public CertificateInfo() {
    }

    /**
     * Constructor with all details.
     * @param name Domain common name.
     * @param fingerprint SHA-256 fingerprint of certificate.
     * @param expires Certificate expiration time as using timestamp.
     * @param signature Certificate signature.
     */
    public CertificateInfo(String name, String fingerprint, long expires, String signature) {
        this.name = name;
        this.fingerprint = fingerprint;
        this.expires = expires;
        this.signature = signature;
    }

    /**
     * Get domain common name.
     * @return Domain common name.
     */
    public String getName() {
        return name;
    }

    /**
     * Set domain common name.
     * @param name Domain common name.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get fingerprint in HEX format.
     * @return Fingerprint in HEX format.
     */
    public String getFingerprint() {
        return fingerprint;
    }

    /**
     * Set fingerprint in HEX format.
     * @param fingerprint Fingerprint in HEX format.
     */
    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    /**
     * Get expiration time as Unix timestamp.
     * @return Expiration time as Unix timestamp.
     */
    public long getExpires() {
        return expires;
    }

    /**
     * Set expiration time as Unix timestamp.
     * @param expires Expiration time as Unix timestamp.
     */
    public void setExpires(long expires) {
        this.expires = expires;
    }

    /**
     * Get fingerprint signature.
     * @return Fingerprint signature.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Set fingerprint signature.
     * @param signature Fingerprint signature.
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }
}
