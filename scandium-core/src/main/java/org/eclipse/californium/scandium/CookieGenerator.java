/*******************************************************************************
 * Copyright (c) 2017 Institute for Pervasive Computing, ETH Zurich and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 */
package org.eclipse.californium.scandium;

import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.CompressionMethod;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Generates a cookie in such a way that they can be verified without retaining
 * any per-client state on the server.
 * <p>
 * <pre>
 * Cookie = HMAC(Secret, Client - IP, Client - Parameters)
 * </pre>
 * <p>
 * as suggested
 * <a href="http://tools.ietf.org/html/rfc6347#section-4.2.1">here</a>.
 */
public class CookieGenerator {

    private static final long keyLifetime = TimeUnit.MINUTES.toMillis(5);

    private long lastGenerationDate;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private SecretKeySpec key;

    // attributes used for random byte generation
    private final SecureRandom rng = new SecureRandom();
    byte[] rd = new byte[32];

    private boolean isKeyExpired() {
        return System.currentTimeMillis() - lastGenerationDate > keyLifetime;
    }

    /**
     * Generate a new secret key for MAC algorithm
     **/
    private SecretKeySpec generateSecretKey() {
        if (key == null || isKeyExpired()) {
            lastGenerationDate = System.currentTimeMillis();
            rng.nextBytes(rd);
            key = new SecretKeySpec(rd, "MAC");
        }
        return key;
    }

    /**
     * Generates a cookie in such a way that they can be verified without
     * retaining any per-client state on the server.
     * <p>
     * <pre>
     * Cookie = HMAC(Secret, Client - IP, Client - Parameters)
     * </pre>
     * <p>
     * as suggested
     * <a href="http://tools.ietf.org/html/rfc6347#section-4.2.1">here</a>.
     *
     * @return the cookie generated from the client's parameters
     * @throws GeneralSecurityException if the cookie cannot be computed
     * @throws GeneralSecurityException if the cookie cannot be computed
     */
    public byte[] generateCookie(final ClientHello clientHello) throws
                                                                GeneralSecurityException,
                                                                CloneNotSupportedException {
        // Cookie = HMAC(Secret, Client-IP, Client-Parameters)
        final Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(generateSecretKey());
        // Client-IP
        hmac.update(clientHello.getPeer().toString().getBytes());
        // Client-Parameters
        hmac.update((byte) clientHello.getClientVersion().getMajor());
        hmac.update((byte) clientHello.getClientVersion().getMinor());
        hmac.update(clientHello.getRandom().getRandomBytes());
        hmac.update(clientHello.getSessionId().getId());
        hmac.update(CipherSuite.listToByteArray(clientHello.getCipherSuites()));
        hmac.update(CompressionMethod.listToByteArray(clientHello.getCompressionMethods()));
        return hmac.doFinal();
    }
}
