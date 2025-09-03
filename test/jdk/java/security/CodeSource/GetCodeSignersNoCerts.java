/*
 * Copyright (c) 2005, 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * @test
 * @bug 8366522
 * @summary Verify that NPE is not thrown CodeSource.getCodeSigners() when CodeSource is created with empty or null certs argument
 */
import java.io.File;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

public class GetCodeSignersNoCerts {
    private static final Certificate NON_X509_CERT = new Certificate("") {
        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }

        @Override
        public void verify(PublicKey key) {
        }

        @Override
        public void verify(PublicKey key, String sigProvider) {
        }

        @Override
        public String toString() {
            return "";
        }

        @Override
        public PublicKey getPublicKey() {
            return null;
        }
    };

    public static void main(String[] args) throws Exception {
        File certsFile = new File(System.getProperty("test.src", "."), "certs");
        URL location = certsFile.toURI().toURL();

        // CodeSource.getCodeSigners must not throw a NPE when there are no X509 certificates in the chain

        CodeSource cs = new CodeSource(location, new java.security.cert.Certificate[0]);
        cs.getCodeSigners();

        cs = new CodeSource(location, (java.security.cert.Certificate[]) null);
        cs.getCodeSigners();

        cs = new CodeSource(location, new Certificate[] {NON_X509_CERT});
        cs.getCodeSigners();
    }
}

