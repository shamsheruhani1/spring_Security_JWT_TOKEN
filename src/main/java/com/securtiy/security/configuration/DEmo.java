package com.securtiy.security.configuration;

import java.security.SecureRandom;
import java.util.Base64;

public class DEmo {

    public static void main(String[] args) {
        System.out.println(generateSafeToken());
    }
      static String generateSafeToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[36]; // 36 bytes * 8 = 288 bits, a little bit more than
        // the 256 required bits
        random.nextBytes(bytes);
        var encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(bytes);
    }
}
