package com.viettel.vcs.utils;

import lombok.experimental.UtilityClass;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@UtilityClass
public class EncryptionUtils {

    private static final Logger logger = LogManager.getLogger(EncryptionUtils.class);
    private static final int AUTH_TAG_SIZE = 128; // bits
    private static final int IV_LEN = 12; // bytes
    private static final double PRNG_RESEED_INTERVAL = Math.pow(2, 16);
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final List<Integer> ALLOWED_KEY_SIZES = Arrays
            .asList(128, 192, 256); // bits
    private static SecureRandom prng;
    private static int bytesGenerated = 0;
    private static final String AES_CBC_ALGORITHM = "AES";
    private static final String SECRET_KEY = "vcs_telsec@2021";

    private static SecretKeySpec generateKey(String key, String algorithm) {
        byte[] keyBytes = key.getBytes();
        keyBytes = Arrays.copyOf(keyBytes, 16);
        return new SecretKeySpec(keyBytes, algorithm);
    }

    public static String decrypt(String input) {
        try {
            String secretKey = SECRET_KEY;
            byte[] bytes = Base64.getDecoder().decode(input);
            SecretKeySpec aesKeySpec = generateKey(secretKey, AES_CBC_ALGORITHM);
            byte[] easDecryptBytes = aesDecrypt(bytes, aesKeySpec);
            return new String(easDecryptBytes, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            logger.error("Decypttion failed {} , {} ", ex, ex.getMessage());
            return input;
        }
    }

    public static String encrypt(String input) {
        SecretKeySpec aesKeySpec = generateKey(SECRET_KEY, AES_CBC_ALGORITHM);
        byte[] encryptBytes = aesEncypt(input.getBytes(), aesKeySpec);
        return Base64.getEncoder().encodeToString(encryptBytes);
    }

    public static byte[] aesEncypt(byte[] input, SecretKeySpec key) {
        Objects.requireNonNull(input, "Input message cannot be null");
        Objects.requireNonNull(key, "key cannot be null");
        if (input.length == 0) {
            throw new IllegalArgumentException("Length of message cannot be 0");
        }

        if (!ALLOWED_KEY_SIZES.contains(key.getEncoded().length * 8)) {
            throw new IllegalArgumentException("Size of key must be 128, 192 or 256");
        }
        try {

            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            byte[] iv = getIV(IV_LEN);
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(AUTH_TAG_SIZE, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec);
            byte[] messageCipher = cipher.doFinal(input);

            // Prepend the IV with the message cipher
            byte[] cipherText = new byte[messageCipher.length + IV_LEN];
            System.arraycopy(iv, 0, cipherText, 0, IV_LEN);
            System.arraycopy(messageCipher, 0, cipherText, IV_LEN,
                    messageCipher.length);
            return cipherText;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            logger.error("AES Encryptiton failed {} , {} ", ex, ex.getMessage());
            return input;
        }
    }

    public static byte[] aesDecrypt(byte[] input, SecretKeySpec key) {
        try {
            Objects.requireNonNull(input, "Input message cannot be null");
            Objects.requireNonNull(key, "key cannot be null");

            if (input.length == 0) {
                throw new IllegalArgumentException("Input array cannot be empty");
            }

            byte[] iv = new byte[IV_LEN];
            System.arraycopy(input, 0, iv, 0, IV_LEN);

            byte[] messageCipher = new byte[input.length - IV_LEN];
            System.arraycopy(input, IV_LEN, messageCipher, 0, input.length - IV_LEN);

            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(AUTH_TAG_SIZE, iv);
            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParamSpec);

            return cipher.doFinal(messageCipher);
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                NoSuchAlgorithmException | InvalidKeyException | BadPaddingException ex) {
            logger.error("AES Decyption failed , ", ex);
            return input;
        }
    }

    private static byte[] getIV(int bytesNum) {

        if (bytesNum < 1) throw new IllegalArgumentException(
                "Number of bytes must be greater than 0");

        byte[] iv = new byte[bytesNum];

        prng = Optional.ofNullable(prng).orElseGet(() -> {
            try {
                prng = SecureRandom.getInstanceStrong();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException("Wrong algorithm name", e);
            }
            return prng;
        });

        if (bytesGenerated > PRNG_RESEED_INTERVAL || bytesGenerated == 0) {
            bytesGenerated = 0;
        }
        prng.nextBytes(iv);
        bytesGenerated = bytesGenerated + bytesNum;
        return iv;
    }
}
