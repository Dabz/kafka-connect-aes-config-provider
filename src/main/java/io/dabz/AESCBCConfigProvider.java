package io.dabz;

import org.apache.kafka.common.config.ConfigData;
import org.apache.kafka.common.config.provider.ConfigProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class AESCBCConfigProvider implements ConfigProvider {
    private Map<String, SecretKey> keys;
    private Map<String, IvParameterSpec> initializationVectors;

    public static String KEY_PREFIX_CONFIG = "keys.";
    public static String IV_CONFIG = ".iv";
    public static String KEY_CONFIG = ".key";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("No command specify");
            System.err.println("Usage: java -jar AESConfigProvider.jar generatekey/encrypt/decryot ");
            System.exit(1);
        }

        var command = args[0];
        AESCBCConfigProvider aescbcConfigProvider = new AESCBCConfigProvider();
        if (command.equalsIgnoreCase("generateKey")) {
            generateKeyCommand(aescbcConfigProvider);
        }
        if (command.equalsIgnoreCase("encrypt")) {
            if (args.length < 4) {
                System.err.println("Usage: java -jar AESConfigProvider.jar encrypt [key] [iv] [value]");
                System.exit(1);
            }
            var key = aescbcConfigProvider.loadKey(args[1]);
            var initilizationVector = new IvParameterSpec(args[2].getBytes());
            var value = args[3];
            var encoded = encrypt(value, key, initilizationVector);
            System.out.println(encoded);
        }
        else if (command.equalsIgnoreCase("decrypt")) {
            if (args.length < 4) {
                System.err.println("Usage: java -jar AESConfigProvider.jar decrypt [key] [iv] [value]");
                System.exit(1);
            }
            var key = aescbcConfigProvider.loadKey(args[1]);
            var initilizationVector = new IvParameterSpec(args[2].getBytes());
            var value = args[3];
            var decoded = decrypt(value, key, initilizationVector);
            System.out.println(decoded);
        } else {
            System.err.println("Unkown command " + command);
            System.exit(1);
        }
    }

    private static void generateKeyCommand(AESCBCConfigProvider aescbcConfigProvider) throws NoSuchAlgorithmException {
        SecretKey secretKey = aescbcConfigProvider.generateKey();
        var base64Key = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println("Generated key:");
        System.out.println(base64Key);
    }

    @Override
    public void configure(Map<String, ?> map) {
        this.keys = new HashMap<>();
        this.initializationVectors = new HashMap<>();
        map.entrySet().forEach((entry) -> {
            if (entry.getKey().startsWith(KEY_PREFIX_CONFIG)) {
                var keyWithSuffix = entry.getKey().replace(KEY_PREFIX_CONFIG, "");
                if (keyWithSuffix.endsWith(KEY_CONFIG)) {
                    var keyName = keyWithSuffix.replace(KEY_CONFIG, "");
                    SecretKey secretKey = loadKey(entry.getValue().toString());
                    keys.put(keyName, secretKey);
                } else if (keyWithSuffix.endsWith(IV_CONFIG)) {
                    var keyName = keyWithSuffix.replace(IV_CONFIG, "");
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(entry.getValue().toString().getBytes());
                    initializationVectors.put(keyName, ivParameterSpec);
                }
            }
        });

        for (var keyName : this.keys.keySet()) {
            if (!initializationVectors.containsKey(keyName)) {
                throw new RuntimeException(String.format("AES Key %s has no initialization vector set", keyName));
            }
        }
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public SecretKey loadKey(String key) {
        var encoded = Base64.getDecoder().decode(key);
        return new SecretKeySpec(encoded, "AES");
    }

    public static String encrypt(String input, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    @Override
    public ConfigData get(String path) {
        return null;
    }

    @Override
    public ConfigData get(String path, Set<String> keys) {
        HashMap<String, String> config = new HashMap<>();
        var key = this.keys.get(path);
        var initializationVector = this.initializationVectors.get(path);

        if (key == null || initializationVector == null) {
            throw new RuntimeException(String.format("Key %s not defined in the AES configuration", path));
        }

        for (var encryptedKey : keys) {
            String decoded = null;
            try {
                decoded = decrypt(encryptedKey, key, initializationVector);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            config.put(encryptedKey, decoded);
        }
        return new ConfigData(config);
    }

    @Override
    public void close() throws IOException {

    }

}
