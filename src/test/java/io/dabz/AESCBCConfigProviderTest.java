package io.dabz;

import org.apache.kafka.common.config.ConfigData;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AESCBCConfigProviderTest {
    @Test
    void ensureEncryptDecrypt() throws Exception {
        var key = AESCBCConfigProvider.generateKey();
        var iv = new IvParameterSpec("1234567891234567".getBytes());

        var text = "Hello World";
        var encoded = AESCBCConfigProvider.encrypt(text, key, iv);
        var decoded = AESCBCConfigProvider.decrypt(encoded, key, iv);


        Assertions.assertEquals(text, decoded);
        Assertions.assertNotEquals(text, encoded);
    }

    @Test
    void ensureConfigIsLoadedAndDecrypt() throws Exception {
        var key = "rXEM9J7EqGwUt40r+7ejphu7Q0L+ERuwp48CXiujIAY=";
        var iv = "1234567891234567";
        var ivSpec = new IvParameterSpec(iv.getBytes());
        var text = "Hello World";
        AESCBCConfigProvider aescbcConfigProvider = new AESCBCConfigProvider();
        var encoded = AESCBCConfigProvider.encrypt(text, aescbcConfigProvider.loadKey(key), ivSpec);

        var config = new HashMap<String, String>();
        config.put("keys.test.key", key);
        config.put("keys.test.iv", iv);
        aescbcConfigProvider.configure(config);
        ConfigData configData = aescbcConfigProvider.get("test", Set.of(encoded));

        Assertions.assertEquals(text, configData.data().get(encoded));
    }
}