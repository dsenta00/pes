package dsenta.crypto.pes;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import dsenta.crypto.pes.exception.HashMismatchException;
import dsenta.crypto.pes.model.PesKey;
import dsenta.crypto.pes.random.PesRandom;
import dsenta.crypto.pes.repository.PesKeyRepository;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Pes {

    private static final int PES_BLOCK_CYPHER_SIZE_BYTES = 16;
    private static final int PES_BLOCK_CYPHER_SIZE_BYTES_FAST_MOD_AND = 0xf;

    public static String encrypt(String string, String key) {
        byte[] cypher = encrypt(string.getBytes(StandardCharsets.UTF_8), key);
        return Base64.getEncoder().encodeToString(cypher);
    }

    public static byte[] encrypt(byte[] bytes, String key) {
        PesKey pesKey = PesKeyRepository.fetchOrCreate(key);
        long hash = pesKey.hash(bytes);

        byte[] length = ByteBuffer
                .allocate(Integer.BYTES)
                .putInt(bytes.length)
                .array();

        int lengthWithoutPadding = bytes.length +
                Long.BYTES + // hash size
                4; // length of "length"

        byte paddingLen = (byte) (PES_BLOCK_CYPHER_SIZE_BYTES - (lengthWithoutPadding & PES_BLOCK_CYPHER_SIZE_BYTES_FAST_MOD_AND));
        byte[] padding = PesRandom.randomize(new byte[paddingLen]);

        byte[] hashBytes = ByteBuffer
                .allocate(Long.BYTES)
                .putLong(hash)
                .array();

        byte[] out = ByteBuffer
                .wrap(new byte[lengthWithoutPadding + paddingLen])
                .put(hashBytes)
                .put(length)
                .put(bytes)
                .put(padding)
                .array();

        pesKey.encrypt(out);

        return out;
    }

    public static String decrypt(String cypher, String key) {
        return new String(decrypt(Base64.getDecoder().decode(cypher), key));
    }

    public static byte[] decrypt(byte[] bytes, String key) {
        PesKey pesKey = PesKeyRepository.fetchOrCreate(key);

        pesKey.decrypt(bytes);

        int length = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8, 12)).getInt();
        byte[] out = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 12, 12 + length)).array();

        checkHash(pesKey, out, bytes);

        return out;
    }

    private static void checkHash(PesKey pesKey, byte[] out, byte[] bytes) {
        long givenHash = pesKey.hash(out);
        long hash = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 8)).getLong();
        if (givenHash != hash) {
            throw new HashMismatchException();
        }
    }
}