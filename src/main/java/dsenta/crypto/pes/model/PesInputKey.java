package dsenta.crypto.pes.model;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class PesInputKey {
    private final List<Long> chunks;

    public PesInputKey(String base64Key) {
        if (Objects.isNull(base64Key)) {
            chunks = new ArrayList<>();
            return;
        }

        byte[] bytes = Base64.getDecoder().decode(base64Key);

        this.chunks = IntStream.range(0, bytes.length / Long.BYTES)
                .boxed()
                .map(i -> i * Long.BYTES)
                .map(i -> Arrays.copyOfRange(bytes, i, i + Long.BYTES))
                .map(BigInteger::new)
                .map(BigInteger::longValue)
                .collect(Collectors.toList());
    }

    public List<Long> getChunks() {
        return chunks;
    }
}
