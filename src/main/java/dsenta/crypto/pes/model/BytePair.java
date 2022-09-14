package dsenta.crypto.pes.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class BytePair {
    private final byte first;
    private final byte second;

    public BytePair(int i) {
        first = (byte) (i & 0xff);
        second = (byte) ((i >> 8) & 0xff);
    }

    public int asInteger() {
        return (first & 0xff) | (second & 0xff) << 8;
    }
}