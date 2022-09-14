package dsenta.crypto.pes.model;

import lombok.Data;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Data
public class PermutationTable {
    private static final int AXIS_SIZE = 256;
    public static final int TOTAL = AXIS_SIZE * AXIS_SIZE;
    public static final int MOD_TOTAL_BY_AND = 0xffff;
    private final List<BytePair> bytePairs = IntStream
            .range(0, TOTAL)
            .boxed()
            .map(BytePair::new)
            .collect(Collectors.toList());
    public BytePair permutation(byte first, byte second) {
        int index = (first & 0xff) | (second & 0xff) << 8;
        return bytePairs.get(index);
    }
}