package dsenta.crypto.pes.model;

import redbms.crypto.pes.utils.ByteUtils;
import redbms.crypto.pes.utils.Pcg;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class PesKey {
    private final int NO_OF_CYCLES = 11;
    private final PermutationTable keyTable = new PermutationTable();
    private final PermutationTable inverseKeyTable = new PermutationTable();

    public PesKey(PesInputKey pesInputKey) {
        List<Pcg> pcgList = pesInputKey
                .getChunks()
                .stream()
                .map(Pcg::new)
                .collect(Collectors.toList());

        int i = 0;
        List<BytePair> keyBytePairs = this.keyTable.getBytePairs();
        List<BytePair> inverseKeyBytePairs = this.inverseKeyTable.getBytePairs();

        do {
            for (Pcg pcg : pcgList) {
                int j = Math.abs(pcg.nextInt()) & PermutationTable.MOD_TOTAL_BY_AND;

                BytePair keyFirst = keyBytePairs.get(i);
                BytePair keySecond = keyBytePairs.get(j);
                keyBytePairs.set(j, keyFirst);
                keyBytePairs.set(i, keySecond);
                inverseKeyBytePairs.set(keySecond.asInteger(), new BytePair(i));
                inverseKeyBytePairs.set(keyFirst.asInteger(), new BytePair(j));
            }
            ++i;
        } while (i < PermutationTable.TOTAL);
    }

    public byte[] hash64(byte[] bytes) {
        if (Objects.isNull(bytes)) return new byte[8];
        if (bytes.length == 0) return new byte[8];

        byte[] hash = Arrays.copyOf(bytes, 8);

        for (int i = 8; i < bytes.length; ++i) {
            int actualIndex = i & 7;
            hash[actualIndex] = keyTable.permutation(hash[actualIndex], bytes[i]).getSecond();
        }

        return hash;
    }

    public long hash(byte[] bytes) {
        if (Objects.isNull(bytes)) return 0L;
        if (bytes.length == 0) return 0L;

        byte[] hash = Arrays.copyOf(bytes, 8);

        for (int i = 8; i < bytes.length; ++i) {
            int actualIndex = i & 7;
            hash[actualIndex] = keyTable.permutation(hash[actualIndex], bytes[i]).getSecond();
        }

        return ByteUtils.bytesToLong(hash64(bytes));
    }

    public void encrypt(byte[] bytes) {
        Objects.requireNonNull(bytes, "Cannot encrypt null");
        assert bytes.length > 0 : "Cannot encrypt empty array";

        int permutation = 0;
        int lastIndex = bytes.length - 1;

        do {
            int i = 0;
            do {
                BytePair bytePair = keyTable.permutation(bytes[i], bytes[i + 1]);
                bytes[i] = bytePair.getFirst();
                bytes[i + 1] = bytePair.getSecond();
                i++;
            } while (i < lastIndex);

            BytePair bytePair = keyTable.permutation(bytes[lastIndex], bytes[0]);
            bytes[lastIndex] = bytePair.getFirst();
            bytes[0] = bytePair.getSecond();
            permutation++;
        } while (permutation < NO_OF_CYCLES);
    }

    public void decrypt(byte[] bytes) {
        Objects.requireNonNull(bytes, "Cannot decrypt null");
        assert bytes.length > 0 : "Cannot decrypt empty array!";

        int permutation = 0;
        do {
            BytePair bytePair = inverseKeyTable.permutation(bytes[bytes.length - 1], bytes[0]);
            bytes[bytes.length - 1] = bytePair.getFirst();
            bytes[0] = bytePair.getSecond();

            int i = bytes.length - 2;
            do {
                bytePair = inverseKeyTable.permutation(bytes[i], bytes[i + 1]);
                bytes[i] = bytePair.getFirst();
                bytes[i + 1] = bytePair.getSecond();
                i--;
            } while (i >= 0);
            permutation++;
        } while (permutation < NO_OF_CYCLES);
    }
}