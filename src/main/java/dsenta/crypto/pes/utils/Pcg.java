package redbms.crypto.pes.utils;

import java.time.Instant;

public class Pcg {
    private static final long PCG_MULTIPLIER = 6364136223846793005L;
    private static final long PCG_INCREMENT = 1442695040888963407L;
    private static final long PCG_INITIAL_STATE = 0x4d595df4d0f33173L;
    private long state;

    public Pcg(long seed) {
        this.state = PCG_INITIAL_STATE + seed;
    }

    public Pcg(Instant instant) {
        this(instant.toEpochMilli());
    }

    public int nextInt() {
        long x = state;
        int count = (int) (x >> 59);

        state = x * PCG_MULTIPLIER + PCG_INCREMENT;
        x ^= x >> 18;
        return rotr32((int) (x >> 27), count);
    }

    public byte nextByte() {
        return (byte) nextInt();
    }

    public byte[] randomize(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = nextByte();
        }

        return bytes;
    }

    int rotr32(int x, int r) {
        return x >> r | x << (-r & 31);
    }
}
