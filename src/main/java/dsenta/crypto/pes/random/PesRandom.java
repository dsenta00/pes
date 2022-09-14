package dsenta.crypto.pes.random;

import java.time.Instant;

import redbms.crypto.pes.utils.Pcg;

public final class PesRandom {

    private static final Pcg pcg = new Pcg(Instant.now());

    public static byte[] randomize(byte[] input) {
        return pcg.randomize(input);
    }
}