/**
 * MIT License
 *
 * Copyright (c) 2022 Duje Senta
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package dsenta.crypto.pes.utils;

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
