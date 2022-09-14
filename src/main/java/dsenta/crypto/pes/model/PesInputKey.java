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
