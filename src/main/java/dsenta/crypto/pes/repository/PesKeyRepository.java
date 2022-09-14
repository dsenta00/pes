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
package dsenta.crypto.pes.repository;

import static java.util.Objects.isNull;

import java.util.HashMap;
import java.util.Map;

import dsenta.crypto.pes.model.PesInputKey;
import dsenta.crypto.pes.model.PesKey;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PesKeyRepository {

    private static final PesKey hashingKey = new PesKey(new PesInputKey(null));
    private static final Map<String, PesKey> pesKeyMap = new HashMap<>();

    public static PesKey fetchOrCreate(String key) {
        if (isNull(key)) {
            return hashingKey;
        }

        if (!pesKeyMap.containsKey(key)) {
            pesKeyMap.put(key, new PesKey(new PesInputKey(key)));
        }

        return pesKeyMap.get(key);
    }

    public static void drop() {
        pesKeyMap.clear();
    }
}