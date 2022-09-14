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