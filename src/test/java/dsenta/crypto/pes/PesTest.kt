package dsenta.crypto.pes

import dsenta.crypto.pes.repository.PesKeyRepository
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.RepeatedTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.util.*
import java.util.stream.Collectors
import java.util.stream.IntStream
import kotlin.random.Random.Default.nextBytes

class PesTest {

    private val keyPES = Base64.getEncoder().encodeToString(nextBytes(256))
    private val content = nextBytes(1024 * 1024) // 1 MB

    @BeforeEach
    @AfterEach
    fun before() {
        PesKeyRepository.drop()
    }

    @RepeatedTest(5)
    fun shouldDecryptBytes() {
        val bytes = content.copyOf()
        val encryptedBytes = Pes.encrypt(bytes, keyPES)
        val decryptedBytes = Pes.decrypt(encryptedBytes, keyPES)
        assertArrayEquals(bytes, decryptedBytes)
    }

    @RepeatedTest(5)
    fun shouldDecryptBytesWhenGeneratingAgain() {
        val bytes = content.copyOf()
        val encryptedBytes = Pes.encrypt(bytes, keyPES)
        PesKeyRepository.drop()
        val decryptedBytes = Pes.decrypt(encryptedBytes, keyPES)
        assertArrayEquals(bytes, decryptedBytes)
    }

    @ParameterizedTest
    @ValueSource(strings = ["", "Read and write Chinese characters - 读写汉字 - 学中文"])
    fun shouldDecryptString(input: String) {
        val cypher = Pes.encrypt(input, keyPES)
        val decrypted = Pes.decrypt(cypher, keyPES)
        assertEquals(input, decrypted)
    }

    @Test
    fun everytimeAnotherCypher() {
        val cyphers = IntStream.range(0, 1000).boxed().map {
            Pes.encrypt("Miljenko", keyPES)
        }.collect(Collectors.toSet())

        assertEquals(1000, cyphers.size)

        cyphers.forEach {
            assertEquals("Miljenko", Pes.decrypt(it, keyPES))
        }
    }
}