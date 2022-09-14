package dsenta.crypto.pes.exception;

public class HashMismatchException extends RuntimeException {
    private static final long serialVersionUID = -7494869927460326618L;

    public HashMismatchException() {
        super("Hash mismatch");
    }
}