package com.onionpir.jna;

/**
 * Static utilities for the OnionPIR JNA binding.
 */
public final class OnionPir {

    private static final OnionPirLibrary LIB = OnionPirLibrary.INSTANCE;

    private OnionPir() {
    }

    /**
     * Get PIR parameter info for a database with the given number of entries.
     * Pass 0 to use the compiled-in default.
     */
    public static PirParamsInfo.ByValue paramsInfo(long numEntries) {
        return LIB.onion_get_params_info(numEntries);
    }

    /**
     * Convert a native {@link OnionBuf} to a Java {@code byte[]} and free
     * the native buffer. This mirrors the Rust {@code buf_to_vec()} helper:
     * copy the data, then immediately call {@code onion_free_buf()}.
     */
    static byte[] bufToBytes(OnionBuf.ByValue buf) {
        if (buf.data == null || buf.len.longValue() == 0) {
            LIB.onion_free_buf(buf);
            return new byte[0];
        }
        int length = buf.len.intValue();
        byte[] result = buf.data.getByteArray(0, length);
        LIB.onion_free_buf(buf);
        return result;
    }
}
