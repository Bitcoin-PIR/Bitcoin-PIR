package com.onionpir.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.List;

/**
 * JNA mapping for the C struct:
 * <pre>
 * typedef struct {
 *     uint8_t *data;
 *     size_t   len;
 * } OnionBuf;
 * </pre>
 * Returned by value from functions that produce variable-length output.
 * Must be freed with {@code onion_free_buf()}.
 */
public class OnionBuf extends Structure {

    public Pointer data;
    public NativeLong len;

    public OnionBuf() {
        super();
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("data", "len");
    }

    public static class ByValue extends OnionBuf implements Structure.ByValue {
    }
}
