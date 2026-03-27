package com.onionpir.jna;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * Raw JNA declarations for every {@code extern "C"} function in {@code ffi_c.h}.
 * <p>
 * The native library name is {@code "onionpir"}, which JNA resolves to
 * {@code libonionpir.so} (Linux) or {@code libonionpir.dylib} (macOS).
 * Build the shared library with:
 * <pre>
 * cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
 * make -j$(nproc)
 * </pre>
 */
public interface OnionPirLibrary extends Library {

    OnionPirLibrary INSTANCE = Native.load("onionpir", OnionPirLibrary.class);

    // ── Buffer management ────────────────────────────────────────────────

    void onion_free_buf(OnionBuf.ByValue buf);

    // ── Params ───────────────────────────────────────────────────────────

    PirParamsInfo.ByValue onion_get_params_info(long num_entries);

    // ── Client ───────────────────────────────────────────────────────────

    Pointer onion_client_new(long num_entries);

    void onion_client_free(Pointer h);

    Pointer onion_client_new_from_sk(long num_entries, long client_id,
                                     byte[] sk, NativeLong sk_len);

    OnionBuf.ByValue onion_client_export_secret_key(Pointer h);

    long onion_client_get_id(Pointer h);

    OnionBuf.ByValue onion_client_generate_galois_keys(Pointer h);

    OnionBuf.ByValue onion_client_generate_gsw_keys(Pointer h);

    OnionBuf.ByValue onion_client_generate_query(Pointer h, long entry_index);

    OnionBuf.ByValue onion_client_decrypt_response(Pointer h, long entry_index,
                                                    byte[] resp, NativeLong resp_len);

    // ── Server ───────────────────────────────────────────────────────────

    Pointer onion_server_new(long num_entries);

    void onion_server_free(Pointer h);

    int onion_server_load_db(Pointer h, String path);

    void onion_server_save_db(Pointer h, String path);

    void onion_server_push_chunk(Pointer h, byte[] data, NativeLong data_len,
                                  NativeLong chunk_idx);

    void onion_server_preprocess(Pointer h);

    void onion_server_set_shared_database(Pointer h,
                                           Pointer shared_ntt_store,
                                           NativeLong shared_store_num_entries,
                                           Pointer index_table,
                                           NativeLong index_table_len);

    void onion_server_ntt_expand_entry(Pointer h, byte[] raw_entry,
                                        NativeLong raw_len, Pointer dst);

    void onion_server_set_galois_key(Pointer h, long client_id,
                                      byte[] key, NativeLong key_len);

    void onion_server_set_gsw_key(Pointer h, long client_id,
                                    byte[] key, NativeLong key_len);

    void onion_server_remove_client(Pointer h, long client_id);

    OnionBuf.ByValue onion_server_answer_query(Pointer h, long client_id,
                                                byte[] query, NativeLong query_len);

    void onion_server_set_key_store(Pointer server, Pointer store);

    // ── Key store ────────────────────────────────────────────────────────

    Pointer onion_key_store_new(long num_entries);

    void onion_key_store_free(Pointer h);

    void onion_key_store_set_galois_key(Pointer h, long client_id,
                                         byte[] key, NativeLong key_len);

    void onion_key_store_set_gsw_key(Pointer h, long client_id,
                                       byte[] key, NativeLong key_len);

    OnionBuf.ByValue onion_key_store_export_gsw(Pointer h, long client_id);

    void onion_key_store_import_gsw(Pointer h, long client_id,
                                      Pointer data, NativeLong num_values);

    int onion_key_store_has_client(Pointer h, long client_id);

    void onion_key_store_remove_client(Pointer h, long client_id);

    // ── Query queue ──────────────────────────────────────────────────────

    Pointer onion_queue_new(Pointer server);

    void onion_queue_stop(Pointer h);

    void onion_queue_free(Pointer h);

    long onion_queue_submit(Pointer h, long client_id,
                             byte[] query, NativeLong query_len);

    byte onion_queue_status(Pointer h, long ticket);

    long onion_queue_position(Pointer h, long ticket);

    OnionBuf.ByValue onion_queue_result(Pointer h, long ticket);
}
