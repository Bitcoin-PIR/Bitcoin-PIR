package com.onionpir.jna;

import com.sun.jna.Structure;

import java.util.List;

/**
 * JNA mapping for the C struct:
 * <pre>
 * typedef struct {
 *     uint64_t num_entries;
 *     uint64_t entry_size;
 *     uint64_t num_plaintexts;
 *     uint64_t fst_dim_sz;
 *     uint64_t other_dim_sz;
 *     uint64_t poly_degree;
 *     uint64_t coeff_val_cnt;
 *     double   db_size_mb;
 *     double   physical_size_mb;
 * } CPirParamsInfo;
 * </pre>
 */
public class PirParamsInfo extends Structure {

    public long num_entries;
    public long entry_size;
    public long num_plaintexts;
    public long fst_dim_sz;
    public long other_dim_sz;
    public long poly_degree;
    public long coeff_val_cnt;
    public double db_size_mb;
    public double physical_size_mb;

    @Override
    protected List<String> getFieldOrder() {
        return List.of(
            "num_entries", "entry_size", "num_plaintexts",
            "fst_dim_sz", "other_dim_sz", "poly_degree",
            "coeff_val_cnt", "db_size_mb", "physical_size_mb"
        );
    }

    public static class ByValue extends PirParamsInfo implements Structure.ByValue {
    }
}
