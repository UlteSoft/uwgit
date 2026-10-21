#!/usr/bin/env bash
# Sourced after entering the frozen source tree. Selecting targets, rather than
# test-name filters, excludes every present/future test in the mutation harness.
skip_fuzz=${skip_fuzz:-0}
[[ $skip_fuzz == 0 || $skip_fuzz == 1 ]] || { echo 'UWGIT_SKIP_FUZZ must be 0 or 1' >&2; exit 2; }
regular_targets=()
regular_filters=()
if [[ $skip_fuzz == 1 ]]; then
    regular_targets=(--lib --bins)
    for test_source in tests/*.rs; do
        test_name=${test_source##*/}
        test_name=${test_name%.rs}
        [[ $test_name == audit_fuzz ]] || regular_targets+=(--test "$test_name")
    done
    regular_filters=(--skip every_payload_byte_mutation_is_replayable_even_if_decoding_fails --skip myers_is_shortest_and_covers_every_byte_exhaustively --skip exhaustive_small_edits_cover_every_selected_byte_with_equal_gaps)
    printf '{"audit_fuzz":"excluded target","mutation_and_exhaustive_properties":"three named tests filtered","libfuzzer":"not invoked","doctests":"not selected"}\n' > "$run/evidence/test-selection.json"
else
    printf '{"audit_fuzz":"regular non-ignored cases","libfuzzer":"not invoked","doctests":"selected"}\n' > "$run/evidence/test-selection.json"
fi
