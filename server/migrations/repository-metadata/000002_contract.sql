BEGIN;

-- The compatibility fence ensures no v1 binary still depends on the original
-- index while the replacement assumes its stable name.
DROP INDEX ogvcs_metadata.file_path_history_by_file_id;
ALTER INDEX ogvcs_metadata.file_path_history_by_file_id_v2
    RENAME TO file_path_history_by_file_id;

COMMIT;
