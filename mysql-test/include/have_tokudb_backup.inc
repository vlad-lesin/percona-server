--source include/have_tokudb.inc

if (!$TOKUDB_BACKUP) {
  --skip TokuDB Backup requires the environment variable \$TOKUDB_BACKUP to be set (normally done by mtr)
}

#
# Check if --plugin-dir was setup for TokuDB
#
--let $pdcd_tested_dir=$TOKUDB_BACKUP_DIR/
--source include/plugin_dirs_contains_dir.inc
if ( !$pdcd_found ) {
  --skip TokuDB Backup requires that --plugin-dir is set to the TokuDB Backup plugin dir (either the .opt file does not contain \$TOKUDB_BACKUP_OPT or another plugin is in use)
}
