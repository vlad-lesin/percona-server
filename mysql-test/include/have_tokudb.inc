#
# Check if server has support for loading plugins
#
if (`SELECT @@have_dynamic_loading != 'YES'`) {
  --skip TokuDB requires dynamic loading
}

if (!$TOKUDB) {
  --skip TokuDB requires the environment variable \$TOKUDB to be set (normally done by mtr)
}

#
# Check if --plugin-dir was setup for TokuDB
#
--let $pdcd_tested_dir=$TOKUDB_DIR
--source include/plugin_dirs_contains_dir.inc
if ( !$pdcd_found ) {
 --skip TokuDB requires that --plugin-dir is set to the TokuDB plugin dir (either the .opt file does not contain \$TOKUDB_OPT or another plugin is in use)
}
