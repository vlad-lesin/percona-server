# Set different paths for --datadir
let $MYSQLD_DATADIR1 = $MYSQL_TMP_DIR/$DATA_DIR_NAME;
let $DATA_ARCH_PATH = $MYSQL_TMP_DIR/$DATA_DIR_NAME.zip;

--echo #########
--echo # Test for "ALTER TABLE ... UPGRADE PARTITIONING"
--echo ###

--echo # Copy the remote tablespace & DB zip files from suite location to working location.
--copy_file $MYSQLTEST_VARDIR/std_data/$DATA_DIR_NAME.zip $DATA_ARCH_PATH

--echo # Check that the file exists in the working folder.
--file_exists $DATA_ARCH_PATH

--echo # Unzip the zip file.
--exec unzip -qo $DATA_ARCH_PATH -d $MYSQL_TMP_DIR

--let $MYSQLD_DATADIR=`SELECT @@datadir`

--echo # Stop DB server which was created by MTR default
--exec echo "wait" > $MYSQLTEST_VARDIR/tmp/mysqld.1.expect
--shutdown_server
--source include/wait_until_disconnected.inc

--echo # Create a bootstrap file in temp location
--replace_result $MYSQL_TMP_DIR MYSQL_TMP_DIR
--exec echo $MYSQL_TMP_DIR/bootstrap.log

--echo # Restart the server
--exec echo "restart: --loose-skip-log-bin --skip-log-slave-updates --datadir=$MYSQLD_DATADIR1 $ADDITIONAL_OPTS" > $MYSQLTEST_VARDIR/tmp/mysqld.1.expect
--enable_reconnect
--source include/wait_until_connected_again.inc

--echo # Check test table before upgrade
SHOW CREATE TABLE test.t1;
SELECT * FROM test.t1 ORDER BY a;
--source include/table_files_replace_pattern.inc
--list_files $MYSQLD_DATADIR1/test/

--echo # Upgrade
ALTER TABLE test.t1 UPGRADE PARTITIONING;

--echo # Check test table after upgrade
SHOW CREATE TABLE test.t1;
SELECT * FROM test.t1 ORDER BY a;
--source include/table_files_replace_pattern.inc
--list_files $MYSQLD_DATADIR1/test/

--echo # Stop the server
--source include/shutdown_mysqld.inc

--echo # Remove data directory
--exec rm -rf $MYSQLD_DATADIR1
