--echo #########
--echo # Test for "ALTER TABLE ... UPGRADE PARTITIONING"
--echo ###

--echo # Unzip the zip file.
--file_exists $DATA_ARCH_PATH
--exec unzip -qo $DATA_ARCH_PATH -d $MYSQL_TMP_DIR

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
