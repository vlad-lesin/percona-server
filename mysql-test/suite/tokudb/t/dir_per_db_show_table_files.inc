--sorted_result

--echo ## Looking for *.tokudb files in data_dir
--replace_regex /[a-z0-9]+_[a-z0-9]+_[a-z0-9]+(_[BP]_[a-z0-9]+){0,1}\./id./
--list_files $DATADIR *.tokudb

--echo ## Looking for *.tokudb files in data_dir/$DB
--replace_regex /[a-z0-9]+_[a-z0-9]+_[a-z0-9]+(_[BP]_[a-z0-9]+){0,1}\./id./
--list_files $DATADIR/$DB/ *.tokudb
