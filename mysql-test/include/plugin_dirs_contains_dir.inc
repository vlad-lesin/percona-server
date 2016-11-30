# Checks if the certain dir is in plugin_dir,
# if yes returns $pdcd_found=1 and $pdcd_found=0
# otherwise.
#
# input parameters:
#
# $pdcd_tested_dir - directory to check
#

--let pdcd_plugin_dir= `SELECT @@plugin_dir`
--let pdcd_out_file= $MYSQL_TMP_DIR/pdcd_out_file.inc
--let pdcd_tested_dir=$pdcd_tested_dir

--perl

sub remove_last_slash {
  my $path = shift @_;
  chop $path while(substr($path, -1) eq '/');
  return $path;
}

my $plugin_dir = $ENV{'pdcd_plugin_dir'};
my $tested_dir = remove_last_slash($ENV{'pdcd_tested_dir'});
my $out_file = $ENV{'pdcd_out_file'};
my $found = 0;

my @plugin_dirs = split(/:/, $plugin_dir);

foreach my $pd (@plugin_dirs) {
  $pd = remove_last_slash($pd);
  if ($pd eq $tested_dir) {
    $found = 1;
    last;
  }
}

open(my $fh, '>', $out_file) or die "Could not open file '$filename' $!";

if ($found) {
  print $fh '--let $pdcd_found=1'."\n";
} else {
  print $fh '--let $pdcd_found=0'."\n";
}

close $fh;

exit 0;

EOF

--source $pdcd_out_file
