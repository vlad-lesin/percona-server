#ifndef _HA_TOKUPART_H
#define _HA_TOKUPART_H

#include "partition_base.h"

class ha_tokupart: public Partition_base
{
public:
  ha_tokupart(
    handlerton*	hton,
    TABLE_SHARE*	table_arg) :
    Partition_base(hton, table_arg) { };

  ha_tokupart(handlerton *hton, TABLE_SHARE *share,
              partition_info *part_info_arg,
              Partition_base *clone_arg,
              MEM_ROOT *clone_mem_root_arg) :
    Partition_base(hton, share, part_info_arg, clone_arg, clone_mem_root_arg)
    {}

  ~ha_tokupart() {}

private:
  virtual handler *get_file_handler(TABLE_SHARE *share,
                                    MEM_ROOT *alloc,
                                    handlerton *db_type);
};

#endif // _HA_TOKUPART_H
