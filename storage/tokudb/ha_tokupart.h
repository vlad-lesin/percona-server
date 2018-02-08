#ifndef _HA_TOKUPART_H
#define _HA_TOKUPART_H

#include "partitioning/partition_handler.h"

class Ha_tokupart_share : public Partition_share
{
public:
  Ha_tokupart_share(TABLE_SHARE*  table_share) {};

  ~Ha_tokupart_share() {};
private:
  /** Disable default constructor. */
  Ha_tokupart_share() {};
};

class ha_tokupart:
  public ha_tokudb,
  public Partition_helper,
  public Partition_handler
{
public:
  ha_tokupart(
  handlerton*	hton,
  TABLE_SHARE*	table_arg);

  ~ha_tokupart();
};

#endif // _HA_TOKUPART_H
