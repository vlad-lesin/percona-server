#define MYSQL_SERVER 1

#include "sql/table.h"
#include "item.h"
#include "ha_rocksdb.h"
#include "ha_rockspart.h"

using myrocks::ha_rocksdb;
namespace myrocks {
extern handlerton *rocksdb_hton;
}

handler *ha_rockspart::get_file_handler(TABLE_SHARE *share,
                                       MEM_ROOT *alloc) const {
  ha_rocksdb *file = new(alloc) ha_rocksdb(myrocks::rocksdb_hton, share);
  file->init();
  return file;
}

void ha_rockspart::set_pk_can_be_decoded_for_each_partition() {
  for (auto file= reinterpret_cast<ha_rocksdb **>(m_file); *file; file++)
    (*file)->set_pk_can_be_decoded(m_pk_can_be_decoded);
}

int ha_rockspart::open(const char *name,
                       int mode,
                       uint test_if_locked,
                       const dd::Table *table_def) {
  int result = native_part::Partition_base::open(
    name, mode, test_if_locked, table_def);
  set_pk_can_be_decoded_for_each_partition();
  return result;
}

int ha_rockspart::create(const char *name,
                         TABLE *form,
                         HA_CREATE_INFO *create_info,
                         dd::Table *table_def) {
  int result = native_part::Partition_base::create(
    name, form, create_info, table_def);
  set_pk_can_be_decoded_for_each_partition();
  return result;
}


/**
  Clone the open and locked partitioning handler.

  @param  mem_root  MEM_ROOT to use.

  @return Pointer to the successfully created clone or NULL

  @details
  This function creates a new Partition_base handler as a clone/copy. The
  original (this) must already be opened and locked. The clone will use
  the originals m_part_info.
  It also allocates memory for ref + ref_dup.
  In Partition_base::open() it will clone its original handlers partitions
  which will allocate then on the correct MEM_ROOT and also open them.
*/

handler *ha_rockspart::clone(const char *name, MEM_ROOT *mem_root)
{
  ha_rockspart *new_handler;

  DBUG_ENTER("Partition_base::clone");

  /* If this->table == NULL, then the current handler has been created but not
  opened. Prohibit cloning such handler. */
  if (!table)
    DBUG_RETURN(NULL);

  new_handler= new (mem_root) ha_rockspart(ht, table_share, m_part_info,
                                           this, mem_root);
  if (!new_handler)
    DBUG_RETURN(NULL);

  /*
    We will not clone each partition's handler here, it will be done in
    Partition_base::open() for clones. Also set_ha_share_ref is not needed
    here, since 1) ha_share is copied in the constructor used above
    2) each partition's cloned handler will set it from its original.
  */

  /*
    Allocate new_handler->ref here because otherwise ha_open will allocate it
    on this->table->mem_root and we will not be able to reclaim that memory
    when the clone handler object is destroyed.
  */
  if (!(new_handler->ref= (uchar*) alloc_root(mem_root,
                                              ALIGN_SIZE(ref_length)*2)))
    goto err;

  if (new_handler->ha_open(table, name,
                           table->db_stat,
                           HA_OPEN_IGNORE_IF_LOCKED,
                           nullptr))
    goto err;

  new_handler->m_pk_can_be_decoded = m_pk_can_be_decoded;
  new_handler->set_pk_can_be_decoded_for_each_partition();

  DBUG_RETURN((handler*) new_handler);

err:
  delete new_handler;
  DBUG_RETURN(NULL);
}

ulong ha_rockspart::index_flags(uint idx, uint part, bool all_parts) const {
    return myrocks::ha_rocksdb::index_flags(
      m_pk_can_be_decoded, table_share, idx, part, all_parts);
}

bool ha_rockspart::rpl_lookup_rows() {
  return true;
}
