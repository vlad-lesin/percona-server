/* Copyright (c) 2000, 2011, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/* Handling of arrays that can grow dynamicly. */

#include "mysys_priv.h"
#include "m_string.h"

/*
  Initiate dynamic array

  SYNOPSIS
    init_dynamic_array2()
      array		Pointer to an array
      element_size	Size of element
      init_buffer       Initial buffer pointer
      init_alloc	Number of initial elements
      alloc_increment	Increment for adding new elements

  DESCRIPTION
    init_dynamic_array() initiates array and allocate space for 
    init_alloc eilements. 
    Array is usable even if space allocation failed, hence, the
    function never returns TRUE.
    Static buffers must begin immediately after the array structure.

  RETURN VALUE
    FALSE	Ok
*/

my_bool init_dynamic_array2(DYNAMIC_ARRAY *array, uint element_size,
                            void *init_buffer, ulong init_alloc, 
                            ulong alloc_increment)
{
  DBUG_ENTER("init_dynamic_array");
  if (!alloc_increment)
  {
    alloc_increment=MY_MAX((8192-MALLOC_OVERHEAD)/element_size,16);
    if (init_alloc > 8 && alloc_increment > init_alloc * 2)
      alloc_increment=init_alloc*2;
  }

  if (!init_alloc)
  {
    init_alloc=alloc_increment;
    init_buffer= 0;
  }
  array->elements=0;
  array->max_element=init_alloc;
  array->alloc_increment=alloc_increment;
  array->size_of_element=element_size;
  if ((array->buffer= init_buffer))
    DBUG_RETURN(FALSE);
  /* 
    Since the dynamic array is usable even if allocation fails here malloc
    should not throw an error
  */
  if (!(array->buffer= (uchar*) my_malloc(element_size*init_alloc, MYF(0))))
    array->max_element=0;
  DBUG_RETURN(FALSE);
} 

my_bool init_dynamic_array(DYNAMIC_ARRAY *array, uint element_size,
                           ulong init_alloc, ulong alloc_increment)
{
  /* placeholder to preserve ABI */
  return my_init_dynamic_array_ci(array, element_size, init_alloc, 
                                  alloc_increment);
}
/*
  Insert element at the end of array. Allocate memory if needed.

  SYNOPSIS
    insert_dynamic()
      array
      element

  RETURN VALUE
    TRUE	Insert failed
    FALSE	Ok
*/

my_bool insert_dynamic(DYNAMIC_ARRAY *array, const void *element)
{
  uchar* buffer;
  if (array->elements == array->max_element)
  {						/* Call only when nessesary */
    if (!(buffer=alloc_dynamic(array)))
      return TRUE;
  }
  else
  {
    buffer=array->buffer+(array->elements * array->size_of_element);
    array->elements++;
  }
  memcpy(buffer,element,(size_t) array->size_of_element);
  return FALSE;
}

/**
   Insert element at the end of the array only if the element
   is not already found in the array. This function takes O(n)
   and expected to be used only with small size arrays.

   @param[in] array
   @param[in] element

   @return FALSE OK
           TRUE  Insert failed
*/
my_bool insert_dynamic_set(DYNAMIC_ARRAY *array, const void *element)
{
  uint i;
  for (i = 0; i < array->elements; i++)
  {
    void *temp = dynamic_element(array, i, void**);
    if (!memcmp(temp, element, (size_t) array->size_of_element))
      return FALSE;
  }
  return insert_dynamic(array, element);
}


/*
  Alloc space for next element(s) 

  SYNOPSIS
    alloc_dynamic()
      array

  DESCRIPTION
    alloc_dynamic() checks if there is empty space for at least
    one element if not tries to allocate space for alloc_increment
    elements at the end of array.

  RETURN VALUE
    pointer	Pointer to empty space for element
    0		Error
*/

void *alloc_dynamic(DYNAMIC_ARRAY *array)
{
  if (array->elements == array->max_element)
  {
    char *new_ptr;
    if (array->buffer == (uchar *)(array + 1))
    {
      /*
        In this senerio, the buffer is statically preallocated,
        so we have to create an all-new malloc since we overflowed
      */
      if (!(new_ptr= (char *) my_malloc((array->max_element+
                                         array->alloc_increment) *
                                        array->size_of_element,
                                        MYF(MY_WME))))
        return 0;
      memcpy(new_ptr, array->buffer, 
             array->elements * array->size_of_element);
    }
    else
    if (!(new_ptr=(char*) my_realloc(array->buffer,(array->max_element+
                                     array->alloc_increment)*
                                     array->size_of_element,
                                     MYF(MY_WME | MY_ALLOW_ZERO_PTR))))
      return 0;
    array->buffer= (uchar*) new_ptr;
    array->max_element+=array->alloc_increment;
  }
  return array->buffer+(array->elements++ * array->size_of_element);
}


/*
  Pop last element from array.

  SYNOPSIS
    pop_dynamic()
      array
  
  RETURN VALUE    
    pointer	Ok
    0		Array is empty
*/

void *pop_dynamic(DYNAMIC_ARRAY *array)
{
  if (array->elements)
    return array->buffer+(--array->elements * array->size_of_element);
  return 0;
}

/*
  Replace element in array with given element and index

  SYNOPSIS
    set_dynamic()
      array
      element	Element to be inserted
      idx	Index where element is to be inserted

  DESCRIPTION
    set_dynamic() replaces element in array. 
    If idx > max_element insert new element. Allocate memory if needed. 
 
  RETURN VALUE
    TRUE	Idx was out of range and allocation of new memory failed
    FALSE	Ok
*/

my_bool set_dynamic(DYNAMIC_ARRAY *array, const void *element, ulong idx)
{
  if (idx >= array->elements)
  {
    if (idx >= array->max_element && allocate_dynamic(array, idx))
      return TRUE;
    memset((array->buffer+array->elements*array->size_of_element), 0, 
	  (idx - array->elements)*array->size_of_element);
    array->elements=idx+1;
  }
  memcpy(array->buffer+(idx * array->size_of_element),element,
	 (size_t) array->size_of_element);
  return FALSE;
}


/*
  Ensure that dynamic array has enough elements

  SYNOPSIS
    allocate_dynamic()
    array
    max_elements        Numbers of elements that is needed

  NOTES
   Any new allocated element are NOT initialized

  RETURN VALUE
    FALSE	Ok
    TRUE	Allocation of new memory failed
*/

my_bool allocate_dynamic(DYNAMIC_ARRAY *array, ulong max_elements)
{
  if (max_elements >= array->max_element)
  {
    ulong size;
    uchar *new_ptr;
    size= (max_elements + array->alloc_increment)/array->alloc_increment;
    size*= array->alloc_increment;
    if (array->buffer == (uchar *)(array + 1))
    {
       /*
         In this senerio, the buffer is statically preallocated,
         so we have to create an all-new malloc since we overflowed
       */
       if (!(new_ptr= (uchar *) my_malloc(size *
                                         array->size_of_element,
                                         MYF(MY_WME))))
         return 0;
       memcpy(new_ptr, array->buffer, 
              array->elements * array->size_of_element);
     }
     else


    if (!(new_ptr= (uchar*) my_realloc(array->buffer,size*
                                       array->size_of_element,
                                       MYF(MY_WME | MY_ALLOW_ZERO_PTR))))
      return TRUE;
    array->buffer= new_ptr;
    array->max_element= size;
  }
  return FALSE;
}


/*
  Get an element from array by given index

  SYNOPSIS
    get_dynamic()
      array	
      uchar*	Element to be returned. If idx > elements contain zeroes.
      idx	Index of element wanted. 
*/

void get_dynamic(DYNAMIC_ARRAY *array, void *element, ulong idx)
{
  if (idx >= array->elements)
  {
    DBUG_PRINT("warning",("To big array idx: %lu, array size is %lu",
                          idx,array->elements));
    memset(element, 0, array->size_of_element);
    return;
  }
  memcpy(element,array->buffer+idx*array->size_of_element,
         (size_t) array->size_of_element);
}


/*
  Empty array by freeing all memory

  SYNOPSIS
    delete_dynamic()
      array	Array to be deleted
*/

void delete_dynamic(DYNAMIC_ARRAY *array)
{
  /*
    Just mark as empty if we are using a static buffer
  */
  if (array->buffer == (uchar *)(array + 1))
    array->elements= 0;
  else
  if (array->buffer)
  {
    my_free(array->buffer);
    array->buffer=0;
    array->elements=array->max_element=0;
  }
}

/*
  Delete element by given index

  SYNOPSIS
    delete_dynamic_element()
      array
      idx        Index of element to be deleted
*/

void delete_dynamic_element(DYNAMIC_ARRAY *array, ulong idx)
{
  char *ptr= (char*) array->buffer+array->size_of_element*idx;
  array->elements--;
  memmove(ptr,ptr+array->size_of_element,
          (array->elements-idx)*array->size_of_element);
}


/*
  Free unused memory

  SYNOPSIS
    freeze_size()
      array	Array to be freed

*/

void freeze_size(DYNAMIC_ARRAY *array)
{
  ulong elements= MY_MAX(array->elements, 1);

  /*
    Do nothing if we are using a static buffer
  */
  if (array->buffer == (uchar *)(array + 1))
    return;
    
  if (array->buffer && array->max_element != elements)
  {
    array->buffer=(uchar*) my_realloc(array->buffer,
                                     elements*array->size_of_element,
                                     MYF(MY_WME));
    array->max_element=elements;
  }
}


/*
  Get the index of a dynamic element

  SYNOPSIS
    get_index_dynamic()
     array	Array
     element Whose element index 

*/

long get_index_dynamic(DYNAMIC_ARRAY *array, const void *element)
{
  size_t ret;
  if (array->buffer > (uchar *)element)
    return -1;

  ret= ((uchar *)element - array->buffer) /  array->size_of_element;
  if (ret > array->elements)
    return -1;

  return ret;

}
