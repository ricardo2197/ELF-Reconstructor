/* elfcomm.c -- common code for ELF format file.
   Copyright (C) 2010-2019 Free Software Foundation, Inc.

   Originally developed by Eric Youngdale <eric@andante.jic.com>
   Modifications by Nick Clifton <nickc@redhat.com>

   This file is part of GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#include "dbgtrace.hpp"
#include "elfcomm.hpp"
#include <assert.h>
#include <iostream>

void (*byte_put) (unsigned char *, elf_vma, int);

void
byte_put_little_endian (unsigned char * field, elf_vma value, int size)
{
  switch (size)
    {
    case 8:
      field[7] = (((value >> 24) >> 24) >> 8) & 0xff;
      field[6] = ((value >> 24) >> 24) & 0xff;
      field[5] = ((value >> 24) >> 16) & 0xff;
      field[4] = ((value >> 24) >> 8) & 0xff;
      /* Fall through.  */
    case 4:
      field[3] = (value >> 24) & 0xff;
      /* Fall through.  */
    case 3:
      field[2] = (value >> 16) & 0xff;
      /* Fall through.  */
    case 2:
      field[1] = (value >> 8) & 0xff;
      /* Fall through.  */
    case 1:
      field[0] = value & 0xff;
      break;

    default:
      DBGE("Unhandled data length: %d\n", size);
      exit(-1);
    }
}

void
byte_put_big_endian (unsigned char * field, elf_vma value, int size)
{
  switch (size)
    {
    case 8:
      field[7] = value & 0xff;
      field[6] = (value >> 8) & 0xff;
      field[5] = (value >> 16) & 0xff;
      field[4] = (value >> 24) & 0xff;
      value >>= 16;
      value >>= 16;
      /* Fall through.  */
    case 4:
      field[3] = value & 0xff;
      value >>= 8;
      /* Fall through.  */
    case 3:
      field[2] = value & 0xff;
      value >>= 8;
      /* Fall through.  */
    case 2:
      field[1] = value & 0xff;
      value >>= 8;
      /* Fall through.  */
    case 1:
      field[0] = value & 0xff;
      break;

    default:
      DBGE("Unhandled data length: %d\n", size);
      exit(-1);
    }
}

elf_vma (*byte_get) (const unsigned char *, int);

elf_vma
byte_get_little_endian (const unsigned char *field, int size)
{
  switch (size)
    {
    case 1:
      return *field;

    case 2:
      return  ((unsigned int) (field[0]))
	|    (((unsigned int) (field[1])) << 8);

    case 3:
      return  ((unsigned long) (field[0]))
	|    (((unsigned long) (field[1])) << 8)
	|    (((unsigned long) (field[2])) << 16);

    case 4:
      return  ((unsigned long) (field[0]))
	|    (((unsigned long) (field[1])) << 8)
	|    (((unsigned long) (field[2])) << 16)
	|    (((unsigned long) (field[3])) << 24);

    case 5:
      if (sizeof (elf_vma) == 8)
	return  ((elf_vma) (field[0]))
	  |    (((elf_vma) (field[1])) << 8)
	  |    (((elf_vma) (field[2])) << 16)
	  |    (((elf_vma) (field[3])) << 24)
	  |    (((elf_vma) (field[4])) << 32);
      else if (sizeof (elf_vma) == 4)
	/* We want to extract data from an 8 byte wide field and
	   place it into a 4 byte wide field.  Since this is a little
	   endian source we can just use the 4 byte extraction code.  */
	return  ((unsigned long) (field[0]))
	  |    (((unsigned long) (field[1])) << 8)
	  |    (((unsigned long) (field[2])) << 16)
	  |    (((unsigned long) (field[3])) << 24);
      /* Fall through.  */

    case 6:
      if (sizeof (elf_vma) == 8)
	return  ((elf_vma) (field[0]))
	  |    (((elf_vma) (field[1])) << 8)
	  |    (((elf_vma) (field[2])) << 16)
	  |    (((elf_vma) (field[3])) << 24)
	  |    (((elf_vma) (field[4])) << 32)
	  |    (((elf_vma) (field[5])) << 40);
      else if (sizeof (elf_vma) == 4)
	/* We want to extract data from an 8 byte wide field and
	   place it into a 4 byte wide field.  Since this is a little
	   endian source we can just use the 4 byte extraction code.  */
	return  ((unsigned long) (field[0]))
	  |    (((unsigned long) (field[1])) << 8)
	  |    (((unsigned long) (field[2])) << 16)
	  |    (((unsigned long) (field[3])) << 24);
      /* Fall through.  */

    case 7:
      if (sizeof (elf_vma) == 8)
	return  ((elf_vma) (field[0]))
	  |    (((elf_vma) (field[1])) << 8)
	  |    (((elf_vma) (field[2])) << 16)
	  |    (((elf_vma) (field[3])) << 24)
	  |    (((elf_vma) (field[4])) << 32)
	  |    (((elf_vma) (field[5])) << 40)
	  |    (((elf_vma) (field[6])) << 48);
      else if (sizeof (elf_vma) == 4)
	/* We want to extract data from an 8 byte wide field and
	   place it into a 4 byte wide field.  Since this is a little
	   endian source we can just use the 4 byte extraction code.  */
	return  ((unsigned long) (field[0]))
	  |    (((unsigned long) (field[1])) << 8)
	  |    (((unsigned long) (field[2])) << 16)
	  |    (((unsigned long) (field[3])) << 24);
      /* Fall through.  */

    case 8:
      if (sizeof (elf_vma) == 8)
	return  ((elf_vma) (field[0]))
	  |    (((elf_vma) (field[1])) << 8)
	  |    (((elf_vma) (field[2])) << 16)
	  |    (((elf_vma) (field[3])) << 24)
	  |    (((elf_vma) (field[4])) << 32)
	  |    (((elf_vma) (field[5])) << 40)
	  |    (((elf_vma) (field[6])) << 48)
	  |    (((elf_vma) (field[7])) << 56);
      else if (sizeof (elf_vma) == 4)
	/* We want to extract data from an 8 byte wide field and
	   place it into a 4 byte wide field.  Since this is a little
	   endian source we can just use the 4 byte extraction code.  */
	return  ((unsigned long) (field[0]))
	  |    (((unsigned long) (field[1])) << 8)
	  |    (((unsigned long) (field[2])) << 16)
	  |    (((unsigned long) (field[3])) << 24);
      /* Fall through.  */

    default:
      DBGE("Unhandled data length: %d\n", size);
      exit(-1);
    }
}

elf_vma
byte_get_big_endian (const unsigned char *field, int size)
{
  switch (size)
    {
    case 1:
      return *field;

    case 2:
      return ((unsigned int) (field[1])) | (((int) (field[0])) << 8);

    case 3:
      return ((unsigned long) (field[2]))
	|   (((unsigned long) (field[1])) << 8)
	|   (((unsigned long) (field[0])) << 16);

    case 4:
      return ((unsigned long) (field[3]))
	|   (((unsigned long) (field[2])) << 8)
	|   (((unsigned long) (field[1])) << 16)
	|   (((unsigned long) (field[0])) << 24);

    case 5:
      if (sizeof (elf_vma) == 8)
	return ((elf_vma) (field[4]))
	  |   (((elf_vma) (field[3])) << 8)
	  |   (((elf_vma) (field[2])) << 16)
	  |   (((elf_vma) (field[1])) << 24)
	  |   (((elf_vma) (field[0])) << 32);
      else if (sizeof (elf_vma) == 4)
	{
	  /* Although we are extracting data from an 8 byte wide field,
	     we are returning only 4 bytes of data.  */
	  field += 1;
	  return ((unsigned long) (field[3]))
	    |   (((unsigned long) (field[2])) << 8)
	    |   (((unsigned long) (field[1])) << 16)
	    |   (((unsigned long) (field[0])) << 24);
	}
      /* Fall through.  */

    case 6:
      if (sizeof (elf_vma) == 8)
	return ((elf_vma) (field[5]))
	  |   (((elf_vma) (field[4])) << 8)
	  |   (((elf_vma) (field[3])) << 16)
	  |   (((elf_vma) (field[2])) << 24)
	  |   (((elf_vma) (field[1])) << 32)
	  |   (((elf_vma) (field[0])) << 40);
      else if (sizeof (elf_vma) == 4)
	{
	  /* Although we are extracting data from an 8 byte wide field,
	     we are returning only 4 bytes of data.  */
	  field += 2;
	  return ((unsigned long) (field[3]))
	    |   (((unsigned long) (field[2])) << 8)
	    |   (((unsigned long) (field[1])) << 16)
	    |   (((unsigned long) (field[0])) << 24);
	}
      /* Fall through.  */

    case 7:
      if (sizeof (elf_vma) == 8)
	return ((elf_vma) (field[6]))
	  |   (((elf_vma) (field[5])) << 8)
	  |   (((elf_vma) (field[4])) << 16)
	  |   (((elf_vma) (field[3])) << 24)
	  |   (((elf_vma) (field[2])) << 32)
	  |   (((elf_vma) (field[1])) << 40)
	  |   (((elf_vma) (field[0])) << 48);
      else if (sizeof (elf_vma) == 4)
	{
	  /* Although we are extracting data from an 8 byte wide field,
	     we are returning only 4 bytes of data.  */
	  field += 3;
	  return ((unsigned long) (field[3]))
	    |   (((unsigned long) (field[2])) << 8)
	    |   (((unsigned long) (field[1])) << 16)
	    |   (((unsigned long) (field[0])) << 24);
	}
      /* Fall through.  */

    case 8:
      if (sizeof (elf_vma) == 8)
	return ((elf_vma) (field[7]))
	  |   (((elf_vma) (field[6])) << 8)
	  |   (((elf_vma) (field[5])) << 16)
	  |   (((elf_vma) (field[4])) << 24)
	  |   (((elf_vma) (field[3])) << 32)
	  |   (((elf_vma) (field[2])) << 40)
	  |   (((elf_vma) (field[1])) << 48)
	  |   (((elf_vma) (field[0])) << 56);
      else if (sizeof (elf_vma) == 4)
	{
	  /* Although we are extracting data from an 8 byte wide field,
	     we are returning only 4 bytes of data.  */
	  field += 4;
	  return ((unsigned long) (field[3]))
	    |   (((unsigned long) (field[2])) << 8)
	    |   (((unsigned long) (field[1])) << 16)
	    |   (((unsigned long) (field[0])) << 24);
	}
      /* Fall through.  */

    default:
      DBGE("Unhandled data length: %d\n", size);
      exit(-1);
    }
}

elf_vma
byte_get_signed (const unsigned char *field, int size)
{
  elf_vma x = byte_get (field, size);

  switch (size)
    {
    case 1:
      return (x ^ 0x80) - 0x80;
    case 2:
      return (x ^ 0x8000) - 0x8000;
    case 3:
      return (x ^ 0x800000) - 0x800000;
    case 4:
      return (x ^ 0x80000000) - 0x80000000;
    case 5:
    case 6:
    case 7:
    case 8:
      /* Reads of 5-, 6-, and 7-byte numbers are the result of
         trying to read past the end of a buffer, and will therefore
         not have meaningful values, so we don't try to deal with
         the sign in these cases.  */
      return x;
    default:
      exit(-1);
    }
}

/* Return the high-order 32-bits and the low-order 32-bits
   of an 8-byte value separately.  */

void
byte_get_64 (const unsigned char *field, elf_vma *high, elf_vma *low)
{
  if (byte_get == byte_get_big_endian)
    {
      *high = byte_get_big_endian (field, 4);
      *low = byte_get_big_endian (field + 4, 4);
    }
  else
    {
      *high = byte_get_little_endian (field + 4, 4);
      *low = byte_get_little_endian (field, 4);
    }
  return;
}