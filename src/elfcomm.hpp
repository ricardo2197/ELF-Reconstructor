/* elfcomm.h -- include file of common code for ELF format file.
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

#ifndef _ELFCOMM_H
#define _ELFCOMM_H

typedef unsigned  elf_vma;

extern void (*byte_put) (unsigned char *, elf_vma, int);
extern void byte_put_little_endian (unsigned char *, elf_vma, int);
extern void byte_put_big_endian (unsigned char *, elf_vma, int);

extern elf_vma (*byte_get) (const unsigned char *, int);
extern elf_vma byte_get_signed (const unsigned char *, int);
extern elf_vma byte_get_little_endian (const unsigned char *, int);
extern elf_vma byte_get_big_endian (const unsigned char *, int);
extern void byte_get_64 (const unsigned char *, elf_vma *, elf_vma *);

#define BYTE_PUT(field, val)	byte_put ((unsigned char *)&field, val, sizeof (field))
#define BYTE_GET(field)		byte_get ((const unsigned char *)&field, sizeof (field))
#define BYTE_GET_SIGNED(field)	byte_get_signed (field, sizeof (field))

#endif /* _ELFCOMM_H */