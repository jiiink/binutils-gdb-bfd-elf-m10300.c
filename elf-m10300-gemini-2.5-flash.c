/* Matsushita 10300 specific support for 32-bit ELF
   Copyright (C) 1996-2025 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

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
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/mn10300.h"
#include "libiberty.h"

/* The mn10300 linker needs to keep track of the number of relocs that
   it decides to copy in check_relocs for each symbol.  This is so
   that it can discard PC relative relocs if it doesn't need them when
   linking with -Bsymbolic.  We store the information in a field
   extending the regular ELF linker hash table.  */

struct elf32_mn10300_link_hash_entry
{
  /* The basic elf link hash table entry.  */
  struct elf_link_hash_entry root;

  /* For function symbols, the number of times this function is
     called directly (ie by name).  */
  unsigned int direct_calls;

  /* For function symbols, the size of this function's stack
     (if <= 255 bytes).  We stuff this into "call" instructions
     to this target when it's valid and profitable to do so.

     This does not include stack allocated by movm!  */
  unsigned char stack_size;

  /* For function symbols, arguments (if any) for movm instruction
     in the prologue.  We stuff this value into "call" instructions
     to the target when it's valid and profitable to do so.  */
  unsigned char movm_args;

  /* For function symbols, the amount of stack space that would be allocated
     by the movm instruction.  This is redundant with movm_args, but we
     add it to the hash table to avoid computing it over and over.  */
  unsigned char movm_stack_size;

/* When set, convert all "call" instructions to this target into "calls"
   instructions.  */
#define MN10300_CONVERT_CALL_TO_CALLS 0x1

/* Used to mark functions which have had redundant parts of their
   prologue deleted.  */
#define MN10300_DELETED_PROLOGUE_BYTES 0x2
  unsigned char flags;

  /* Calculated value.  */
  bfd_vma value;

#define GOT_UNKNOWN	0
#define GOT_NORMAL	1
#define GOT_TLS_GD	2
#define GOT_TLS_LD	3
#define GOT_TLS_IE	4
  /* Used to distinguish GOT entries for TLS types from normal GOT entries.  */
  unsigned char tls_type;
};

/* We derive a hash table from the main elf linker hash table so
   we can store state variables and a secondary hash table without
   resorting to global variables.  */
struct elf32_mn10300_link_hash_table
{
  /* The main hash table.  */
  struct elf_link_hash_table root;

  /* A hash table for static functions.  We could derive a new hash table
     instead of using the full elf32_mn10300_link_hash_table if we wanted
     to save some memory.  */
  struct elf32_mn10300_link_hash_table *static_hash_table;

  /* Random linker state flags.  */
#define MN10300_HASH_ENTRIES_INITIALIZED 0x1
  char flags;
  struct
  {
    bfd_signed_vma  refcount;
    bfd_vma	    offset;
    char	    got_allocated;
    char	    rel_emitted;
  } tls_ldm_got;
};

#define elf_mn10300_hash_entry(ent) ((struct elf32_mn10300_link_hash_entry *)(ent))

struct elf_mn10300_obj_tdata
{
  struct elf_obj_tdata root;

  /* tls_type for each local got entry.  */
  char * local_got_tls_type;
};

#define elf_mn10300_tdata(abfd) \
  ((struct elf_mn10300_obj_tdata *) (abfd)->tdata.any)

#define elf_mn10300_local_got_tls_type(abfd) \
  (elf_mn10300_tdata (abfd)->local_got_tls_type)

#ifndef streq
#define streq(a, b) (strcmp ((a),(b)) == 0)
#endif

/* For MN10300 linker hash table.  */

/* Get the MN10300 ELF linker hash table from a link_info structure.  */

#define elf32_mn10300_hash_table(p) \
  ((is_elf_hash_table ((p)->hash)					\
    && elf_hash_table_id (elf_hash_table (p)) == MN10300_ELF_DATA)	\
   ? (struct elf32_mn10300_link_hash_table *) (p)->hash : NULL)

#define elf32_mn10300_link_hash_traverse(table, func, info)		\
  (elf_link_hash_traverse						\
   (&(table)->root,							\
    (bool (*) (struct elf_link_hash_entry *, void *)) (func),		\
    (info)))

static reloc_howto_type elf_mn10300_howto_table[] =
{
  /* Dummy relocation.  Does nothing.  */
  HOWTO (R_MN10300_NONE,
	 0,
	 0,
	 0,
	 false,
	 0,
	 complain_overflow_dont,
	 bfd_elf_generic_reloc,
	 "R_MN10300_NONE",
	 false,
	 0,
	 0,
	 false),
  /* Standard 32 bit reloc.  */
  HOWTO (R_MN10300_32,
	 0,
	 4,
	 32,
	 false,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_MN10300_32",
	 false,
	 0xffffffff,
	 0xffffffff,
	 false),
  /* Standard 16 bit reloc.  */
  HOWTO (R_MN10300_16,
	 0,
	 2,
	 16,
	 false,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_MN10300_16",
	 false,
	 0xffff,
	 0xffff,
	 false),
  /* Standard 8 bit reloc.  */
  HOWTO (R_MN10300_8,
	 0,
	 1,
	 8,
	 false,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_MN10300_8",
	 false,
	 0xff,
	 0xff,
	 false),
  /* Standard 32bit pc-relative reloc.  */
  HOWTO (R_MN10300_PCREL32,
	 0,
	 4,
	 32,
	 true,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_MN10300_PCREL32",
	 false,
	 0xffffffff,
	 0xffffffff,
	 true),
  /* Standard 16bit pc-relative reloc.  */
  HOWTO (R_MN10300_PCREL16,
	 0,
	 2,
	 16,
	 true,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_MN10300_PCREL16",
	 false,
	 0xffff,
	 0xffff,
	 true),
  /* Standard 8 pc-relative reloc.  */
  HOWTO (R_MN10300_PCREL8,
	 0,
	 1,
	 8,
	 true,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_MN10300_PCREL8",
	 false,
	 0xff,
	 0xff,
	 true),

  /* GNU extension to record C++ vtable hierarchy.  */
  HOWTO (R_MN10300_GNU_VTINHERIT, /* type */
	 0,			/* rightshift */
	 0,			/* size */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 NULL,			/* special_function */
	 "R_MN10300_GNU_VTINHERIT", /* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* GNU extension to record C++ vtable member usage */
  HOWTO (R_MN10300_GNU_VTENTRY,	/* type */
	 0,			/* rightshift */
	 0,			/* size */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 NULL,			/* special_function */
	 "R_MN10300_GNU_VTENTRY", /* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */

  /* Standard 24 bit reloc.  */
  HOWTO (R_MN10300_24,
	 0,
	 4,
	 24,
	 false,
	 0,
	 complain_overflow_bitfield,
	 bfd_elf_generic_reloc,
	 "R_MN10300_24",
	 false,
	 0xffffff,
	 0xffffff,
	 false),
  HOWTO (R_MN10300_GOTPC32,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_GOTPC32",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  HOWTO (R_MN10300_GOTPC16,	/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_GOTPC16",	/* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  HOWTO (R_MN10300_GOTOFF32,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_GOTOFF32",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_GOTOFF24,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 24,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_GOTOFF24",	/* name */
	 false,			/* partial_inplace */
	 0xffffff,		/* src_mask */
	 0xffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_GOTOFF16,	/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_GOTOFF16",	/* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_PLT32,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_PLT32",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  HOWTO (R_MN10300_PLT16,	/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_PLT16",	/* name */
	 false,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 true),			/* pcrel_offset */

  HOWTO (R_MN10300_GOT32,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_GOT32",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_GOT24,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 24,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_GOT24",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_GOT16,	/* type */
	 0,			/* rightshift */
	 2,			/* size */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_GOT16",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_COPY,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_COPY",		/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_GLOB_DAT,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_GLOB_DAT",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_JMP_SLOT,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_JMP_SLOT",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_RELATIVE,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_RELATIVE",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_TLS_GD,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_TLS_GD",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_TLS_LD,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_TLS_LD",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_TLS_LDO,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_TLS_LDO",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_TLS_GOTIE,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_TLS_GOTIE",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_TLS_IE,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_TLS_IE",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_TLS_LE,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_TLS_LE",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_TLS_DTPMOD,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_TLS_DTPMOD",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_TLS_DTPOFF,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_TLS_DTPOFF",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_TLS_TPOFF,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* */
	 "R_MN10300_TLS_TPOFF",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_SYM_DIFF,	/* type */
	 0,			/* rightshift */
	 4,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,/* complain_on_overflow */
	 NULL,			/* special handler.  */
	 "R_MN10300_SYM_DIFF",	/* name */
	 false,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO (R_MN10300_ALIGN,	/* type */
	 0,			/* rightshift */
	 1,			/* size */
	 32,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,/* complain_on_overflow */
	 NULL,			/* special handler.  */
	 "R_MN10300_ALIGN",	/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false)			/* pcrel_offset */
};

struct mn10300_reloc_map
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned char elf_reloc_val;
};

static const struct mn10300_reloc_map mn10300_reloc_map[] =
{
  { BFD_RELOC_NONE, R_MN10300_NONE, },
  { BFD_RELOC_32, R_MN10300_32, },
  { BFD_RELOC_16, R_MN10300_16, },
  { BFD_RELOC_8, R_MN10300_8, },
  { BFD_RELOC_32_PCREL, R_MN10300_PCREL32, },
  { BFD_RELOC_16_PCREL, R_MN10300_PCREL16, },
  { BFD_RELOC_8_PCREL, R_MN10300_PCREL8, },
  { BFD_RELOC_24, R_MN10300_24, },
  { BFD_RELOC_VTABLE_INHERIT, R_MN10300_GNU_VTINHERIT },
  { BFD_RELOC_VTABLE_ENTRY, R_MN10300_GNU_VTENTRY },
  { BFD_RELOC_32_GOT_PCREL, R_MN10300_GOTPC32 },
  { BFD_RELOC_16_GOT_PCREL, R_MN10300_GOTPC16 },
  { BFD_RELOC_32_GOTOFF, R_MN10300_GOTOFF32 },
  { BFD_RELOC_MN10300_GOTOFF24, R_MN10300_GOTOFF24 },
  { BFD_RELOC_16_GOTOFF, R_MN10300_GOTOFF16 },
  { BFD_RELOC_32_PLT_PCREL, R_MN10300_PLT32 },
  { BFD_RELOC_16_PLT_PCREL, R_MN10300_PLT16 },
  { BFD_RELOC_MN10300_GOT32, R_MN10300_GOT32 },
  { BFD_RELOC_MN10300_GOT24, R_MN10300_GOT24 },
  { BFD_RELOC_MN10300_GOT16, R_MN10300_GOT16 },
  { BFD_RELOC_MN10300_COPY, R_MN10300_COPY },
  { BFD_RELOC_MN10300_GLOB_DAT, R_MN10300_GLOB_DAT },
  { BFD_RELOC_MN10300_JMP_SLOT, R_MN10300_JMP_SLOT },
  { BFD_RELOC_MN10300_RELATIVE, R_MN10300_RELATIVE },
  { BFD_RELOC_MN10300_TLS_GD, R_MN10300_TLS_GD },
  { BFD_RELOC_MN10300_TLS_LD, R_MN10300_TLS_LD },
  { BFD_RELOC_MN10300_TLS_LDO, R_MN10300_TLS_LDO },
  { BFD_RELOC_MN10300_TLS_GOTIE, R_MN10300_TLS_GOTIE },
  { BFD_RELOC_MN10300_TLS_IE, R_MN10300_TLS_IE },
  { BFD_RELOC_MN10300_TLS_LE, R_MN10300_TLS_LE },
  { BFD_RELOC_MN10300_TLS_DTPMOD, R_MN10300_TLS_DTPMOD },
  { BFD_RELOC_MN10300_TLS_DTPOFF, R_MN10300_TLS_DTPOFF },
  { BFD_RELOC_MN10300_TLS_TPOFF, R_MN10300_TLS_TPOFF },
  { BFD_RELOC_MN10300_SYM_DIFF, R_MN10300_SYM_DIFF },
  { BFD_RELOC_MN10300_ALIGN, R_MN10300_ALIGN }
};

/* Create the GOT section.  */

static asection *
create_and_align_section(bfd *abfd, const char *name, flagword flags, int alignment)
{
  asection *section = bfd_make_section_anyway_with_flags(abfd, name, flags);
  if (section == NULL) {
    return NULL;
  }
  if (!bfd_set_section_alignment(section, alignment)) {
    return NULL;
  }
  return section;
}

static bool
_bfd_mn10300_elf_create_got_section (bfd * abfd,
				     struct bfd_link_info * info)
{
  const struct elf_backend_data *bed = get_elf_backend_data(abfd);
  struct elf_link_hash_table *htab = elf_hash_table(info);
  asection *current_section;
  struct elf_link_hash_entry *current_hash_entry;
  flagword common_section_flags;
  flagword plt_section_flags;
  int pointer_alignment;

  if (htab->sgot != NULL)
    return true;

  switch (bed->s->arch_size)
    {
    case 32:
      pointer_alignment = 2;
      break;
    case 64:
      pointer_alignment = 3;
      break;
    default:
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  common_section_flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY
                          | SEC_LINKER_CREATED);

  plt_section_flags = common_section_flags | SEC_CODE;
  if (bed->plt_not_loaded) {
    plt_section_flags &= ~(SEC_LOAD | SEC_HAS_CONTENTS);
  }
  if (bed->plt_readonly) {
    plt_section_flags |= SEC_READONLY;
  }

  current_section = create_and_align_section(abfd, ".plt", plt_section_flags, bed->plt_alignment);
  if (current_section == NULL) {
    return false;
  }
  htab->splt = current_section;

  if (bed->want_plt_sym)
    {
      current_hash_entry = _bfd_elf_define_linkage_sym(abfd, info, current_section,
                                                       "_PROCEDURE_LINKAGE_TABLE_");
      if (current_hash_entry == NULL) {
	return false;
      }
      htab->hplt = current_hash_entry;
    }

  current_section = create_and_align_section(abfd, ".got", common_section_flags, pointer_alignment);
  if (current_section == NULL) {
    return false;
  }
  htab->sgot = current_section;

  if (bed->want_got_plt)
    {
      current_section = create_and_align_section(abfd, ".got.plt", common_section_flags, pointer_alignment);
      if (current_section == NULL) {
	return false;
      }
      htab->sgotplt = current_section;
    }

  current_hash_entry = _bfd_elf_define_linkage_sym(abfd, info, current_section, "_GLOBAL_OFFSET_TABLE_");
  if (current_hash_entry == NULL) {
    return false;
  }
  htab->hgot = current_hash_entry;

  current_section->size += bed->got_header_size;

  return true;
}

static const reloc_howto_type *
bfd_elf32_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 bfd_reloc_code_real_type code)
{
  size_t i;
  size_t count = ARRAY_SIZE (mn10300_reloc_map);

  for (i = 0; i < count; ++i)
    if (mn10300_reloc_map[i].bfd_reloc_val == code)
      return &elf_mn10300_howto_table[mn10300_reloc_map[i].elf_reloc_val];

  return NULL;
}

static reloc_howto_type *
bfd_elf32_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 const char *r_name)
{
  if (r_name == NULL)
    return NULL;

  unsigned int i;

  for (i = ARRAY_SIZE (elf_mn10300_howto_table); i--;)
    if (elf_mn10300_howto_table[i].name != NULL
	&& strcasecmp (elf_mn10300_howto_table[i].name, r_name) == 0)
      return elf_mn10300_howto_table + i;

  return NULL;
}

/* Set the howto pointer for an MN10300 ELF reloc.  */

static bool
mn10300_info_to_howto (bfd *abfd,
		       arelent *cache_ptr,
		       Elf_Internal_Rela *dst)
{
  unsigned int r_type;

  if (abfd == NULL || cache_ptr == NULL || dst == NULL)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return false;
    }

  r_type = ELF32_R_TYPE (dst->r_info);
  if (r_type >= R_MN10300_MAX)
    {
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }
  cache_ptr->howto = elf_mn10300_howto_table + r_type;
  return true;
}

static int
elf_mn10300_tls_transition (struct bfd_link_info *	  info,
			    int				  r_type,
			    struct elf_link_hash_entry *  h,
			    asection *			  sec,
			    bool			  counting)
{
  if (r_type == R_MN10300_TLS_GD
      && h != NULL
      && elf_mn10300_hash_entry (h)->tls_type == GOT_TLS_IE)
    return R_MN10300_TLS_GOTIE;

  if (bfd_link_pic (info))
    return r_type;

  if (! (sec->flags & SEC_CODE))
    return r_type;

  bool is_local;
  bool dynamic_sections_created = elf_hash_table (info)->dynamic_sections_created;

  if (!counting && h != NULL && !dynamic_sections_created)
    is_local = true;
  else
    is_local = SYMBOL_CALLS_LOCAL (info, h);

  switch (r_type)
    {
    case R_MN10300_TLS_GD:
      return is_local ? R_MN10300_TLS_LE : R_MN10300_TLS_GOTIE;
    case R_MN10300_TLS_LD:
      return R_MN10300_NONE;
    case R_MN10300_TLS_LDO:
      return R_MN10300_TLS_LE;
    case R_MN10300_TLS_IE:
    case R_MN10300_TLS_GOTIE:
      return is_local ? R_MN10300_TLS_LE : r_type;
    default:
      return r_type;
    }
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma
dtpoff (struct bfd_link_info * info, bfd_vma address)
{
  if (info == NULL)
    return 0;

  struct elf_link_hash_table *htab = elf_hash_table (info);

  if (htab == NULL)
    return 0;

  if (htab->tls_sec == NULL)
    return 0;

  return address - htab->tls_sec->vma;
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma
tpoff (struct bfd_link_info * info, bfd_vma address)
{
  const struct elf_link_hash_table *htab = elf_hash_table (info);
  const struct bfd_section *tls_sec = htab->tls_sec;

  if (tls_sec == NULL)
    {
      return 0;
    }

  bfd_vma tls_segment_end_address = htab->tls_size + tls_sec->vma;

  return address - tls_segment_end_address;
}

/* Returns nonzero if there's a R_MN10300_PLT32 reloc that we now need
   to skip, after this one.  The actual value is the offset between
   this reloc and the PLT reloc.  */

static void
write_mn10300_six_byte_nop (bfd_byte *dest)
{
  static const bfd_byte nop_bytes[] = { 0xFC, 0xE4, 0x00, 0x00, 0x00, 0x00 };
  memcpy (dest, nop_bytes, sizeof(nop_bytes));
}

static void
write_mn10300_seven_byte_nop (bfd_byte *dest)
{
  static const bfd_byte nop_bytes[] = { 0xFE, 0x19, 0x22, 0x00, 0x00, 0x00, 0x00 };
  memcpy (dest, nop_bytes, sizeof(nop_bytes));
}

static void
write_mov_indir_x_a2_an (bfd_byte *dest, unsigned int reg_idx)
{
  static const bfd_byte instr_base[] = { 0xFC, 0x20, 0x00, 0x00, 0x00, 0x00 };
  memcpy(dest, instr_base, sizeof(instr_base));
  dest[1] |= reg_idx;
}

static void
write_add_e2_a0 (bfd_byte *dest)
{
  static const bfd_byte instr_bytes[] = { 0xF9, 0x78, 0x28 };
  memcpy (dest, instr_bytes, sizeof(instr_bytes));
}

static void
write_mov_x_tpoff_a0 (bfd_byte *dest)
{
  static const bfd_byte instr_bytes[] = { 0xFC, 0xDC, 0x00, 0x00, 0x00, 0x00 };
  memcpy (dest, instr_bytes, sizeof(instr_bytes));
}

static void
write_mov_e2_a0 (bfd_byte *dest)
{
  static const bfd_byte instr_bytes[] = { 0xF5, 0x88 };
  memcpy (dest, instr_bytes, sizeof(instr_bytes));
}

#define TLS_PAIR(r1,r2) ((r1) * R_MN10300_MAX + (r2))

static int
mn10300_do_tls_transition (bfd *	 input_bfd,
			   unsigned int	 r_type,
			   unsigned int	 tls_r_type,
			   bfd_byte *	 contents,
			   bfd_vma	 offset)
{
  bfd_byte *op = contents + offset;
  int gotreg = 0;
  int ret_val = 0;

  if (r_type == R_MN10300_TLS_GD
      || r_type == R_MN10300_TLS_LD)
    {
      op -= 2;
      if (bfd_get_8 (input_bfd, op) != 0xFC || bfd_get_8 (input_bfd, op + 1) != 0xCC)
        {
          _bfd_error_handler
            (_("%pB: Expected 'mov imm,d0' instruction at TLS transition, got 0x%02x%02x"),
             input_bfd, bfd_get_8 (input_bfd, op), bfd_get_8 (input_bfd, op + 1));
          return -1;
        }
      if (bfd_get_8 (input_bfd, op + 6) != 0xF1)
        {
          _bfd_error_handler
            (_("%pB: Expected 'add aN,d0' instruction at TLS transition, got 0x%02x"),
             input_bfd, bfd_get_8 (input_bfd, op + 6));
          return -1;
        }
      gotreg = (bfd_get_8 (input_bfd, op + 7) & 0x0c) >> 2;
      if (bfd_get_8 (input_bfd, op + 8) != 0xDD)
        {
          _bfd_error_handler
            (_("%pB: Expected 'Call' instruction at TLS transition, got 0x%02x"),
             input_bfd, bfd_get_8 (input_bfd, op + 8));
          return -1;
        }
    }

  switch (TLS_PAIR (r_type, tls_r_type))
    {
    case TLS_PAIR (R_MN10300_TLS_GD, R_MN10300_TLS_GOTIE):
      {
	    write_mov_indir_x_a2_an (op, gotreg);
	    write_add_e2_a0 (op + 6);
	    write_mn10300_six_byte_nop (op + 9);
      }
      ret_val = 7;
      break;

    case TLS_PAIR (R_MN10300_TLS_GD, R_MN10300_TLS_LE):
      {
	    write_mov_x_tpoff_a0 (op);
	    write_add_e2_a0 (op + 6);
	    write_mn10300_six_byte_nop (op + 9);
      }
      ret_val = 7;
      break;

    case TLS_PAIR (R_MN10300_TLS_LD, R_MN10300_NONE):
      {
	    write_mov_e2_a0 (op);
	    write_mn10300_six_byte_nop (op + 2);
	    write_mn10300_seven_byte_nop (op + 8);
      }
      ret_val = 7;
      break;

    case TLS_PAIR (R_MN10300_TLS_LDO, R_MN10300_TLS_LE):
      ret_val = 0;
      break;

    case TLS_PAIR (R_MN10300_TLS_IE, R_MN10300_TLS_LE):
      if (op[-2] == 0xFC)
	    {
	      bfd_byte *instr_start = op - 2;
	      if ((instr_start[1] & 0xFC) == 0xA4)
            {
              instr_start[1] = (instr_start[1] & 0x03) | 0xCC;
            }
	      else
            {
              instr_start[1] = (instr_start[1] & 0x03) | 0xDC;
            }
	    }
      else if (op[-3] == 0xFE)
	    {
	      op[-2] = 0x08;
	    }
      else
	    {
	      _bfd_error_handler
	        (_("%pB: Unsupported TLS_IE to TLS_LE transition instruction pattern at 0x%lx"),
	         input_bfd, (unsigned long)offset);
	      return -1;
	    }
      ret_val = 0;
      break;

    case TLS_PAIR (R_MN10300_TLS_GOTIE, R_MN10300_TLS_LE):
      if (op[-2] == 0xFC)
	    {
	      bfd_byte *instr_start = op - 2;
	      if ((instr_start[1] & 0xF0) == 0x00)
            {
              instr_start[1] = ((instr_start[1] & 0x0C) >> 2) | 0xCC;
            }
	      else
            {
              instr_start[1] = ((instr_start[1] & 0x0C) >> 2) | 0xDC;
            }
	    }
      else if (op[-3] == 0xFE)
	    {
	      op[-2] = 0x08;
	    }
      else
	    {
	      _bfd_error_handler
	        (_("%pB: Unsupported TLS_GOTIE to TLS_LE transition instruction pattern at 0x%lx"),
	         input_bfd, (unsigned long)offset);
	      return -1;
	    }
      ret_val = 0;
      break;

    default:
      _bfd_error_handler
	(_("%pB: unsupported transition from %s to %s"),
	 input_bfd,
	 elf_mn10300_howto_table[r_type].name,
	 elf_mn10300_howto_table[tls_r_type].name);
      return -1;
    }
#undef TLS_PAIR
  return ret_val;
}

/* Look through the relocs for a section during the first phase.
   Since we don't do .gots or .plts, we just need to consider the
   virtual table relocs for gc.  */

static bool is_got_creation_reloc(unsigned int r_type);
static bool handle_got_relocation(bfd *abfd,
                                  struct bfd_link_info *info,
                                  struct elf32_mn10300_link_hash_table *htab,
                                  struct elf_link_hash_entry *h,
                                  unsigned int r_type,
                                  unsigned long r_symndx,
                                  Elf_Internal_Shdr *symtab_hdr,
                                  bfd_vma **local_got_offsets_ptr,
                                  asection **sgot_ptr,
                                  asection **srelgot_ptr);
static bool handle_shared_relocs(bfd *abfd,
                                 struct bfd_link_info *info,
                                 asection *sec,
                                 struct elf_link_hash_entry *h,
                                 unsigned long r_symndx,
                                 Elf_Internal_Shdr *symtab_hdr,
                                 Elf_Internal_Sym **isymbuf_ptr,
                                 asection **sreloc_ptr,
                                 bfd *dynobj);

static bool
is_got_creation_reloc(unsigned int r_type)
{
  switch (r_type)
    {
    case R_MN10300_GOT32:
    case R_MN10300_GOT24:
    case R_MN10300_GOT16:
    case R_MN10300_GOTOFF32:
    case R_MN10300_GOTOFF24:
    case R_MN10300_GOTOFF16:
    case R_MN10300_GOTPC32:
    case R_MN10300_GOTPC16:
    case R_MN10300_TLS_GD:
    case R_MN10300_TLS_LD:
    case R_MN10300_TLS_GOTIE:
    case R_MN10300_TLS_IE:
      return true;
    default:
      return false;
    }
}

static bool
handle_got_relocation(bfd *abfd,
                      struct bfd_link_info *info,
                      struct elf32_mn10300_link_hash_table *htab,
                      struct elf_link_hash_entry *h,
                      unsigned int r_type,
                      unsigned long r_symndx,
                      Elf_Internal_Shdr *symtab_hdr,
                      bfd_vma **local_got_offsets_ptr,
                      asection **sgot_ptr,
                      asection **srelgot_ptr)
{
  int tls_type = GOT_NORMAL;

  switch (r_type)
    {
    case R_MN10300_TLS_LD:
      htab->tls_ldm_got.refcount++;
      tls_type = GOT_TLS_LD;
      if (htab->tls_ldm_got.got_allocated)
        return true;
      break;

    case R_MN10300_TLS_IE:
    case R_MN10300_TLS_GOTIE:
      if (bfd_link_pic (info))
        info->flags |= DF_STATIC_TLS;
      tls_type = GOT_TLS_IE;
      break;

    case R_MN10300_TLS_GD:
      tls_type = GOT_TLS_GD;
      break;

    default:
      break;
    }

  if (*sgot_ptr == NULL || *srelgot_ptr == NULL)
    {
      _bfd_error_handler(_("Internal error: GOT or REL.GOT section not found for GOT relocation."));
      return false;
    }

  if (r_type == R_MN10300_TLS_LD)
    {
      htab->tls_ldm_got.offset = (*sgot_ptr)->size;
      htab->tls_ldm_got.got_allocated++;
    }
  else if (h != NULL)
    {
      struct elf32_mn10300_link_hash_entry *mn10300_h = elf_mn10300_hash_entry(h);
      if (mn10300_h->tls_type != tls_type && mn10300_h->tls_type != GOT_UNKNOWN)
        {
          if (tls_type == GOT_TLS_IE && mn10300_h->tls_type == GOT_TLS_GD)
            ; /* No change - this is ok.  */
          else if (tls_type == GOT_TLS_GD && mn10300_h->tls_type == GOT_TLS_IE)
            tls_type = GOT_TLS_IE; /* Transition GD->IE.  */
          else
            {
              _bfd_error_handler
                /* xgettext:c-format */
                (_("%pB: %s' accessed both as normal and thread local symbol"),
                 abfd, h->root.root.string);
              return false;
            }
        }

      mn10300_h->tls_type = tls_type;

      if (h->got.offset != (bfd_vma) -1)
        return true;

      h->got.offset = (*sgot_ptr)->size;

      if (ELF_ST_VISIBILITY (h->other) != STV_INTERNAL && h->dynindx == -1)
        {
          if (! bfd_elf_link_record_dynamic_symbol (info, h))
            return false;
        }

      (*srelgot_ptr)->size += sizeof (Elf32_External_Rela);
      if (r_type == R_MN10300_TLS_GD)
        (*srelgot_ptr)->size += sizeof (Elf32_External_Rela);
    }
  else /* Local symbol */
    {
      if (*local_got_offsets_ptr == NULL)
        {
          size_t entry_size = sizeof (bfd_vma) + sizeof (char);
          size_t total_size;
          if (symtab_hdr->sh_info > 0 && SIZE_MAX / symtab_hdr->sh_info < entry_size) {
            _bfd_error_handler(_("Allocation size overflow for local GOT offsets."));
            return false;
          }
          total_size = symtab_hdr->sh_info * entry_size;

          *local_got_offsets_ptr = bfd_alloc (abfd, total_size);

          if (*local_got_offsets_ptr == NULL)
            return false;

          elf_local_got_offsets (abfd) = *local_got_offsets_ptr;
          elf_mn10300_local_got_tls_type (abfd) = (char *) (*local_got_offsets_ptr + symtab_hdr->sh_info);

          for (unsigned int i = 0; i < symtab_hdr->sh_info; i++)
            (*local_got_offsets_ptr)[i] = (bfd_vma) -1;
        }

      if ((*local_got_offsets_ptr)[r_symndx] != (bfd_vma) -1)
        return true;

      (*local_got_offsets_ptr)[r_symndx] = (*sgot_ptr)->size;

      if (bfd_link_pic (info))
        {
          (*srelgot_ptr)->size += sizeof (Elf32_External_Rela);
          if (r_type == R_MN10300_TLS_GD)
            (*srelgot_ptr)->size += sizeof (Elf32_External_Rela);
        }

      elf_mn10300_local_got_tls_type (abfd) [r_symndx] = tls_type;
    }

  (*sgot_ptr)->size += 4;
  if (r_type == R_MN10300_TLS_GD || r_type == R_MN10300_TLS_LD)
    (*sgot_ptr)->size += 4;

  return true;
}

static bool
handle_shared_relocs(bfd *abfd,
                     struct bfd_link_info *info,
                     asection *sec,
                     struct elf_link_hash_entry *h,
                     unsigned long r_symndx,
                     Elf_Internal_Shdr *symtab_hdr,
                     Elf_Internal_Sym **isymbuf_ptr,
                     asection **sreloc_ptr,
                     bfd *dynobj)
{
  if (bfd_link_pic (info) && (sec->flags & SEC_ALLOC) != 0)
    {
      asection * sym_section = NULL;

      if (h == NULL)
        {
          Elf_Internal_Sym * isym;

          if (*isymbuf_ptr == NULL)
            {
              *isymbuf_ptr = bfd_elf_get_elf_syms (abfd, symtab_hdr, symtab_hdr->sh_info, 0, NULL, NULL, NULL);
              if (*isymbuf_ptr == NULL)
                return false;
            }
          isym = *isymbuf_ptr + r_symndx;
          if (isym->st_shndx == SHN_ABS)
            sym_section = bfd_abs_section_ptr;
        }
      else
        {
          if (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak)
            sym_section = h->root.u.def.section;
        }

      if (sym_section != bfd_abs_section_ptr)
        {
          if (*sreloc_ptr == NULL)
            {
              *sreloc_ptr = _bfd_elf_make_dynamic_reloc_section(sec, dynobj, 2, abfd, /*rela?*/ true);
              if (*sreloc_ptr == NULL)
                return false;
            }
          (*sreloc_ptr)->size += sizeof (Elf32_External_Rela);
        }
    }
  return true;
}

static bool
mn10300_elf_check_relocs (bfd *abfd,
			  struct bfd_link_info *info,
			  asection *sec,
			  const Elf_Internal_Rela *relocs)
{
  struct elf32_mn10300_link_hash_table * htab = elf32_mn10300_hash_table (info);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (abfd);
  bfd *dynobj = elf_hash_table (info)->dynobj;
  bfd_vma *local_got_offsets = elf_local_got_offsets (abfd);
  const Elf_Internal_Rela *rel_end = relocs + sec->reloc_count;

  asection *sgot = NULL;
  asection *srelgot = NULL;
  asection *sreloc = NULL;

  Elf_Internal_Sym * isymbuf_for_local_syms = NULL;
  bool sym_diff_reloc_seen = false;
  bool result = true;

  if (bfd_link_relocatable (info))
    return true;

  if (dynobj != NULL)
    {
      sgot = htab->root.sgot;
      srelgot = htab->root.srelgot;
      if (sgot == NULL || srelgot == NULL)
        {
          _bfd_error_handler(_("Internal error: Existing dynobj but GOT/REL.GOT sections are null."));
          return false;
        }
    }

  for (const Elf_Internal_Rela *rel = relocs; rel < rel_end; rel++)
    {
      struct elf_link_hash_entry *h = NULL;
      unsigned long r_symndx = ELF32_R_SYM (rel->r_info);
      unsigned int r_type = ELF32_R_TYPE (rel->r_info);

      if (r_symndx >= symtab_hdr->sh_info)
	{
	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h != NULL && (h->root.type == bfd_link_hash_indirect || h->root.type == bfd_link_hash_warning))
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;
	}

      r_type = elf_mn10300_tls_transition (info, r_type, h, sec, true);

      if (dynobj == NULL && is_got_creation_reloc(r_type))
        {
          elf_hash_table (info)->dynobj = dynobj = abfd;
          if (! _bfd_mn10300_elf_create_got_section (dynobj, info))
            {
              result = false;
              break;
            }
          sgot = htab->root.sgot;
          srelgot = htab->root.srelgot;
        }

      bool requires_shared_relocs = false;

      switch (r_type)
	{
	case R_MN10300_GNU_VTINHERIT:
	  if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
	    {
	      result = false;
	      break;
	    }
	  break;

	case R_MN10300_GNU_VTENTRY:
	  if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
	    {
	      result = false;
	      break;
	    }
	  break;

	case R_MN10300_TLS_LD:
	case R_MN10300_TLS_IE:
	case R_MN10300_TLS_GOTIE:
	case R_MN10300_TLS_GD:
	case R_MN10300_GOT32:
	case R_MN10300_GOT24:
	case R_MN10300_GOT16:
	  if (!handle_got_relocation(abfd, info, htab, h, r_type, r_symndx, symtab_hdr,
                                     &local_got_offsets, &sgot, &srelgot))
	    {
	      result = false;
	      break;
	    }
	  requires_shared_relocs = true;
	  break;

	case R_MN10300_PLT32:
	case R_MN10300_PLT16:
	  if (h == NULL
	      || ELF_ST_VISIBILITY (h->other) == STV_INTERNAL
	      || ELF_ST_VISIBILITY (h->other) == STV_HIDDEN)
	    break;
	  h->needs_plt = 1;
	  break;

	case R_MN10300_24:
	case R_MN10300_16:
	case R_MN10300_8:
	case R_MN10300_PCREL32:
	case R_MN10300_PCREL16:
	case R_MN10300_PCREL8:
	  if (h != NULL)
	    h->non_got_ref = 1;
	  break;

	case R_MN10300_32:
	  if (h != NULL)
	    h->non_got_ref = 1;
	  requires_shared_relocs = true;
	  break;

	case R_MN10300_SYM_DIFF:
	  sym_diff_reloc_seen = true;
	  break;

	default:
	  break;
	}

      if (requires_shared_relocs && ! sym_diff_reloc_seen)
	{
	  if (!handle_shared_relocs(abfd, info, sec, h, r_symndx, symtab_hdr,
                                    &isymbuf_for_local_syms, &sreloc, dynobj))
	    {
	      result = false;
	      break;
	    }
	}

      if (r_type != R_MN10300_SYM_DIFF)
	sym_diff_reloc_seen = false;
    }

  if (isymbuf_for_local_syms != NULL
      && symtab_hdr->contents != (unsigned char *) isymbuf_for_local_syms)
    free (isymbuf_for_local_syms);

  return result;
}

/* Return the section that should be marked against GC for a given
   relocation.  */

static asection *
mn10300_elf_gc_mark_hook (asection *sec,
			  struct bfd_link_info *info,
			  Elf_Internal_Rela *rel,
			  struct elf_link_hash_entry *h,
			  Elf_Internal_Sym *sym)
{
  if (h != NULL && rel != NULL)
    {
      unsigned int r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == R_MN10300_GNU_VTINHERIT || r_type == R_MN10300_GNU_VTENTRY)
        {
          return NULL;
        }
    }

  return _bfd_elf_gc_mark_hook (sec, info, rel, h, sym);
}

/* Perform a relocation as part of a final link.  */

static bfd_reloc_status_type
mn10300_elf_final_link_relocate (reloc_howto_type *howto,
				 bfd *input_bfd,
				 bfd *output_bfd ATTRIBUTE_UNUSED,
				 asection *input_section,
				 bfd_byte *contents,
				 bfd_vma offset,
				 bfd_vma value,
				 bfd_vma addend,
				 struct elf_link_hash_entry * h,
				 unsigned long symndx,
				 struct bfd_link_info *info,
				 asection *sym_sec ATTRIBUTE_UNUSED,
				 int is_local ATTRIBUTE_UNUSED)
{
  struct elf32_mn10300_link_hash_table * htab = elf32_mn10300_hash_table (info);
  static asection *  sym_diff_section;
  static bfd_vma     sym_diff_value;
  bool is_sym_diff_reloc;
  unsigned long r_type = howto->type;
  bfd_byte * hit_data = contents + offset;
  bfd *      dynobj;
  asection * sgot;
  asection * splt;
  asection * sreloc;

  dynobj = elf_hash_table (info)->dynobj;
  sgot   = NULL;
  splt   = NULL;
  sreloc = NULL;

  switch (r_type)
    {
    case R_MN10300_24:
    case R_MN10300_16:
    case R_MN10300_8:
    case R_MN10300_PCREL8:
    case R_MN10300_PCREL16:
    case R_MN10300_PCREL32:
    case R_MN10300_GOTOFF32:
    case R_MN10300_GOTOFF24:
    case R_MN10300_GOTOFF16:
      if (bfd_link_pic (info)
	  && (input_section->flags & SEC_ALLOC) != 0
	  && h != NULL
	  && ! SYMBOL_REFERENCES_LOCAL (info, h))
	return bfd_reloc_dangerous;
      /* Fall through.  */
    case R_MN10300_GOT32:
      if (bfd_link_pic (info)
	  && (input_section->flags & SEC_ALLOC) != 0
	  && h != NULL
	  && ELF_ST_VISIBILITY (h->other) == STV_PROTECTED
	  && (h->type == STT_FUNC || h->type == STT_GNU_IFUNC)
	  && ! SYMBOL_REFERENCES_LOCAL (info, h))
	return bfd_reloc_dangerous;
    }

  is_sym_diff_reloc = false;
  if (sym_diff_section != NULL)
    {
      BFD_ASSERT (sym_diff_section == input_section);

      switch (r_type)
	{
	case R_MN10300_32:
	case R_MN10300_24:
	case R_MN10300_16:
	case R_MN10300_8:
	  value -= sym_diff_value;
	  if (r_type == R_MN10300_32
	      && value == 0
	      && strcmp (input_section->name, ".debug_loc") == 0)
	    value = 1;
	  sym_diff_section = NULL;
	  is_sym_diff_reloc = true;
	  break;

	default:
	  sym_diff_section = NULL;
	  break;
	}
    }

#define MN10300_S8_MAX 0x7f
#define MN10300_S8_MIN -0x80
#define MN10300_S16_MAX 0x7fff
#define MN10300_S16_MIN -0x8000
#define MN10300_S24_MAX 0x7fffff
#define MN10300_S24_MIN -0x800000

  static void
  mn10300_put_24 (bfd *abfd, bfd_vma val, bfd_byte *loc)
  {
    bfd_put_8 (abfd, val & 0xff, loc);
    bfd_put_8 (abfd, (val >> 8) & 0xff, loc + 1);
    bfd_put_8 (abfd, (val >> 16) & 0xff, loc + 2);
  }

  static bfd_reloc_status_type
  mn10300_check_and_put_value (bfd *abfd, bfd_byte *loc, bfd_vma val,
			       unsigned long r_t)
  {
    switch (r_t)
      {
      case R_MN10300_8:
      case R_MN10300_PCREL8:
	if ((long) val > MN10300_S8_MAX || (long) val < MN10300_S8_MIN)
	  return bfd_reloc_overflow;
	bfd_put_8 (abfd, val, loc);
	break;
      case R_MN10300_16:
      case R_MN10300_PCREL16:
      case R_MN10300_GOTPC16:
      case R_MN10300_GOTOFF16:
      case R_MN10300_PLT16:
      case R_MN10300_GOT16:
	if ((long) val > MN10300_S16_MAX || (long) val < MN10300_S16_MIN)
	  return bfd_reloc_overflow;
	bfd_put_16 (abfd, val, loc);
	break;
      case R_MN10300_24:
      case R_MN10300_GOTOFF24:
      case R_MN10300_GOT24:
	if ((long) val > MN10300_S24_MAX || (long) val < MN10300_S24_MIN)
	  return bfd_reloc_overflow;
	mn10300_put_24 (abfd, val, loc);
	break;
      case R_MN10300_32:
      case R_MN10300_PCREL32:
      case R_MN10300_GOTPC32:
      case R_MN10300_GOTOFF32:
      case R_MN10300_PLT32:
      case R_MN10300_TLS_LDO:
      case R_MN10300_TLS_LE:
      case R_MN10300_TLS_LD:
      case R_MN10300_TLS_GOTIE:
      case R_MN10300_TLS_GD:
      case R_MN10300_TLS_IE:
      case R_MN10300_GOT32:
	bfd_put_32 (abfd, val, loc);
	break;
      default:
	return bfd_reloc_notsupported;
      }
    return bfd_reloc_ok;
  }

  static bfd_reloc_status_type
  mn10300_handle_rela_32_pic (bfd *input_bfd_h, bfd *output_bfd_h,
			      struct bfd_link_info *info_ptr,
			      asection *input_sec, bfd_vma offset_val,
			      bfd_vma val, bfd_vma addend_val,
			      struct elf_link_hash_entry *h_ptr,
			      asection **sreloc_ptr,
			      int *skip_local_write)
  {
    Elf_Internal_Rela outrel;
    *skip_local_write = 0;

    if (*sreloc_ptr == NULL)
      {
	*sreloc_ptr = _bfd_elf_get_dynamic_reloc_section (input_bfd_h, input_sec, /*rela?*/ true);
	if (*sreloc_ptr == NULL)
	  return bfd_reloc_error;
      }

    outrel.r_offset = _bfd_elf_section_offset (input_bfd_h, info_ptr, input_sec, offset_val);
    if (outrel.r_offset == (bfd_vma) -1)
      return bfd_reloc_ok;

    outrel.r_offset += (input_sec->output_section->vma + input_sec->output_offset);

    if (h_ptr == NULL || SYMBOL_REFERENCES_LOCAL (info_ptr, h_ptr))
      {
	outrel.r_info = ELF32_R_INFO (0, R_MN10300_RELATIVE);
	outrel.r_addend = val + addend_val;
	bfd_elf32_swap_reloca_out (output_bfd_h, &outrel,
				   (bfd_byte *) (((Elf32_External_Rela *) (*sreloc_ptr)->contents)
						 + (*sreloc_ptr)->reloc_count));
	++ (*sreloc_ptr)->reloc_count;
      }
    else
      {
	BFD_ASSERT (h_ptr->dynindx != (unsigned int) -1);
	outrel.r_info = ELF32_R_INFO (h_ptr->dynindx, R_MN10300_32);
	outrel.r_addend = addend_val;
	bfd_elf32_swap_reloca_out (output_bfd_h, &outrel,
				   (bfd_byte *) (((Elf32_External_Rela *) (*sreloc_ptr)->contents)
						 + (*sreloc_ptr)->reloc_count));
	++ (*sreloc_ptr)->reloc_count;
	*skip_local_write = 1;
      }
    return bfd_reloc_ok;
  }

  static bfd_reloc_status_type
  mn10300_emit_tls_ld_reloc (bfd *output_bfd_h,
			     struct elf32_mn10300_link_hash_table *htab_ptr)
  {
    asection *sgot_sec = htab_ptr->root.sgot;
    asection *srelgot_sec = htab_ptr->root.srelgot;
    Elf_Internal_Rela rel;

    BFD_ASSERT (sgot_sec != NULL);
    BFD_ASSERT (srelgot_sec != NULL);

    htab_ptr->tls_ldm_got.rel_emitted++;
    rel.r_offset = (sgot_sec->output_section->vma
		    + sgot_sec->output_offset
		    + htab_ptr->tls_ldm_got.offset);
    bfd_put_32 (output_bfd_h, (bfd_vma) 0, sgot_sec->contents + htab_ptr->tls_ldm_got.offset);
    bfd_put_32 (output_bfd_h, (bfd_vma) 0, sgot_sec->contents + htab_ptr->tls_ldm_got.offset + 4);
    rel.r_info = ELF32_R_INFO (0, R_MN10300_TLS_DTPMOD);
    rel.r_addend = 0;
    bfd_elf32_swap_reloca_out (output_bfd_h, & rel,
			       (bfd_byte *) ((Elf32_External_Rela *) srelgot_sec->contents
					     + srelgot_sec->reloc_count));
    ++ srelgot_sec->reloc_count;

    return bfd_reloc_ok;
  }

  static bfd_reloc_status_type
  mn10300_handle_got_tls_group (bfd *input_bfd_h, bfd *output_bfd_h,
				bfd_byte *hit_data_ptr, bfd_vma val,
				bfd_vma addend_val, unsigned long r_t,
				struct elf_link_hash_entry *h_ptr,
				unsigned long symndx_val,
				struct bfd_link_info *info_ptr,
				struct elf32_mn10300_link_hash_table *htab_ptr)
  {
    asection *sgot_sec = htab_ptr->root.sgot;
    bfd_vma write_val;

    if (elf_hash_table (info_ptr)->dynobj == NULL)
      return bfd_reloc_dangerous;

    if (r_t == R_MN10300_TLS_GD)
      val = dtpoff (info_ptr, val);
    else if (r_t == R_MN10300_TLS_GOTIE)
      val = tpoff (info_ptr, val);

    if (h_ptr != NULL)
      {
	bfd_vma off = h_ptr->got.offset;
	if (off == (bfd_vma) -1)
	  off = 0;

	if (sgot_sec->contents != NULL
	    && (! elf_hash_table (info_ptr)->dynamic_sections_created
		|| SYMBOL_REFERENCES_LOCAL (info_ptr, h_ptr)))
	  bfd_put_32 (output_bfd_h, val, sgot_sec->contents + off);

	write_val = sgot_sec->output_offset + off;
      }
    else
      {
	bfd_vma off = elf_local_got_offsets (input_bfd_h)[symndx_val];

	if (off & 1)
	  bfd_put_32 (output_bfd_h, val, sgot_sec->contents + (off & ~ (bfd_vma) 1));
	else
	  {
	    bfd_put_32 (output_bfd_h, val, sgot_sec->contents + off);

	    if (bfd_link_pic (info_ptr))
	      {
		asection *srelgot_sec = htab_ptr->root.srelgot;
		Elf_Internal_Rela outrel;

		if (srelgot_sec == NULL)
		  return bfd_reloc_error;

		outrel.r_offset = (sgot_sec->output_section->vma
				   + sgot_sec->output_offset
				   + off);
		outrel.r_addend = val;

		switch (r_t)
		  {
		  case R_MN10300_TLS_GD:
		    outrel.r_info = ELF32_R_INFO (0, R_MN10300_TLS_DTPOFF);
		    outrel.r_offset = (sgot_sec->output_section->vma
				       + sgot_sec->output_offset
				       + off + 4);
		    bfd_elf32_swap_reloca_out (output_bfd_h, & outrel,
					       (bfd_byte *) (((Elf32_External_Rela *)
							      srelgot_sec->contents)
							     + srelgot_sec->reloc_count));
		    ++ srelgot_sec->reloc_count;
		    outrel.r_info = ELF32_R_INFO (0, R_MN10300_TLS_DTPMOD);
		    break;
		  case R_MN10300_TLS_GOTIE:
		  case R_MN10300_TLS_IE:
		    outrel.r_info = ELF32_R_INFO (0, R_MN10300_TLS_TPOFF);
		    break;
		  default:
		    outrel.r_info = ELF32_R_INFO (0, R_MN10300_RELATIVE);
		    break;
		  }

		bfd_elf32_swap_reloca_out (output_bfd_h, &outrel,
					   (bfd_byte *) (((Elf32_External_Rela *)
							  srelgot_sec->contents)
							 + srelgot_sec->reloc_count));
		++ srelgot_sec->reloc_count;
		elf_local_got_offsets (input_bfd_h)[symndx_val] |= 1;
	      }
	  }
	write_val = sgot_sec->output_offset + (off & ~(bfd_vma) 1);
      }

    write_val += addend_val;

    if (r_t == R_MN10300_TLS_IE)
      write_val += sgot_sec->output_section->vma;

    return mn10300_check_and_put_value (input_bfd_h, hit_data_ptr, write_val, r_t);
  }

  static bfd_reloc_status_type
  mn10300_handle_plt_reloc (bfd *input_bfd_h, bfd_byte *hit_data_ptr, bfd_vma val,
			    bfd_vma addend_val, unsigned long r_t,
			    asection *input_sec, bfd_vma offset_val,
			    struct elf_link_hash_entry *h_ptr,
			    struct bfd_link_info *info_ptr,
			    struct elf32_mn10300_link_hash_table *htab_ptr)
  {
    asection *splt_sec;

    if (h_ptr != NULL
	&& ELF_ST_VISIBILITY (h_ptr->other) != STV_INTERNAL
	&& ELF_ST_VISIBILITY (h_ptr->other) != STV_HIDDEN
	&& h_ptr->plt.offset != (bfd_vma) -1)
      {
	if (elf_hash_table (info_ptr)->dynobj == NULL)
	  return bfd_reloc_dangerous;

	splt_sec = htab_ptr->root.splt;
	val = (splt_sec->output_section->vma
	       + splt_sec->output_offset
	       + h_ptr->plt.offset) - val;
      }

    val -= (input_sec->output_section->vma + input_sec->output_offset);
    val -= offset_val;
    val += addend_val;

    return mn10300_check_and_put_value (input_bfd_h, hit_data_ptr, val, r_t);
  }


  switch (r_type)
    {
    case R_MN10300_SYM_DIFF:
      BFD_ASSERT (addend == 0);
      sym_diff_section = input_section;
      sym_diff_value = value;
      return bfd_reloc_ok;

    case R_MN10300_ALIGN:
    case R_MN10300_NONE:
      return bfd_reloc_ok;

    case R_MN10300_32:
      if (bfd_link_pic (info)
	  && !is_sym_diff_reloc
	  && sym_sec != bfd_abs_section_ptr
	  && (input_section->flags & SEC_ALLOC) != 0)
	{
	  int skip_local_write = 0;
	  bfd_reloc_status_type status = mn10300_handle_rela_32_pic (
	      input_bfd, output_bfd, info, input_section, offset,
	      value, addend, h, &sreloc, &skip_local_write);
	  if (status != bfd_reloc_ok)
	    return status;
	  if (skip_local_write)
	    return bfd_reloc_ok;
	}
      value += addend;
      return mn10300_check_and_put_value (input_bfd, hit_data, value, r_type);

    case R_MN10300_24:
    case R_MN10300_16:
    case R_MN10300_8:
      value += addend;
      return mn10300_check_and_put_value (input_bfd, hit_data, value, r_type);

    case R_MN10300_PCREL8:
    case R_MN10300_PCREL16:
    case R_MN10300_PCREL32:
      value -= (input_section->output_section->vma
		+ input_section->output_offset);
      value -= offset;
      value += addend;
      return mn10300_check_and_put_value (input_bfd, hit_data, value, r_type);

    case R_MN10300_GNU_VTINHERIT:
    case R_MN10300_GNU_VTENTRY:
      return bfd_reloc_ok;

    case R_MN10300_GOTPC32:
    case R_MN10300_GOTPC16:
      if (dynobj == NULL)
	return bfd_reloc_dangerous;
      value = htab->root.sgot->output_section->vma;
      value -= (input_section->output_section->vma
		+ input_section->output_offset);
      value -= offset;
      value += addend;
      return mn10300_check_and_put_value (input_bfd, hit_data, value, r_type);

    case R_MN10300_GOTOFF32:
    case R_MN10300_GOTOFF24:
    case R_MN10300_GOTOFF16:
      if (dynobj == NULL)
	return bfd_reloc_dangerous;
      value -= htab->root.sgot->output_section->vma;
      value += addend;
      return mn10300_check_and_put_value (input_bfd, hit_data, value, r_type);

    case R_MN10300_PLT32:
    case R_MN10300_PLT16:
      return mn10300_handle_plt_reloc (input_bfd, hit_data, value, addend,
				       r_type, input_section, offset,
				       h, info, htab);

    case R_MN10300_TLS_LDO:
      value = dtpoff (info, value);
      value += addend;
      return mn10300_check_and_put_value (input_bfd, hit_data, value, r_type);

    case R_MN10300_TLS_LE:
      value = tpoff (info, value);
      value += addend;
      return mn10300_check_and_put_value (input_bfd, hit_data, value, r_type);

    case R_MN10300_TLS_LD:
      if (dynobj == NULL)
	return bfd_reloc_dangerous;

      sgot = htab->root.sgot;
      BFD_ASSERT (sgot != NULL);
      value = htab->tls_ldm_got.offset + sgot->output_offset;
      if (!htab->tls_ldm_got.rel_emitted)
	{
	  bfd_reloc_status_type status = mn10300_emit_tls_ld_reloc (output_bfd, htab);
	  if (status != bfd_reloc_ok)
	    return status;
	}
      return mn10300_check_and_put_value (input_bfd, hit_data, value, r_type);

    case R_MN10300_TLS_GOTIE:
    case R_MN10300_TLS_GD:
    case R_MN10300_TLS_IE:
    case R_MN10300_GOT32:
    case R_MN10300_GOT24:
    case R_MN10300_GOT16:
      return mn10300_handle_got_tls_group (input_bfd, output_bfd,
					   hit_data, value, addend, r_type,
					   h, symndx, info, htab);

    default:
      return bfd_reloc_notsupported;
    }
}

/* Relocate an MN10300 ELF section.  */

static bool
should_relocation_be_zero (struct bfd_link_info *info,
                           enum bfd_link_hash_type h_type,
                           int r_type,
                           unsigned char h_other,
                           bfd_vma h_plt_offset,
                           asection *input_section,
                           struct elf_link_hash_entry *hh_entry)
{
  if (! (h_type == bfd_link_hash_defined || h_type == bfd_link_hash_defweak))
    return false;

  switch (r_type)
    {
    case R_MN10300_GOTPC32:
    case R_MN10300_GOTPC16:
      return true;

    case R_MN10300_PLT32:
    case R_MN10300_PLT16:
      return (ELF_ST_VISIBILITY (h_other) != STV_INTERNAL
              && ELF_ST_VISIBILITY (h_other) != STV_HIDDEN
              && h_plt_offset != (bfd_vma) -1);

    case R_MN10300_GOT32:
    case R_MN10300_GOT24:
    case R_MN10300_TLS_GD:
    case R_MN10300_TLS_LD:
    case R_MN10300_TLS_GOTIE:
    case R_MN10300_TLS_IE:
    case R_MN10300_GOT16:
      return (elf_hash_table (info)->dynamic_sections_created
              && !SYMBOL_REFERENCES_LOCAL (info, hh_entry));

    case R_MN10300_32:
      /* _32 relocs in executables force _COPY relocs, such that the address
         of the symbol ends up being local.  */
      return (!SYMBOL_REFERENCES_LOCAL (info, hh_entry)
              && (((input_section->flags & SEC_ALLOC) != 0
                   && !bfd_link_executable (info))
                  /* DWARF will emit R_MN10300_32 relocations in its
                     sections against symbols defined externally in shared
                     libraries.  We can't do anything with them here.  */
                  || ((input_section->flags & SEC_DEBUGGING) != 0
                      && ((struct elf32_mn10300_link_hash_entry *) hh_entry)->root.def_dynamic)));

    default:
      return false;
    }
}

static const char *
get_error_symbol_name (bfd *input_bfd,
                       Elf_Internal_Shdr *symtab_hdr,
                       struct elf32_mn10300_link_hash_entry *h_mn10300,
                       Elf_Internal_Sym *local_sym_ptr,
                       asection *target_section)
{
  if (h_mn10300 != NULL)
    return h_mn10300->root.root.root.string;

  /* For local symbols, h_mn10300 is NULL. */
  /* Use 'local_sym_ptr' and 'target_section' for local symbols. */
  const char *name = (bfd_elf_string_from_elf_section
                      (input_bfd, symtab_hdr->sh_link, local_sym_ptr->st_name));
  if (name == NULL || *name == '\0')
    name = bfd_section_name (target_section);
  return name;
}

static bool
handle_relocation_error (struct bfd_link_info *info,
                         bfd *input_bfd,
                         asection *input_section,
                         Elf_Internal_Rela *rel,
                         reloc_howto_type *howto,
                         int r_type,
                         Elf_Internal_Shdr *symtab_hdr,
                         struct elf32_mn10300_link_hash_entry *h_mn10300,
                         Elf_Internal_Sym *local_sym_ptr,
                         asection *target_section,
                         bfd_reloc_status_type r_status)
{
  const char *name = get_error_symbol_name(input_bfd, symtab_hdr, h_mn10300, local_sym_ptr, target_section);
  const char *msg = NULL;

  switch (r_status)
    {
    case bfd_reloc_overflow:
      (*info->callbacks->reloc_overflow)
        (info, (h_mn10300 ? &h_mn10300->root.root : NULL), name, howto->name,
         (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
      return true; /* Error reported by callback, continue processing */

    case bfd_reloc_undefined:
      (*info->callbacks->undefined_symbol)
        (info, name, input_bfd, input_section, rel->r_offset, true);
      return true; /* Error reported by callback, continue processing */

    case bfd_reloc_outofrange:
      msg = _("internal error: out of range error");
      break;

    case bfd_reloc_notsupported:
      msg = _("internal error: unsupported relocation error");
      break;

    case bfd_reloc_dangerous:
      if (r_type == R_MN10300_PCREL32)
        msg = _("error: inappropriate relocation type for shared"
                " library (did you forget -fpic?)");
      else if (r_type == R_MN10300_GOT32)
        msg = _("%pB: taking the address of protected function"
                " '%s' cannot be done when making a shared library");
      else
        msg = _("internal error: suspicious relocation type used"
                " in shared library");
      break;

    default:
      msg = _("internal error: unknown error");
      break;
    }

  if (msg != NULL)
    {
      _bfd_error_handler (msg, input_bfd, name);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }
  return true;
}

static int
mn10300_elf_relocate_section (bfd *output_bfd,
			      struct bfd_link_info *info,
			      bfd *input_bfd,
			      asection *input_section,
			      bfd_byte *contents,
			      Elf_Internal_Rela *relocs,
			      Elf_Internal_Sym *local_syms,
			      asection **local_sections)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);

  Elf_Internal_Rela *rel = relocs;
  Elf_Internal_Rela *relend = relocs + input_section->reloc_count;

  for (; rel < relend; rel++)
    {
      unsigned long r_symndx = ELF32_R_SYM (rel->r_info);
      int r_type = ELF32_R_TYPE (rel->r_info);
      reloc_howto_type *howto = elf_mn10300_howto_table + r_type;
      bfd_vma relocation = 0;
      bfd_reloc_status_type r_status;
      bool unresolved_reloc = false;

      Elf_Internal_Sym *current_sym_ptr = NULL;
      asection *target_section = NULL;
      struct elf_link_hash_entry *sym_global_hash = NULL;
      struct elf32_mn10300_link_hash_entry *h_mn10300 = NULL;

      /* Just skip the vtable gc relocs.  */
      if (r_type == R_MN10300_GNU_VTINHERIT
	  || r_type == R_MN10300_GNU_VTENTRY)
	continue;

      int tls_r_type = elf_mn10300_tls_transition (info, r_type, sym_global_hash, input_section, 0);
      if (tls_r_type != r_type)
	{
	  bool had_plt = mn10300_do_tls_transition (input_bfd, r_type, tls_r_type,
					       contents, rel->r_offset);
	  r_type = tls_r_type;
	  howto = elf_mn10300_howto_table + r_type;

	  if (had_plt)
	    {
	      Elf_Internal_Rela *trel_ptr;
	      for (trel_ptr = rel+1; trel_ptr < relend; trel_ptr++)
		if ((ELF32_R_TYPE (trel_ptr->r_info) == R_MN10300_PLT32
		     || ELF32_R_TYPE (trel_ptr->r_info) == R_MN10300_PCREL32)
		    && rel->r_offset + had_plt == trel_ptr->r_offset)
		  trel_ptr->r_info = ELF32_R_INFO (0, R_MN10300_NONE);
	    }
	}

      if (r_symndx < symtab_hdr->sh_info)
	{
	  current_sym_ptr = local_syms + r_symndx;
	  target_section = local_sections[r_symndx];
	  relocation = _bfd_elf_rela_local_sym (output_bfd, current_sym_ptr, &target_section, rel);
	}
      else
	{
	  bool warned_macro = false;
	  bool ignored_macro = false;
	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   sym_global_hash, target_section, relocation,
				   unresolved_reloc, warned_macro, ignored_macro);
	  h_mn10300 = elf_mn10300_hash_entry (sym_global_hash);

	  if (h_mn10300 != NULL)
	    {
	      if (should_relocation_be_zero (info,
	                                     h_mn10300->root.root.type,
	                                     r_type,
	                                     h_mn10300->root.other,
	                                     h_mn10300->root.plt.offset,
	                                     input_section,
	                                     sym_global_hash))
	        {
	          relocation = 0;
	        }
	      else if (!bfd_link_relocatable (info) && unresolved_reloc
	               && _bfd_elf_section_offset (output_bfd, info, input_section,
	                                           rel->r_offset) != (bfd_vma) -1)
	        {
	          const char *sym_name_for_error = get_error_symbol_name(input_bfd, symtab_hdr, h_mn10300, current_sym_ptr, target_section);
	          _bfd_error_handler
	            (_("%pB(%pA+%#" PRIx64 "): "
	               "unresolvable %s relocation against symbol `%s'"),
	             input_bfd,
	             input_section,
	             (uint64_t) rel->r_offset,
	             howto->name,
	             sym_name_for_error);
	        }
	    }
	  else if (!bfd_link_relocatable (info) && unresolved_reloc
	           && _bfd_elf_section_offset (output_bfd, info, input_section,
	                                       rel->r_offset) != (bfd_vma) -1)
	    {
	      /* This branch handles the case where sym_global_hash and h_mn10300 are NULL */
	      /* but RELOC_FOR_GLOBAL_SYMBOL still set unresolved_reloc. */
	      const char *sym_name_for_error = get_error_symbol_name(input_bfd, symtab_hdr, h_mn10300, current_sym_ptr, target_section);
	      _bfd_error_handler
	        (_("%pB(%pA+%#" PRIx64 "): "
	           "unresolvable %s relocation against symbol `%s'"),
	         input_bfd,
	         input_section,
	         (uint64_t) rel->r_offset,
	         howto->name,
	         sym_name_for_error);
	    }
	}

      if (target_section != NULL && discarded_section (target_section))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, R_MN10300_NONE,
					 howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      r_status = mn10300_elf_final_link_relocate (howto, input_bfd, output_bfd,
						   input_section,
						   contents, rel->r_offset,
						   relocation, rel->r_addend,
						   sym_global_hash,
						   r_symndx,
						   info, target_section, h_mn10300 == NULL);

      if (r_status != bfd_reloc_ok)
	{
	  if (!handle_relocation_error (info, input_bfd, input_section, rel,
	                                howto, r_type, symtab_hdr, h_mn10300,
	                                current_sym_ptr, target_section, r_status))
	    {
	      return false;
	    }
	}
    }

  return true;
}

/* Finish initializing one hash table entry.  */

static bool
elf32_mn10300_finish_hash_table_entry (struct bfd_hash_entry *gen_entry,
				       void *in_args)
{
  struct elf32_mn10300_link_hash_entry *entry = (struct elf32_mn10300_link_hash_entry *) gen_entry;
  struct bfd_link_info *link_info = (struct bfd_link_info *) in_args;
  unsigned int byte_count = 0;

  if (entry->flags == MN10300_CONVERT_CALL_TO_CALLS)
    return true;

  bool no_direct_calls_present = (entry->direct_calls == 0);
  bool no_optimizable_instructions_exist = (entry->stack_size == 0 && entry->movm_args == 0);
  bool symbol_is_dynamic_and_public = (elf_hash_table (link_info)->dynamic_sections_created
                                       && ELF_ST_VISIBILITY (entry->root.other) != STV_INTERNAL
                                       && ELF_ST_VISIBILITY (entry->root.other) != STV_HIDDEN);

  if (no_direct_calls_present || no_optimizable_instructions_exist || symbol_is_dynamic_and_public)
    {
      entry->flags |= MN10300_CONVERT_CALL_TO_CALLS;
      return true;
    }

  if (entry->movm_args)
    byte_count += 2;

  if (entry->stack_size > 0)
    {
      if (entry->stack_size <= 128)
	byte_count += 3;
      else
	byte_count += 4;
    }

  if (byte_count < entry->direct_calls)
    entry->flags |= MN10300_CONVERT_CALL_TO_CALLS;

  return true;
}

/* Used to count hash table entries.  */

static bool
elf32_mn10300_count_hash_table_entries (struct bfd_hash_entry *gen_entry ATTRIBUTE_UNUSED,
					void * in_args)
{
  if (in_args == NULL)
    {
      return false;
    }

  int *count = (int *) in_args;
  (*count)++;
  return true;
}

/* Used to enumerate hash table entries into a linear array.  */

static bool
elf32_mn10300_list_hash_table_entries (struct bfd_hash_entry *gen_entry,
				       void * in_args)
{
  struct bfd_hash_entry ***array_cursor_ref = (struct bfd_hash_entry ***) in_args;

  if (array_cursor_ref == NULL)
    {
      return false;
    }

  if (*array_cursor_ref == NULL)
    {
      return false;
    }

  **array_cursor_ref = gen_entry;
  (*array_cursor_ref)++;

  return true;
}

/* Used to sort the array created by the above.  */

static int
sort_by_value (const void *va, const void *vb)
{
  const struct elf32_mn10300_link_hash_entry *a
    = *(const struct elf32_mn10300_link_hash_entry **) va;
  const struct elf32_mn10300_link_hash_entry *b
    = *(const struct elf32_mn10300_link_hash_entry **) vb;

  if (a->value < b->value)
    return -1;
  else if (a->value > b->value)
    return 1;
  else
    return 0;
}

/* Compute the stack size and movm arguments for the function
   referred to by HASH at address ADDR in section with
   contents CONTENTS, store the information in the hash table.  */

#define MN10300_MOVM_OPCODE_BYTE1 0xcf
#define MN10300_ADD_SP_IMM8_OPCODE_BYTE1 0xf8
#define MN10300_ADD_SP_IMM8_OPCODE_BYTE2 0xfe
#define MN10300_ADD_SP_IMM16_OPCODE_BYTE1 0xfa
#define MN10300_ADD_SP_IMM16_OPCODE_BYTE2 0xfe

#define MN10300_REG_D2_MASK 0x80
#define MN10300_REG_D3_MASK 0x40
#define MN10300_REG_A2_MASK 0x20
#define MN10300_REG_A3_MASK 0x10
#define MN10300_REG_OTHER_MASK 0x08
#define MN10300_REG_EXOTHER_MASK 0x01
#define MN10300_REG_EXREG1_MASK 0x02
#define MN10300_REG_EXREG0_MASK 0x04

#define MN10300_REG_SIZE 4

#define MN10300_MAX_CALL_STACK_SIZE 255

static inline int32_t
sign_extend_8_to_32(uint8_t val)
{
  return (int8_t)val;
}

static inline int32_t
sign_extend_16_to_32(uint16_t val)
{
  return (int16_t)val;
}

static void
compute_function_info (bfd *abfd,
		       struct elf32_mn10300_link_hash_entry *hash,
		       bfd_vma addr,
		       unsigned char *contents)
{
  bfd_vma current_offset = addr;
  unsigned char byte1, byte2;

  hash->movm_args = 0;
  hash->movm_stack_size = 0;
  hash->stack_size = 0;

  byte1 = bfd_get_8 (abfd, contents + current_offset);
  byte2 = bfd_get_8 (abfd, contents + current_offset + 1);

  if (byte1 == MN10300_MOVM_OPCODE_BYTE1)
    {
      hash->movm_args = byte2;
      current_offset += 2;
      byte1 = bfd_get_8 (abfd, contents + current_offset);
      byte2 = bfd_get_8 (abfd, contents + current_offset + 1);
    }

  if (hash->movm_args != 0)
    {
      unsigned int calculated_movm_stack_size = 0;

      if (hash->movm_args & MN10300_REG_D2_MASK)
        calculated_movm_stack_size += MN10300_REG_SIZE;
      if (hash->movm_args & MN10300_REG_D3_MASK)
        calculated_movm_stack_size += MN10300_REG_SIZE;
      if (hash->movm_args & MN10300_REG_A2_MASK)
        calculated_movm_stack_size += MN10300_REG_SIZE;
      if (hash->movm_args & MN10300_REG_A3_MASK)
        calculated_movm_stack_size += MN10300_REG_SIZE;
      if (hash->movm_args & MN10300_REG_OTHER_MASK)
        calculated_movm_stack_size += 8 * MN10300_REG_SIZE;

      if (bfd_get_mach (abfd) == bfd_mach_am33 || bfd_get_mach (abfd) == bfd_mach_am33_2)
        {
          if (hash->movm_args & MN10300_REG_EXOTHER_MASK)
            calculated_movm_stack_size += 6 * MN10300_REG_SIZE;
          if (hash->movm_args & MN10300_REG_EXREG1_MASK)
            calculated_movm_stack_size += 4 * MN10300_REG_SIZE;
          if (hash->movm_args & MN10300_REG_EXREG0_MASK)
            calculated_movm_stack_size += 2 * MN10300_REG_SIZE;
        }
      hash->movm_stack_size = calculated_movm_stack_size;
    }

  if (byte1 == MN10300_ADD_SP_IMM8_OPCODE_BYTE1 && byte2 == MN10300_ADD_SP_IMM8_OPCODE_BYTE2)
    {
      uint8_t imm8_raw = bfd_get_8 (abfd, contents + current_offset + 2);
      int32_t imm8_signed = sign_extend_8_to_32(imm8_raw);
      hash->stack_size = -imm8_signed;
    }
  else if (byte1 == MN10300_ADD_SP_IMM16_OPCODE_BYTE1 && byte2 == MN10300_ADD_SP_IMM16_OPCODE_BYTE2)
    {
      uint16_t imm16_raw = bfd_get_16 (abfd, contents + current_offset + 2);
      int32_t imm16_signed = sign_extend_16_to_32(imm16_raw);
      int32_t calculated_stack_size = -imm16_signed;

      if (calculated_stack_size >= 0 && calculated_stack_size < MN10300_MAX_CALL_STACK_SIZE)
        hash->stack_size = calculated_stack_size;
      else
        hash->stack_size = 0;
    }

  if (hash->stack_size + hash->movm_stack_size > MN10300_MAX_CALL_STACK_SIZE)
    hash->stack_size = 0;
}

/* Delete some bytes from a section while relaxing.  */

static bool
mn10300_elf_relax_delete_bytes (bfd *abfd,
				asection *sec,
				bfd_vma initial_addr,
				int initial_count)
{
  bfd_vma current_addr = initial_addr;
  int current_count = initial_count;

  do
    {
      Elf_Internal_Shdr *symtab_hdr;
      unsigned int sec_shndx;
      bfd_byte *contents;
      Elf_Internal_Rela *irel, *irelend;
      Elf_Internal_Rela *irelalign = NULL;
      bfd_vma toaddr;
      Elf_Internal_Sym *isym, *isymend;
      struct elf_link_hash_entry **sym_hashes;
      struct elf_link_hash_entry **end_hashes;
      unsigned int symcount;

      bfd_vma next_addr = 0;
      int next_count = 0;
      bool recurse_needed = false;

      sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);
      contents = elf_section_data (sec)->this_hdr.contents;

      toaddr = sec->size;

      irel = elf_section_data (sec)->relocs;
      irelend = irel + sec->reloc_count;

      if (sec->reloc_count > 0)
	{
	  /* If there is an align reloc at the end of the section ignore it.  */
	  if (ELF32_R_TYPE ((irelend - 1)->r_info) == (int) R_MN10300_ALIGN)
	    --irelend;

	  for (Elf_Internal_Rela *current_irel = irel; current_irel < irelend; ++current_irel)
	    {
	      if (ELF32_R_TYPE (current_irel->r_info) == (int) R_MN10300_ALIGN
		  && current_irel->r_offset > current_addr
		  && current_irel->r_offset < toaddr)
		{
		  unsigned int alignment_val = 1U << current_irel->r_addend;

		  if (current_count < alignment_val
		      || (alignment_val % current_count != 0))
		    {
		      irelalign = current_irel;
		      toaddr = current_irel->r_offset;
		      break;
		    }
		}
	    }
	}

      size_t bytes_to_shift = 0;
      if (toaddr > current_addr + current_count)
	{
	  bytes_to_shift = (size_t) (toaddr - (current_addr + current_count));
	}

      memmove (contents + current_addr, contents + current_addr + current_count, bytes_to_shift);

      if (irelalign == NULL)
	{
	  sec->size -= current_count;
	  toaddr++;
	}
      else
	{
	  for (int i = 0; i < current_count; ++i)
	    {
	      bfd_put_8 (abfd, (bfd_vma) 0xcb, contents + toaddr - current_count + i);
	    }
	}

      for (Elf_Internal_Rela *current_irel = elf_section_data (sec)->relocs; current_irel < irelend; ++current_irel)
	{
	  bool applies_to_reloc = (current_irel->r_offset > current_addr && current_irel->r_offset < toaddr);
	  bool is_align_at_boundary = (ELF32_R_TYPE (current_irel->r_info) == (int) R_MN10300_ALIGN
				      && current_irel->r_offset == toaddr);

	  if (applies_to_reloc || is_align_at_boundary)
	    {
	      current_irel->r_offset -= current_count;
	    }
	}

      symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
      isym = (Elf_Internal_Sym *) symtab_hdr->contents;
      isymend = isym + symtab_hdr->sh_info;

      for (Elf_Internal_Sym *current_isym = isym; current_isym < isymend; ++current_isym)
	{
	  if (current_isym->st_shndx == sec_shndx
	      && current_isym->st_value > current_addr
	      && current_isym->st_value < toaddr)
	    {
	      if (current_isym->st_value < current_addr + current_count)
		current_isym->st_value = current_addr;
	      else
		current_isym->st_value -= current_count;
	    }
	  else if (current_isym->st_shndx == sec_shndx
		   && ELF_ST_TYPE (current_isym->st_info) == STT_FUNC
		   && current_isym->st_value + current_isym->st_size > current_addr
		   && current_isym->st_value + current_isym->st_size < toaddr)
	    {
	      current_isym->st_size -= current_count;
	    }
	}

      symcount = (symtab_hdr->sh_size / sizeof (Elf32_External_Sym)) - symtab_hdr->sh_info;
      sym_hashes = elf_sym_hashes (abfd);
      
      if (sym_hashes != NULL)
        {
          end_hashes = sym_hashes + symcount;

          for (struct elf_link_hash_entry **current_hash_ptr = sym_hashes; current_hash_ptr < end_hashes; ++current_hash_ptr)
            {
              struct elf_link_hash_entry *sym_hash = *current_hash_ptr;

              if ((sym_hash->root.type == bfd_link_hash_defined || sym_hash->root.type == bfd_link_hash_defweak)
                  && sym_hash->root.u.def.section == sec
                  && sym_hash->root.u.def.value > current_addr
                  && sym_hash->root.u.def.value < toaddr)
                {
                  if (sym_hash->root.u.def.value < current_addr + current_count)
                    sym_hash->root.u.def.value = current_addr;
                  else
                    sym_hash->root.u.def.value -= current_count;
                }
              else if (sym_hash->root.type == bfd_link_hash_defined
                       && sym_hash->root.u.def.section == sec
                       && sym_hash->type == STT_FUNC
                       && sym_hash->root.u.def.value + sym_hash->size > current_addr
                       && sym_hash->root.u.def.value + sym_hash->size < toaddr)
                {
                  sym_hash->size -= current_count;
                }
            }
        }

      if (irelalign != NULL)
	{
	  bfd_vma alignto_original_offset_aligned;
	  bfd_vma alignaddr_adjusted_offset_aligned;

	  if ((int) irelalign->r_addend > 0)
	    {
	      unsigned int alignment_val = 1U << irelalign->r_addend;

	      alignto_original_offset_aligned = BFD_ALIGN (toaddr, alignment_val);
	      alignaddr_adjusted_offset_aligned = BFD_ALIGN (irelalign->r_offset, alignment_val);

	      if (alignaddr_adjusted_offset_aligned < alignto_original_offset_aligned)
		{
		  next_addr = alignaddr_adjusted_offset_aligned;
		  next_count = (int) (alignto_original_offset_aligned - alignaddr_adjusted_offset_aligned);
		  recurse_needed = true;
		}
	    }
	}

      if (recurse_needed)
	{
	  current_addr = next_addr;
	  current_count = next_count;
	}
      else
	{
	  break;
	}

    } while (true);

  return true;
}

/* Return TRUE if a symbol exists at the given address, else return
   FALSE.  */

static bool
mn10300_elf_symbol_address_p (bfd *abfd,
                              asection *sec,
                              Elf_Internal_Sym *isym_start,
                              bfd_vma addr)
{
  Elf_Internal_Shdr *symtab_hdr;
  unsigned int sec_shndx;
  Elf_Internal_Sym *isym_current;
  struct elf_link_hash_entry **sym_hashes;
  struct elf_link_hash_entry **sym_hashes_end;
  unsigned int global_sym_count;

  if (abfd == NULL || sec == NULL || isym_start == NULL)
    {
      return false;
    }

  sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);

  elf_bfd_t *elf_data = elf_tdata(abfd);
  if (elf_data == NULL)
    {
      return false;
    }
  symtab_hdr = &elf_data->symtab_hdr;

  if (symtab_hdr->sh_info > 0)
    {
      for (isym_current = isym_start;
           isym_current < isym_start + symtab_hdr->sh_info;
           isym_current++)
        {
          if (isym_current->st_shndx == sec_shndx
              && isym_current->st_value == addr)
            {
              return true;
            }
        }
    }

  unsigned int total_symbols_in_section = symtab_hdr->sh_size / sizeof (Elf32_External_Sym);
  if (total_symbols_in_section > symtab_hdr->sh_info)
    {
      global_sym_count = total_symbols_in_section - symtab_hdr->sh_info;
    }
  else
    {
      global_sym_count = 0;
    }

  if (global_sym_count > 0)
    {
      sym_hashes = elf_sym_hashes (abfd);
      if (sym_hashes == NULL)
        {
          return false;
        }

      sym_hashes_end = sym_hashes + global_sym_count;
      for (; sym_hashes < sym_hashes_end; sym_hashes++)
        {
          struct elf_link_hash_entry *sym_hash = *sym_hashes;

          if (sym_hash == NULL)
            {
              continue;
            }

          if ((sym_hash->root.type == bfd_link_hash_defined
               || sym_hash->root.type == bfd_link_hash_defweak)
              && sym_hash->root.u.def.section == sec
              && sym_hash->root.u.def.value == addr)
            {
              return true;
            }
        }
    }

  return false;
}

/* This function handles relaxing for the mn10300.

   There are quite a few relaxing opportunities available on the mn10300:

	* calls:32 -> calls:16					   2 bytes
	* call:32  -> call:16					   2 bytes

	* call:32 -> calls:32					   1 byte
	* call:16 -> calls:16					   1 byte
		* These are done anytime using "calls" would result
		in smaller code, or when necessary to preserve the
		meaning of the program.

	* call:32						   varies
	* call:16
		* In some circumstances we can move instructions
		from a function prologue into a "call" instruction.
		This is only done if the resulting code is no larger
		than the original code.

	* jmp:32 -> jmp:16					   2 bytes
	* jmp:16 -> bra:8					   1 byte

		* If the previous instruction is a conditional branch
		around the jump/bra, we may be able to reverse its condition
		and change its target to the jump's target.  The jump/bra
		can then be deleted.				   2 bytes

	* mov abs32 -> mov abs16				   1 or 2 bytes

	* Most instructions which accept imm32 can relax to imm16  1 or 2 bytes
	- Most instructions which accept imm16 can relax to imm8   1 or 2 bytes

	* Most instructions which accept d32 can relax to d16	   1 or 2 bytes
	- Most instructions which accept d16 can relax to d8	   1 or 2 bytes

	We don't handle imm16->imm8 or d16->d8 as they're very rare
	and somewhat more difficult to support.  */

static bool
mn10300_elf_relax_section (bfd *abfd,
			   asection *sec,
			   struct bfd_link_info *link_info,
			   bool *again)
{
  Elf_Internal_Shdr *symtab_hdr = NULL;
  Elf_Internal_Rela *internal_relocs = NULL;
  Elf_Internal_Sym *isymbuf = NULL;
  bfd_byte *contents = NULL;
  struct elf32_mn10300_link_hash_table *hash_table;
  bfd_vma align_gap_adjustment;
  bool local_isymbuf_allocated = false;
  bool local_contents_allocated = false;
  bool local_internal_relocs_allocated = false;

  static const unsigned char OPCODE_BR_CC = 0xdc;
  static const unsigned char OPCODE_CALL_DD = 0xdd;
  static const unsigned char OPCODE_CALLS_FC_FF_PREFIX = 0xfc; // 0xfc 0xff
  static const unsigned char OPCODE_BR_CC_16 = 0xcc;
  static const unsigned char OPCODE_CALL_CD = 0xcd;
  static const unsigned char OPCODE_CALLS_FA_FF_PREFIX = 0xfa; // 0xfa 0xff
  static const unsigned char OPCODE_BR_CA = 0xca;
  static const unsigned char OPCODE_AM33_24BIT_PREFIX = 0xfd;
  static const unsigned char OPCODE_AM33_8BIT_PREFIX = 0xfb;
  static const unsigned char OPCODE_AM33_32BIT_PREFIX = 0xfe;
  static const unsigned char OPCODE_AM33_16BIT_PREFIX = 0xfa;

  // Helper for managing allocated memory. Returns true if memory should be freed, false if it was cached.
  auto static bool
  mn10300_manage_symbuf_memory(struct bfd_link_info *li, Elf_Internal_Shdr *shdr,
                               Elf_Internal_Sym **isymbuf_ptr, bool was_locally_allocated)
  {
    if (*isymbuf_ptr != NULL && shdr->contents != (unsigned char *) *isymbuf_ptr)
      {
        if (!li->keep_memory)
          {
            if (was_locally_allocated)
              free(*isymbuf_ptr);
            return true;
          }
        else
          {
            shdr->contents = (unsigned char *) *isymbuf_ptr;
          }
      }
    *isymbuf_ptr = NULL;
    return false;
  }

  auto static bool
  mn10300_manage_contents_memory(struct bfd_link_info *li, asection *s,
                                 bfd_byte **contents_ptr, bool was_locally_allocated)
  {
    if (*contents_ptr != NULL && elf_section_data(s)->this_hdr.contents != *contents_ptr)
      {
        if (!li->keep_memory)
          {
            if (was_locally_allocated)
              free(*contents_ptr);
            return true;
          }
        else
          {
            elf_section_data(s)->this_hdr.contents = *contents_ptr;
          }
      }
    *contents_ptr = NULL;
    return false;
  }

  auto static bool
  mn10300_manage_relocs_memory(asection *s, Elf_Internal_Rela **internal_relocs_ptr, bool was_locally_allocated)
  {
    if (*internal_relocs_ptr != NULL && elf_section_data(s)->relocs != *internal_relocs_ptr)
      {
        if (was_locally_allocated)
          free(*internal_relocs_ptr);
        return true;
      }
    *internal_relocs_ptr = NULL;
    return false;
  }

  auto static const char *
  get_unique_sym_name(bfd *ibfd, Elf_Internal_Shdr *ishdr,
                      Elf_Internal_Sym *isym, asection *sym_sec,
                      char *buffer, size_t buffer_size)
  {
    const char *base_name = bfd_elf_string_from_elf_section(ibfd, ishdr->sh_link, isym->st_name);
    int len = snprintf(buffer, buffer_size, "%s_%08x", base_name, sym_sec->id);
    if (len < 0 || (size_t)len >= buffer_size)
      return NULL;
    return buffer;
  }

  auto static bool
  get_reloc_symbol_info(bfd *ibfd, Elf_Internal_Shdr *ishdr, Elf_Internal_Sym *isymbuf_base,
                        unsigned long r_sym_index, bfd_vma r_addend,
                        struct elf32_mn10300_link_hash_table *ht,
                        asection **sym_sec_out, bfd_vma *symval_out,
                        struct elf32_mn10300_link_hash_entry **hash_out)
  {
    asection *sym_sec = NULL;
    bfd_vma symval;
    struct elf32_mn10300_link_hash_entry *h = NULL;
    char local_sym_name_buffer[256];

    if (r_sym_index < ishdr->sh_info)
      {
        Elf_Internal_Sym *isym = isymbuf_base + r_sym_index;

        if (isym->st_shndx == SHN_UNDEF) sym_sec = bfd_und_section_ptr;
        else if (isym->st_shndx == SHN_ABS) sym_sec = bfd_abs_section_ptr;
        else if (isym->st_shndx == SHN_COMMON) sym_sec = bfd_com_section_ptr;
        else sym_sec = bfd_section_from_elf_index(ibfd, isym->st_shndx);

        if ((sym_sec->flags & SEC_MERGE) && sym_sec->sec_info_type == SEC_INFO_TYPE_MERGE)
          {
            symval = isym->st_value;
            if (ELF_ST_TYPE(isym->st_info) == STT_SECTION)
              symval += r_addend;
            symval = _bfd_merged_section_offset(ibfd, &sym_sec, elf_section_data(sym_sec)->sec_info, symval);
            if (ELF_ST_TYPE(isym->st_info) != STT_SECTION)
              symval += r_addend;
            symval += sym_sec->output_section->vma + sym_sec->output_offset - r_addend;
          }
        else
          symval = isym->st_value + sym_sec->output_section->vma + sym_sec->output_offset;

        const char *sym_name = get_unique_sym_name(ibfd, ishdr, isym, sym_sec,
                                                   local_sym_name_buffer, sizeof(local_sym_name_buffer));
        if (sym_name == NULL) return false;

        h = (struct elf32_mn10300_link_hash_entry *)
          elf_link_hash_lookup(&ht->static_hash_table->root, sym_name, false, false, false);
      }
    else
      {
        unsigned long indx = r_sym_index - ishdr->sh_info;
        h = (struct elf32_mn10300_link_hash_entry *) elf_sym_hashes(ibfd)[indx];
        if (h == NULL || (h->root.root.type != bfd_link_hash_defined && h->root.root.type != bfd_link_hash_defweak))
          return false;
        if (h->root.root.u.def.section->output_section == NULL)
          return false;

        sym_sec = h->root.root.u.def.section->output_section;
        symval = (h->root.root.u.def.value + h->root.root.u.def.section->output_section->vma
                  + h->root.root.u.def.section->output_offset);
      }

    *sym_sec_out = sym_sec;
    *symval_out = symval;
    *hash_out = h;
    return true;
  }

  auto static bool
  process_reloc_flags_for_section(bfd *ibfd, asection *s, Elf_Internal_Rela *irel,
                                  Elf_Internal_Shdr *shdr, Elf_Internal_Sym *isymbuf_base,
                                  struct elf32_mn10300_link_hash_table *ht,
                                  bfd_byte *section_contents)
  {
    long r_type = ELF32_R_TYPE(irel->r_info);
    unsigned long r_index = ELF32_R_SYM(irel->r_info);
    struct elf32_mn10300_link_hash_entry *hash_entry;
    asection *sym_sec = NULL;
    char local_sym_name_buffer[256];

    if (r_type < 0 || r_type >= (int) R_MN10300_MAX)
      return false;

    if (r_index < shdr->sh_info)
      {
        Elf_Internal_Sym *isym = isymbuf_base + r_index;
        if (ELF_ST_TYPE(isym->st_info) != STT_FUNC)
          return true; // Only functions are relevant for flags

        if (isym->st_shndx == SHN_UNDEF) sym_sec = bfd_und_section_ptr;
        else if (isym->st_shndx == SHN_ABS) sym_sec = bfd_abs_section_ptr;
        else if (isym->st_shndx == SHN_COMMON) sym_sec = bfd_com_section_ptr;
        else sym_sec = bfd_section_from_elf_index(ibfd, isym->st_shndx);

        const char *sym_name = get_unique_sym_name(ibfd, shdr, isym, sym_sec,
                                                   local_sym_name_buffer, sizeof(local_sym_name_buffer));
        if (sym_name == NULL) return false;

        hash_entry = (struct elf32_mn10300_link_hash_entry *)
          elf_link_hash_lookup(&ht->static_hash_table->root, sym_name, true, true, false);
        if (hash_entry == NULL) return false;
      }
    else
      {
        r_index -= shdr->sh_info;
        hash_entry = (struct elf32_mn10300_link_hash_entry *) elf_sym_hashes(ibfd)[r_index];
        if (hash_entry == NULL) return false;
      }

    if ((s->flags & SEC_CODE) != 0 && section_contents != NULL)
      {
        unsigned char code = bfd_get_8(ibfd, section_contents + irel->r_offset - 1);
        if (code != OPCODE_CALL_DD && code != OPCODE_CALL_CD)
          hash_entry->flags |= MN10300_CONVERT_CALL_TO_CALLS;
      }

    if (r_type == (int) R_MN10300_PCREL32
        || r_type == (int) R_MN10300_PLT32
        || r_type == (int) R_MN10300_PLT16
        || r_type == (int) R_MN10300_PCREL16)
      hash_entry->direct_calls++;
    else
      hash_entry->flags |= MN10300_CONVERT_CALL_TO_CALLS;

    return true;
  }

  auto static bool
  compute_func_info_for_section(bfd *ibfd, asection *s, Elf_Internal_Shdr *shdr, Elf_Internal_Sym *isymbuf_base,
                                struct elf32_mn10300_link_hash_table *ht, bfd_byte *section_contents)
  {
    unsigned int sec_shndx = _bfd_elf_section_from_bfd_section(ibfd, s);
    unsigned int symcount = (shdr->sh_size / sizeof(Elf32_External_Sym) - shdr->sh_info);
    struct elf_link_hash_entry **hashes = elf_sym_hashes(ibfd);
    struct elf_link_hash_entry **end_hashes = hashes + symcount;
    char local_sym_name_buffer[256];

    Elf_Internal_Sym *isym, *isymend = isymbuf_base + shdr->sh_info;
    for (isym = isymbuf_base; isym < isymend; isym++)
      {
        if (isym->st_shndx == sec_shndx && ELF_ST_TYPE(isym->st_info) == STT_FUNC)
          {
            struct elf32_mn10300_link_hash_entry *hash_entry;
            asection *sym_sec;
            bool aliased = false;
            for (struct elf_link_hash_entry **lhashes = hashes; lhashes < end_hashes; lhashes++)
              {
                hash_entry = (struct elf32_mn10300_link_hash_entry *) *lhashes;
                if ((hash_entry->root.root.type == bfd_link_hash_defined || hash_entry->root.root.type == bfd_link_hash_defweak)
                    && hash_entry->root.root.u.def.section == s
                    && hash_entry->root.type == STT_FUNC
                    && hash_entry->root.root.u.def.value == isym->st_value)
                  { aliased = true; break; }
              }
            if (aliased) continue;

            if (isym->st_shndx == SHN_UNDEF) sym_sec = bfd_und_section_ptr;
            else if (isym->st_shndx == SHN_ABS) sym_sec = bfd_abs_section_ptr;
            else if (isym->st_shndx == SHN_COMMON) sym_sec = bfd_com_section_ptr;
            else sym_sec = bfd_section_from_elf_index(ibfd, isym->st_shndx);

            const char *sym_name = get_unique_sym_name(ibfd, shdr, isym, sym_sec,
                                                       local_sym_name_buffer, sizeof(local_sym_name_buffer));
            if (sym_name == NULL) return false;

            hash_entry = (struct elf32_mn10300_link_hash_entry *)
              elf_link_hash_lookup(&ht->static_hash_table->root, sym_name, true, true, false);
            if (hash_entry == NULL) return false;

            compute_function_info(ibfd, hash_entry, isym->st_value, section_contents);
            hash_entry->value = isym->st_value;
          }
      }

    for (hashes = elf_sym_hashes(ibfd); hashes < end_hashes; hashes++)
      {
        struct elf32_mn10300_link_hash_entry *hash_entry = (struct elf32_mn10300_link_hash_entry *) *hashes;
        if ((hash_entry->root.root.type == bfd_link_hash_defined || hash_entry->root.root.type == bfd_link_hash_defweak)
            && hash_entry->root.root.u.def.section == s
            && hash_entry->root.type == STT_FUNC)
          compute_function_info(ibfd, hash_entry, (hash_entry)->root.root.u.def.value, section_contents);
      }
    return true;
  }

  auto static bool
  mn10300_init_hash_entries_pass(bfd *ibfd, struct bfd_link_info *li, struct elf32_mn10300_link_hash_table *ht)
  {
    bfd *current_bfd;
    asection *section;
    Elf_Internal_Shdr *symtab_hdr_local = NULL;
    Elf_Internal_Sym *isymbuf_local = NULL;
    bfd_byte *contents_local = NULL;
    Elf_Internal_Rela *internal_relocs_local = NULL;
    bool ret = true;
    bool current_isymbuf_allocated = false;
    bool current_contents_allocated = false;
    bool current_relocs_allocated = false;

    for (current_bfd = li->input_bfds; current_bfd != NULL; current_bfd = current_bfd->link.next)
      {
        symtab_hdr_local = &elf_tdata(current_bfd)->symtab_hdr;
        if (symtab_hdr_local->sh_info != 0)
          {
            isymbuf_local = (Elf_Internal_Sym *) symtab_hdr_local->contents;
            if (isymbuf_local == NULL)
              {
                isymbuf_local = bfd_elf_get_elf_syms(current_bfd, symtab_hdr_local, symtab_hdr_local->sh_info, 0,
                                                     NULL, NULL, NULL);
                if (isymbuf_local == NULL) { ret = false; goto cleanup_bfd_loop; }
                current_isymbuf_allocated = true;
              }
          }

        for (section = current_bfd->sections; section != NULL; section = section->next)
          {
            current_contents_allocated = false;
            current_relocs_allocated = false;

            if (!((section->flags & SEC_RELOC) && section->reloc_count)
                || !(section->flags & SEC_ALLOC)
                || !(section->flags & SEC_HAS_CONTENTS))
              continue;

            contents_local = elf_section_data(section)->this_hdr.contents;
            if (contents_local == NULL && section->size != 0)
              {
                if (!bfd_malloc_and_get_section(current_bfd, section, &contents_local))
                  { ret = false; goto cleanup_section_loop; }
                current_contents_allocated = true;
              }

            if ((section->flags & SEC_RELOC) && section->reloc_count != 0)
              {
                internal_relocs_local = _bfd_elf_link_read_relocs(current_bfd, section, NULL, NULL,
                                                                  li->keep_memory);
                if (internal_relocs_local == NULL)
                  { ret = false; goto cleanup_section_loop; }
                current_relocs_allocated = true;

                Elf_Internal_Rela *irel, *irelend = internal_relocs_local + section->reloc_count;
                for (irel = internal_relocs_local; irel < irelend; irel++)
                  {
                    if (!process_reloc_flags_for_section(current_bfd, section, irel, symtab_hdr_local, isymbuf_local,
                                                         ht, contents_local))
                      { ret = false; goto cleanup_section_loop; }
                  }
              }

            if ((section->flags & SEC_CODE) != 0)
              {
                if (!compute_func_info_for_section(current_bfd, section, symtab_hdr_local, isymbuf_local,
                                                   ht, contents_local))
                  { ret = false; goto cleanup_section_loop; }
              }

          cleanup_section_loop:;
            mn10300_manage_relocs_memory(section, &internal_relocs_local, current_relocs_allocated);
            mn10300_manage_contents_memory(li, section, &contents_local, current_contents_allocated);
            if (!ret) break;
          }

        cleanup_bfd_loop:;
        mn10300_manage_symbuf_memory(li, symtab_hdr_local, &isymbuf_local, current_isymbuf_allocated);
        if (!ret) break;
      }
    return ret;
  }

  auto static int
  sort_by_value(const void *a, const void *b)
  {
    const struct elf32_mn10300_link_hash_entry *entry_a = *(const struct elf32_mn10300_link_hash_entry **)a;
    const struct elf32_mn10300_link_hash_entry *entry_b = *(const struct elf32_mn10300_link_hash_entry **)b;

    if (entry_a->value < entry_b->value) return -1;
    if (entry_a->value > entry_b->value) return 1;
    return 0;
  }

  auto static bool
  mn10300_perform_prologue_deletion_pass(bfd *orig_abfd, struct bfd_link_info *li,
                                         struct elf32_mn10300_link_hash_table *ht, bool *again_ptr)
  {
    bfd *input_bfd;
    asection *section;
    Elf_Internal_Shdr *symtab_hdr_local = NULL;
    Elf_Internal_Sym *isymbuf_local = NULL;
    bfd_byte *contents_local = NULL;
    Elf_Internal_Rela *internal_relocs_local = NULL;
    bool ret = true;
    char local_sym_name_buffer[256];
    bool current_isymbuf_allocated = false;
    bool current_contents_allocated = false;
    bool current_relocs_allocated = false;

    for (input_bfd = li->input_bfds; input_bfd != NULL; input_bfd = input_bfd->link.next)
      {
        symtab_hdr_local = &elf_tdata(input_bfd)->symtab_hdr;
        if (symtab_hdr_local->sh_info != 0)
          {
            isymbuf_local = (Elf_Internal_Sym *) symtab_hdr_local->contents;
            if (isymbuf_local == NULL)
              {
                isymbuf_local = bfd_elf_get_elf_syms(input_bfd, symtab_hdr_local, symtab_hdr_local->sh_info, 0,
                                                     NULL, NULL, NULL);
                if (isymbuf_local == NULL) { ret = false; goto cleanup_bfd_loop; }
                current_isymbuf_allocated = true;
              }
          }

        for (section = input_bfd->sections; section != NULL; section = section->next)
          {
            current_contents_allocated = false;
            current_relocs_allocated = false;

            if (!((section->flags & SEC_CODE) && (section->flags & SEC_HAS_CONTENTS) && section->size != 0))
              continue;

            if (section->reloc_count != 0)
              {
                internal_relocs_local = _bfd_elf_link_read_relocs(input_bfd, section, NULL, NULL,
                                                                  li->keep_memory);
                if (internal_relocs_local == NULL) { ret = false; goto cleanup_section_loop; }
                current_relocs_allocated = true;
              }

            contents_local = elf_section_data(section)->this_hdr.contents;
            if (contents_local == NULL)
              {
                if (!bfd_malloc_and_get_section(input_bfd, section, &contents_local))
                  { ret = false; goto cleanup_section_loop; }
                current_contents_allocated = true;
              }

            unsigned int sec_shndx = _bfd_elf_section_from_bfd_section(input_bfd, section);

            // Process local functions
            Elf_Internal_Sym *isym, *isymend = isymbuf_local + symtab_hdr_local->sh_info;
            for (isym = isymbuf_local; isym < isymend; isym++)
              {
                if (isym->st_shndx != sec_shndx || ELF_ST_TYPE(isym->st_info) != STT_FUNC)
                  continue;

                asection *sym_sec;
                if (isym->st_shndx == SHN_UNDEF) sym_sec = bfd_und_section_ptr;
                else if (isym->st_shndx == SHN_ABS) sym_sec = bfd_abs_section_ptr;
                else if (isym->st_shndx == SHN_COMMON) sym_sec = bfd_com_section_ptr;
                else sym_sec = bfd_section_from_elf_index(input_bfd, isym->st_shndx);

                const char *sym_name = get_unique_sym_name(input_bfd, symtab_hdr_local, isym, sym_sec,
                                                           local_sym_name_buffer, sizeof(local_sym_name_buffer));
                if (sym_name == NULL) { ret = false; goto cleanup_section_loop; }

                struct elf32_mn10300_link_hash_entry *sym_hash = (struct elf32_mn10300_link_hash_entry *)
                  elf_link_hash_lookup(&ht->static_hash_table->root, sym_name, false, false, false);

                if (sym_hash == NULL || (sym_hash->flags & MN10300_CONVERT_CALL_TO_CALLS)
                    || (sym_hash->flags & MN10300_DELETED_PROLOGUE_BYTES))
                  continue;

                int bytes = 0;
                if (sym_hash->movm_args) bytes += 2;
                if (sym_hash->stack_size > 0)
                  bytes += (sym_hash->stack_size <= 128) ? 3 : 4;

                if (bytes > 0)
                  {
                    elf_section_data(section)->relocs = internal_relocs_local;
                    elf_section_data(section)->this_hdr.contents = contents_local;
                    symtab_hdr_local->contents = (unsigned char *) isymbuf_local;

                    sym_hash->flags |= MN10300_DELETED_PROLOGUE_BYTES;

                    if (!mn10300_elf_relax_delete_bytes(input_bfd, section, isym->st_value, bytes))
                      { ret = false; goto cleanup_section_loop; }
                    *again_ptr = true;
                  }
              }

            // Process global functions
            unsigned int symcount_global = (symtab_hdr_local->sh_size / sizeof(Elf32_External_Sym) - symtab_hdr_local->sh_info);
            struct elf_link_hash_entry **hashes = elf_sym_hashes(input_bfd);
            struct elf_link_hash_entry **end_hashes = hashes + symcount_global;
            for (; hashes < end_hashes; hashes++)
              {
                struct elf32_mn10300_link_hash_entry *sym_hash = (struct elf32_mn10300_link_hash_entry *) *hashes;
                if (!((sym_hash->root.root.type == bfd_link_hash_defined || sym_hash->root.root.type == bfd_link_hash_defweak)
                      && sym_hash->root.root.u.def.section == section
                      && !(sym_hash->flags & MN10300_CONVERT_CALL_TO_CALLS)
                      && !(sym_hash->flags & MN10300_DELETED_PROLOGUE_BYTES)))
                  continue;

                int bytes = 0;
                if (sym_hash->movm_args) bytes += 2;
                if (sym_hash->stack_size > 0)
                  bytes += (sym_hash->stack_size <= 128) ? 3 : 4;

                if (bytes > 0)
                  {
                    elf_section_data(section)->relocs = internal_relocs_local;
                    elf_section_data(section)->this_hdr.contents = contents_local;
                    symtab_hdr_local->contents = (unsigned char *) isymbuf_local;

                    sym_hash->flags |= MN10300_DELETED_PROLOGUE_BYTES;
                    bfd_vma symval = sym_hash->root.root.u.def.value;

                    if (!mn10300_elf_relax_delete_bytes(input_bfd, section, symval, bytes))
                      { ret = false; goto cleanup_section_loop; }

                    for (struct elf_link_hash_entry **hh = elf_sym_hashes(input_bfd); hh < end_hashes; hh++)
                      {
                        struct elf32_mn10300_link_hash_entry *h_alias = (struct elf32_mn10300_link_hash_entry *) *hh;
                        if (h_alias != sym_hash
                            && (h_alias->root.root.type == bfd_link_hash_defined || h_alias->root.root.type == bfd_link_hash_defweak)
                            && h_alias->root.root.u.def.section == section
                            && !(h_alias->flags & MN10300_CONVERT_CALL_TO_CALLS)
                            && h_alias->root.root.u.def.value == symval
                            && h_alias->root.type == STT_FUNC)
                          h_alias->flags |= MN10300_DELETED_PROLOGUE_BYTES;
                      }
                    *again_ptr = true;
                  }
              }
          cleanup_section_loop:;
            mn10300_manage_relocs_memory(section, &internal_relocs_local, current_relocs_allocated);
            mn10300_manage_contents_memory(li, section, &contents_local, current_contents_allocated);
            if (!ret) break;
          }
        cleanup_bfd_loop:;
        mn10300_manage_symbuf_memory(li, symtab_hdr_local, &isymbuf_local, current_isymbuf_allocated);
        if (!ret) break;
      }
    return ret;
  }

  if (bfd_link_relocatable (link_info))
    {
      link_info->callbacks->fatal(_("%P: --relax and -r may not be used together\n"));
      return false;
    }

  *again = false;

  hash_table = elf32_mn10300_hash_table (link_info);
  if (hash_table == NULL)
    goto error_return;

  if ((hash_table->flags & MN10300_HASH_ENTRIES_INITIALIZED) == 0)
    {
      if (!mn10300_init_hash_entries_pass(abfd, link_info, hash_table))
        goto error_return;

      {
        int static_count = 0;
        elf32_mn10300_link_hash_traverse(hash_table->static_hash_table,
                                         elf32_mn10300_count_hash_table_entries,
                                         &static_count);

        struct elf32_mn10300_link_hash_entry **entries = NULL;
        if (static_count > 0)
          {
            entries = bfd_malloc(static_count * sizeof(*entries));
            if (entries == NULL)
              goto error_return;
          }

        struct elf32_mn10300_link_hash_entry **ptr = entries;
        if (static_count > 0)
          elf32_mn10300_link_hash_traverse(hash_table->static_hash_table,
                                           elf32_mn10300_list_hash_table_entries,
                                           &ptr);

        if (static_count > 1)
          qsort(entries, static_count, sizeof(entries[0]), sort_by_value);

        for (int i = 0; i < static_count - 1; i++)
          {
            if (entries[i]->value && entries[i]->value == entries[i+1]->value)
              {
                int v = entries[i]->flags;
                int j;

                for (j = i + 1; j < static_count && entries[j]->value == entries[i]->value; j++)
                  v |= entries[j]->flags;

                for (j = i; j < static_count && entries[j]->value == entries[i]->value; j++)
                  entries[j]->flags = v;

                i = j - 1;
              }
          }
        free(entries);
      }

      hash_table->flags |= MN10300_HASH_ENTRIES_INITIALIZED;

      if (!mn10300_perform_prologue_deletion_pass(abfd, link_info, hash_table, again))
        goto error_return;
    }

  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;

  if (bfd_link_relocatable(link_info)
      || !(sec->flags & SEC_RELOC)
      || sec->reloc_count == 0
      || !(sec->flags & SEC_CODE))
    return true;

  internal_relocs = _bfd_elf_link_read_relocs(abfd, sec, NULL, NULL, link_info->keep_memory);
  if (internal_relocs == NULL)
    goto error_return;
  local_internal_relocs_allocated = true;

  Elf_Internal_Rela *irel, *irelend = internal_relocs + sec->reloc_count;
  align_gap_adjustment = 0;
  for (irel = internal_relocs; irel < irelend; irel++)
    {
      if (ELF32_R_TYPE(irel->r_info) == (int) R_MN10300_ALIGN)
        {
          bfd_vma adj = 1 << irel->r_addend;
          bfd_vma aend = irel->r_offset;
          aend = BFD_ALIGN(aend, 1 << irel->r_addend);
          adj = 2 * adj - adj - 1;

          if (align_gap_adjustment < adj
              && aend < sec->output_section->vma + sec->output_offset + sec->size)
            align_gap_adjustment = adj;
        }
    }

  for (irel = internal_relocs; irel < irelend; irel++)
    {
      int r_type = ELF32_R_TYPE(irel->r_info);
      if (r_type == (int) R_MN10300_NONE || r_type == (int) R_MN10300_8 || r_type == (int) R_MN10300_MAX)
        continue;

      if (contents == NULL)
        {
          contents = elf_section_data(sec)->this_hdr.contents;
          if (contents == NULL)
            {
              if (!bfd_malloc_and_get_section(abfd, sec, &contents))
                goto error_return;
              local_contents_allocated = true;
            }
        }

      if (isymbuf == NULL && symtab_hdr->sh_info != 0)
        {
          isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
          if (isymbuf == NULL)
            {
              isymbuf = bfd_elf_get_elf_syms(abfd, symtab_hdr, symtab_hdr->sh_info, 0,
                                             NULL, NULL, NULL);
              if (isymbuf == NULL)
                goto error_return;
              local_isymbuf_allocated = true;
            }
        }

      bfd_vma symval = 0;
      asection *sym_sec = NULL;
      struct elf32_mn10300_link_hash_entry *h = NULL;

      if (!get_reloc_symbol_info(abfd, symtab_hdr, isymbuf, ELF32_R_SYM(irel->r_info),
                                 irel->r_addend, hash_table, &sym_sec, &symval, &h))
        continue;

      elf_section_data(sec)->relocs = internal_relocs;
      elf_section_data(sec)->this_hdr.contents = contents;
      symtab_hdr->contents = (unsigned char *) isymbuf;

      if (r_type == (int) R_MN10300_PCREL32 || r_type == (int) R_MN10300_PLT32)
        {
          bfd_vma value = symval;
          if (r_type == (int) R_MN10300_PLT32
              && h != NULL
              && ELF_ST_VISIBILITY(h->root.other) != STV_INTERNAL
              && ELF_ST_VISIBILITY(h->root.other) != STV_HIDDEN
              && h->root.plt.offset != (bfd_vma) -1)
            {
              asection *splt = hash_table->root.splt;
              if (splt == NULL) goto error_return;
              value = ((splt->output_section->vma + splt->output_offset + h->root.plt.offset)
                       - (sec->output_section->vma + sec->output_offset + irel->r_offset));
            }

          if (h && (h->flags & MN10300_CONVERT_CALL_TO_CALLS))
            {
              unsigned char code = bfd_get_8(abfd, contents + irel->r_offset - 1);
              if (code == OPCODE_CALL_DD)
                {
                  bfd_put_8(abfd, OPCODE_CALLS_FC_FF_PREFIX, contents + irel->r_offset - 1);
                  bfd_put_8(abfd, 0xff, contents + irel->r_offset);
                  irel->r_offset += 1;
                  irel->r_addend += 1;
                  if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 3, 1))
                    goto error_return;
                  *again = true;
                }
            }
          else if (h)
            {
              unsigned char code = bfd_get_8(abfd, contents + irel->r_offset - 1);
              if (code == OPCODE_CALL_DD)
                {
                  bfd_put_8(abfd, h->movm_args, contents + irel->r_offset + 4);
                  bfd_put_8(abfd, h->stack_size + h->movm_stack_size, contents + irel->r_offset + 5);
                }
            }

          value -= (sec->output_section->vma + sec->output_offset);
          value -= irel->r_offset;
          value += irel->r_addend;

          bfd_signed_vma jump_offset = (sec->output_section == sym_sec->output_section) ? 0x8001 : 0x7fff;

          if ((bfd_signed_vma) value < jump_offset - (bfd_signed_vma) align_gap_adjustment
              && ((bfd_signed_vma) value > -0x8000 + (bfd_signed_vma) align_gap_adjustment))
            {
              unsigned char code = bfd_get_8(abfd, contents + irel->r_offset - 1);
              if (code != OPCODE_BR_CC && code != OPCODE_CALL_DD && code != 0xff)
                continue;

              if (code == OPCODE_BR_CC) bfd_put_8(abfd, OPCODE_BR_CC_16, contents + irel->r_offset - 1);
              else if (code == OPCODE_CALL_DD) bfd_put_8(abfd, OPCODE_CALL_CD, contents + irel->r_offset - 1);
              else if (code == 0xff) bfd_put_8(abfd, OPCODE_CALLS_FA_FF_PREFIX, contents + irel->r_offset - 2);

              irel->r_info = ELF32_R_INFO(ELF32_R_SYM(irel->r_info),
                                          (r_type == (int) R_MN10300_PLT32) ? R_MN10300_PLT16 : R_MN10300_PCREL16);

              if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 1, 2))
                goto error_return;
              *again = true;
            }
        }
      else if (r_type == (int) R_MN10300_PCREL16)
        {
          bfd_vma value = symval;
          if (h && (h->flags & MN10300_CONVERT_CALL_TO_CALLS))
            {
              unsigned char code = bfd_get_8(abfd, contents + irel->r_offset - 1);
              if (code == OPCODE_CALL_CD)
                {
                  bfd_put_8(abfd, OPCODE_CALLS_FA_FF_PREFIX, contents + irel->r_offset - 1);
                  bfd_put_8(abfd, 0xff, contents + irel->r_offset);
                  irel->r_offset += 1;
                  irel->r_addend += 1;
                  if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 1, 1))
                    goto error_return;
                  *again = true;
                }
            }
          else if (h)
            {
              unsigned char code = bfd_get_8(abfd, contents + irel->r_offset - 1);
              if (code == OPCODE_CALL_CD)
                {
                  bfd_put_8(abfd, h->movm_args, contents + irel->r_offset + 2);
                  bfd_put_8(abfd, h->stack_size + h->movm_stack_size, contents + irel->r_offset + 3);
                }
            }

          value -= (sec->output_section->vma + sec->output_offset);
          value -= irel->r_offset;
          value += irel->r_addend;

          if ((long) value < 0x80 && (long) value > -0x80)
            {
              unsigned char code = bfd_get_8(abfd, contents + irel->r_offset - 1);
              if (code != OPCODE_BR_CC_16)
                continue;

              bfd_put_8(abfd, OPCODE_BR_CA, contents + irel->r_offset - 1);
              irel->r_info = ELF32_R_INFO(ELF32_R_SYM(irel->r_info), R_MN10300_PCREL8);
              if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 1, 1))
                goto error_return;
              *again = true;
            }

          // Try to eliminate unconditional branch
          Elf_Internal_Rela *nrel = irel + 1;
          if (nrel < irelend && ELF32_R_TYPE(irel->r_info) == (int) R_MN10300_PCREL8
              && ELF32_R_TYPE(nrel->r_info) == (int) R_MN10300_PCREL8)
            {
              if (irel->r_offset == sec->size) continue;
              unsigned char code_next_instr = bfd_get_8(abfd, contents + irel->r_offset + 1);
              if (code_next_instr != OPCODE_BR_CA) continue;
              if (irel->r_offset + 2 != nrel->r_offset) continue;
              if (symval != (sec->output_section->vma + sec->output_offset + irel->r_offset + 3)) continue;

              unsigned char code_current_instr = bfd_get_8(abfd, contents + irel->r_offset - 1);
              if (! (code_current_instr >= 0xc0 && code_current_instr <= 0xc9)
                  && ! (code_current_instr >= 0xe8 && code_current_instr <= 0xeb)
                  && code_current_instr != 0x9d)
                continue;

              if (mn10300_elf_symbol_address_p(abfd, sec, isymbuf, irel->r_offset + 1))
                continue;

              switch (code_current_instr)
                {
                case 0xc8: code_current_instr = 0xc9; break; case 0xc9: code_current_instr = 0xc8; break;
                case 0xc0: code_current_instr = 0xc2; break; case 0xc2: code_current_instr = 0xc0; break;
                case 0xc3: code_current_instr = 0xc1; break; case 0xc1: code_current_instr = 0xc3; break;
                case 0xc4: code_current_instr = 0xc6; break; case 0xc6: code_current_instr = 0xc4; break;
                case 0xc7: code_current_instr = 0xc5; break; case 0xc5: code_current_instr = 0xc7; break;
                case 0xe8: code_current_instr = 0xe9; break; case 0x9d: code_current_instr = 0xe8; break;
                case 0xea: code_current_instr = 0xeb; break; case 0xeb: code_current_instr = 0xea; break;
                default: break;
                }
              bfd_put_8(abfd, code_current_instr, contents + irel->r_offset - 1);

              irel->r_info = nrel->r_info;
              nrel->r_info = ELF32_R_INFO(ELF32_R_SYM(nrel->r_info), R_MN10300_NONE);

              if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 1, 2))
                goto error_return;
              *again = true;
            }
        }
      else if (r_type == (int) R_MN10300_24)
        {
          bfd_vma value = symval + irel->r_addend;
          if ((long) value < 0x7f && (long) value > -0x80)
            {
              if (irel->r_offset < 3) continue;
              unsigned char code_prefix = bfd_get_8(abfd, contents + irel->r_offset - 3);
              if (code_prefix == OPCODE_AM33_24BIT_PREFIX)
                {
                  unsigned char code_op = bfd_get_8(abfd, contents + irel->r_offset - 2);
                  if (code_op != 0x6b && code_op != 0x7b && code_op != 0x8b && code_op != 0x9b
                      && ((code_op & 0x0f) == 0x09 || (code_op & 0x0f) == 0x08
                          || (code_op & 0x0f) == 0x0a || (code_op & 0x0f) == 0x0b
                          || (code_op & 0x0f) == 0x0e))
                    {
                      if ((value & 0x80) == 0)
                        {
                          bfd_put_8(abfd, OPCODE_AM33_8BIT_PREFIX, contents + irel->r_offset - 3);
                          bfd_put_8(abfd, code_op, contents + irel->r_offset - 2);
                          irel->r_info = ELF32_R_INFO(ELF32_R_SYM(irel->r_info), R_MN10300_8);
                          if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 1, 2))
                            goto error_return;
                          *again = true;
                        }
                    }
                }
            }
        }
      else if (r_type == (int) R_MN10300_32
               || r_type == (int) R_MN10300_GOT32
               || r_type == (int) R_MN10300_GOTOFF32)
        {
          bfd_vma value = symval;
          if (r_type != (int) R_MN10300_32)
            {
              asection *sgot = hash_table->root.sgot;
              if (sgot == NULL) goto error_return;

              if (r_type == (int) R_MN10300_GOT32)
                {
                  value = sgot->output_offset;
                  if (h) value += h->root.got.offset;
                  else value += elf_local_got_offsets(abfd)[ELF32_R_SYM(irel->r_info)];
                }
              else if (r_type == (int) R_MN10300_GOTOFF32)
                value -= sgot->output_section->vma;
              else if (r_type == (int) R_MN10300_GOTPC32)
                value = (sgot->output_section->vma - (sec->output_section->vma + sec->output_offset + irel->r_offset));
              else
                abort();
            }
          value += irel->r_addend;

          // 32-bit to 24-bit
          if (value + 0x800000 < 0x1000000 && irel->r_offset >= 3)
            {
              unsigned char code_prefix = bfd_get_8(abfd, contents + irel->r_offset - 3);
              if (code_prefix == OPCODE_AM33_32BIT_PREFIX)
                {
                  unsigned char code_op = bfd_get_8(abfd, contents + irel->r_offset - 2);
                  if (code_op != 0x6b && code_op != 0x7b && code_op != 0x8b && code_op != 0x9b
                      && r_type != (int) R_MN10300_GOTPC32
                      && ((code_op & 0x0f) == 0x09 || (code_op & 0x0f) == 0x08
                          || (code_op & 0x0f) == 0x0a || (code_op & 0x0f) == 0x0b
                          || (code_op & 0x0f) == 0x0e))
                    {
                      if ((value & 0x8000) == 0)
                        {
                          bfd_put_8(abfd, OPCODE_AM33_24BIT_PREFIX, contents + irel->r_offset - 3);
                          bfd_put_8(abfd, code_op, contents + irel->r_offset - 2);

                          int new_r_type;
                          if (r_type == (int) R_MN10300_GOTOFF32) new_r_type = R_MN10300_GOTOFF24;
                          else if (r_type == (int) R_MN10300_GOT32) new_r_type = R_MN10300_GOT24;
                          else new_r_type = R_MN10300_24;
                          irel->r_info = ELF32_R_INFO(ELF32_R_SYM(irel->r_info), new_r_type);

                          if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 3, 1))
                            goto error_return;
                          *again = true;
                        }
                    }
                }
            }

          // 32-bit to 16-bit
          if (value + 0x8000 < 0x10000 && irel->r_offset >= 2)
            {
              unsigned char code_prefix = bfd_get_8(abfd, contents + irel->r_offset - 2);
              if (code_prefix != OPCODE_CALLS_FC_FF_PREFIX) continue;

              unsigned char code_op = bfd_get_8(abfd, contents + irel->r_offset - 1);
              int new_r_type;
              bool relaxed_in_block = false;

              if ((code_op & 0xf0) < 0x80)
                {
                  if (code_op == 0xcc && (value & 0x8000)) goto end_32_to_16_block;
                  new_r_type = (r_type == R_MN10300_GOTOFF32) ? R_MN10300_GOTOFF16
                               : (r_type == R_MN10300_GOT32) ? R_MN10300_GOT16
                               : (r_type == R_MN10300_GOTPC32) ? R_MN10300_GOTPC16 : R_MN10300_16;
                  bfd_put_8(abfd, OPCODE_AM33_16BIT_PREFIX, contents + irel->r_offset - 2); // Replace 0xfc with 0xfa
                  if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 2, 2)) goto error_return;
                  relaxed_in_block = true;
                }
              else if ((code_op & 0xf0) == 0x80 || (code_op & 0xf0) == 0x90)
                {
                  switch (code_op & 0xf3)
                    {
                    case 0x81: case 0x82: case 0x83:
                      if ((code_op & 0xf3) == 0x81) code_op = 0x01 + (code_op & 0x0c);
                      else if ((code_op & 0xf3) == 0x82) code_op = 0x02 + (code_op & 0x0c);
                      else if ((code_op & 0xf3) == 0x83) code_op = 0x03 + (code_op & 0x0c);
                      bfd_put_8(abfd, code_op, contents + irel->r_offset - 2);
                      irel->r_offset -= 1;
                      if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 1, 3)) goto error_return;
                      relaxed_in_block = true;
                      break;
                    case 0x80: case 0x90: case 0x91: case 0x92: case 0x93:
                      if (code_op >= 0x90 && code_op <= 0x93 && (long) value < 0) goto end_32_to_16_block;
                      bfd_put_8(abfd, OPCODE_AM33_16BIT_PREFIX, contents + irel->r_offset - 2);
                      bfd_put_8(abfd, code_op, contents + irel->r_offset - 1);
                      if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 2, 2)) goto error_return;
                      relaxed_in_block = true;
                      break;
                    }
                  if (relaxed_in_block) {
                    new_r_type = (r_type == R_MN10300_GOTOFF32) ? R_MN10300_GOTOFF16
                                 : (r_type == R_MN10300_GOT32) ? R_MN10300_GOT16
                                 : (r_type == R_MN10300_GOTPC32) ? R_MN10300_GOTPC16 : R_MN10300_16;
                  }
                }
              else if ((code_op & 0xf0) < 0xf0)
                {
                  switch (code_op & 0xfc)
                    {
                    case 0xcc: case 0xdc: case 0xa4: case 0xa8: case 0xac:
                      if (code_op == 0xcc && (value & 0x8000)) goto end_32_to_16_block;
                      if ((code_op & 0xfc) == 0xdc && (long) value < 0) goto end_32_to_16_block;

                      if ((code_op & 0xfc) == 0xcc) code_op = 0x2c + (code_op & 0x03);
                      else if ((code_op & 0xfc) == 0xdc) code_op = 0x24 + (code_op & 0x03);
                      else if ((code_op & 0xfc) == 0xa4) code_op = 0x30 + (code_op & 0x03);
                      else if ((code_op & 0xfc) == 0xa8) code_op = 0x34 + (code_op & 0x03);
                      else if ((code_op & 0xfc) == 0xac) code_op = 0x38 + (code_op & 0x03);
                      else abort();
                      bfd_put_8(abfd, code_op, contents + irel->r_offset - 2);
                      irel->r_offset -= 1;
                      if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 1, 3)) goto error_return;
                      relaxed_in_block = true;
                      break;
                    case 0xa0: case 0xb0: case 0xb1: case 0xb2: case 0xb3:
                    case 0xc0: case 0xc8: case 0xd0: case 0xd8: case 0xe0:
                    case 0xe1: case 0xe2: case 0xe3:
                      if (code_op == 0xdc && (long) value < 0) goto end_32_to_16_block;
                      if (code_op >= 0xb0 && code_op <= 0xb3 && (long) value < 0) goto end_32_to_16_block;
                      bfd_put_8(abfd, OPCODE_AM33_16BIT_PREFIX, contents + irel->r_offset - 2);
                      bfd_put_8(abfd, code_op, contents + irel->r_offset - 1);
                      if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 2, 2)) goto error_return;
                      relaxed_in_block = true;
                      break;
                    }
                  if (relaxed_in_block) {
                    new_r_type = (r_type == R_MN10300_GOTOFF32) ? R_MN10300_GOTOFF16
                                 : (r_type == R_MN10300_GOT32) ? R_MN10300_GOT16
                                 : (r_type == R_MN10300_GOTPC32) ? R_MN10300_GOTPC16 : R_MN10300_16;
                  }
                }
              else if (code_op == OPCODE_AM33_32BIT_PREFIX)
                {
                  bfd_put_8(abfd, OPCODE_AM33_16BIT_PREFIX, contents + irel->r_offset - 2);
                  bfd_put_8(abfd, OPCODE_AM33_32BIT_PREFIX, contents + irel->r_offset - 1);
                  if (!mn10300_elf_relax_delete_bytes(abfd, sec, irel->r_offset + 2, 2)) goto error_return;
                  relaxed_in_block = true;
                  new_r_type = (r_type == R_MN10300_GOTOFF32) ? R_MN10300_GOTOFF16
                               : (r_type == R_MN10300_GOT32) ? R_MN10300_GOT16
                               : (r_type == R_MN10300_GOTPC32) ? R_MN10300_GOTPC16 : R_MN10300_16;
                }

              if (relaxed_in_block)
                {
                  irel->r_info = ELF32_R_INFO(ELF32_R_SYM(irel->r_info), new_r_type);
                  *again = true;
                }
            }
        }
      end_32_to_16_block:; // Label for goto in inner loops
    }

  mn10300_manage_symbuf_memory(link_info, symtab_hdr, &isymbuf, local_isymbuf_allocated);
  mn10300_manage_contents_memory(link_info, sec, &contents, local_contents_allocated);
  mn10300_manage_relocs_memory(sec, &internal_relocs, local_internal_relocs_allocated);

  return true;

 error_return:
  if (symtab_hdr != NULL)
    mn10300_manage_symbuf_memory(link_info, symtab_hdr, &isymbuf, local_isymbuf_allocated);
  mn10300_manage_contents_memory(link_info, sec, &contents, local_contents_allocated);
  mn10300_manage_relocs_memory(sec, &internal_relocs, local_internal_relocs_allocated);

  return false;
}

/* This is a version of bfd_generic_get_relocated_section_contents
   which uses mn10300_elf_relocate_section.  */

#include "bfd.h"
#include "elf-bfd.h"
#include "libbfd.h"
#include <string.h> // For memcpy
#include <stddef.h> // For size_t

// Forward declaration for mn10300_elf_relocate_section, as it's used
// but not defined in the provided snippet. Assume it's available from
// an appropriate header or defined elsewhere in the compilation unit.
extern bool mn10300_elf_relocate_section (bfd *, struct bfd_link_info *,
                                          bfd *, asection *, bfd_byte *,
                                          Elf_Internal_Rela *, Elf_Internal_Sym *,
                                          asection **);

static bfd_byte *
mn10300_elf_get_relocated_section_contents (bfd *output_bfd,
					    struct bfd_link_info *link_info,
					    struct bfd_link_order *link_order,
					    bfd_byte *data,
					    bool relocatable,
					    asymbol **symbols)
{
  asection *input_section = link_order->u.indirect.section;
  bfd *input_bfd = input_section->owner;
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;

  // target_data is the buffer where contents will be written.
  // allocated_data_on_null_input tracks if we allocated target_data locally.
  bfd_byte *target_data = data;
  bfd_byte *allocated_data_on_null_input = NULL;

  // Resources that might be allocated and need freeing.
  asection **sections = NULL;
  Elf_Internal_Rela *internal_relocs = NULL;
  Elf_Internal_Sym *isymbuf = NULL;

  // Flags to track ownership of internal_relocs and isymbuf,
  // as they might point to internal BFD structures or newly allocated memory.
  bool isymbuf_is_ours = false;
  bool internal_relocs_is_ours = false;

  // Flag to indicate overall success for the cleanup block.
  bool success = false;

  // Early exit for cases not handled by this specific function.
  if (relocatable
      || elf_section_data (input_section)->this_hdr.contents == NULL)
    {
      return bfd_generic_get_relocated_section_contents (output_bfd, link_info,
						       link_order, data,
						       relocatable,
						       symbols);
    }

  // If no output buffer is provided, allocate one.
  if (target_data == NULL)
    {
      target_data = bfd_malloc (input_section->size);
      if (target_data == NULL)
	return NULL; // Immediate failure on allocation
      allocated_data_on_null_input = target_data; // Mark as locally allocated
    }

  // Copy the original section contents into the target buffer.
  memcpy (target_data, elf_section_data (input_section)->this_hdr.contents,
	  (size_t) input_section->size);

  // Proceed with relocation logic if the section has relocations.
  if ((input_section->flags & SEC_RELOC) != 0
      && input_section->reloc_count > 0)
    {
      // Read relocations for the input section.
      internal_relocs = _bfd_elf_link_read_relocs (input_bfd, input_section,
						   NULL, NULL, false);
      if (internal_relocs == NULL)
	goto cleanup; // Failed to read relocations

      // Check if _bfd_elf_link_read_relocs returned a pointer to internal data
      // or a newly allocated buffer.
      if (internal_relocs != elf_section_data (input_section)->relocs)
        internal_relocs_is_ours = true;

      // Handle symbol table if present.
      if (symtab_hdr->sh_info != 0)
	{
	  // First, try to use cached symbol table contents.
	  isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
	  if (isymbuf == NULL)
	    {
	      // If not cached, load the symbols.
	      isymbuf = bfd_elf_get_elf_syms (input_bfd, symtab_hdr,
						    symtab_hdr->sh_info, 0,
						    NULL, NULL, NULL);
	      if (isymbuf == NULL)
		goto cleanup; // Failed to get symbols
	      isymbuf_is_ours = true; // Mark as newly allocated
	    }
	}

      // Allocate the array to store section pointers for symbols.
      bfd_size_type sections_amt = symtab_hdr->sh_info;
      if (sections_amt > 0) // Only allocate if there are symbols
        {
          sections = bfd_malloc (sections_amt * sizeof (asection *));
          if (sections == NULL)
            goto cleanup; // Failed to allocate sections array
        }

      // Populate the sections array with pointers corresponding to symbol indices.
      Elf_Internal_Sym *current_isym = isymbuf;
      asection **current_secpp = sections;
      for (size_t i = 0; i < symtab_hdr->sh_info; ++i, ++current_isym, ++current_secpp)
	{
	  asection *isec;
	  switch (current_isym->st_shndx)
	    {
	    case SHN_UNDEF:
	      isec = bfd_und_section_ptr;
	      break;
	    case SHN_ABS:
	      isec = bfd_abs_section_ptr;
	      break;
	    case SHN_COMMON:
	      isec = bfd_com_section_ptr;
	      break;
	    default:
	      isec = bfd_section_from_elf_index (input_bfd, current_isym->st_shndx);
	      break;
	    }
	  *current_secpp = isec;
	}

      // Perform the actual relocation process.
      if (! mn10300_elf_relocate_section (output_bfd, link_info, input_bfd,
					  input_section, target_data, internal_relocs,
					  isymbuf, sections))
	goto cleanup; // Relocation failed
    }

  success = true; // If we reach here, all operations were successful

cleanup:
  // Free any locally allocated resources based on ownership flags.
  if (sections != NULL)
    free (sections);

  if (isymbuf_is_ours)
    free (isymbuf);

  if (internal_relocs_is_ours)
    free (internal_relocs);

  // If we allocated the data buffer and the function failed, free it.
  if (!success && allocated_data_on_null_input != NULL)
    free (allocated_data_on_null_input);

  // Return the processed data buffer on success, or NULL on failure.
  return success ? target_data : NULL;
}

/* Assorted hash table functions.  */

/* Initialize an entry in the link hash table.  */

/* Create an entry in an MN10300 ELF linker hash table.  */

static struct bfd_hash_entry *
elf32_mn10300_link_hash_newfunc (struct bfd_hash_entry *entry,
				 struct bfd_hash_table *table,
				 const char *string)
{
  struct elf32_mn10300_link_hash_entry *ret;

  ret = (struct elf32_mn10300_link_hash_entry *) entry;

  if (ret == NULL)
    {
      ret = (struct elf32_mn10300_link_hash_entry *)
	   bfd_hash_allocate (table, sizeof (struct elf32_mn10300_link_hash_entry));
      if (ret == NULL)
        {
          return NULL;
        }
    }

  ret = (struct elf32_mn10300_link_hash_entry *)
	 _bfd_elf_link_hash_newfunc ((struct bfd_hash_entry *) ret,
				     table, string);
  if (ret != NULL)
    {
      ret->direct_calls = 0;
      ret->stack_size = 0;
      ret->movm_args = 0;
      ret->movm_stack_size = 0;
      ret->flags = 0;
      ret->value = 0;
      ret->tls_type = GOT_UNKNOWN;
    }

  return (struct bfd_hash_entry *) ret;
}

static void
_bfd_mn10300_copy_indirect_symbol (struct bfd_link_info *	 info,
				   struct elf_link_hash_entry *	 dir,
				   struct elf_link_hash_entry *	 ind)
{
  struct elf32_mn10300_link_hash_entry *edir = elf_mn10300_hash_entry (dir);
  struct elf32_mn10300_link_hash_entry *eind = elf_mn10300_hash_entry (ind);

  if (ind->root.type == bfd_link_hash_indirect
      && dir->got.refcount <= 0)
    {
      edir->tls_type = eind->tls_type;
      eind->tls_type = GOT_UNKNOWN;
    }

  edir->direct_calls = eind->direct_calls;
  edir->stack_size = eind->stack_size;
  edir->movm_args = eind->movm_args;
  edir->movm_stack_size = eind->movm_stack_size;
  edir->flags = eind->flags;

  _bfd_elf_link_hash_copy_indirect (info, dir, ind);
}

/* Destroy an mn10300 ELF linker hash table.  */

static void
elf32_mn10300_link_hash_table_free (bfd *obfd)
{
  if (obfd == NULL || obfd->link.hash == NULL)
    return;

  struct elf32_mn10300_link_hash_table *const custom_hash_table
    = (struct elf32_mn10300_link_hash_table *) obfd->link.hash;

  struct bfd_link_hash_table *static_ht_to_free = NULL;
  if (custom_hash_table->static_hash_table != NULL)
    {
      static_ht_to_free = &custom_hash_table->static_hash_table->root.root;
    }

  struct bfd_link_hash_table *main_ht_to_free
    = &custom_hash_table->root.root;

  if (static_ht_to_free != NULL)
    {
      obfd->link.hash = static_ht_to_free;
      _bfd_elf_link_hash_table_free (obfd);
    }

  obfd->is_linker_output = true;

  obfd->link.hash = main_ht_to_free;
  _bfd_elf_link_hash_table_free (obfd);
}

/* Create an mn10300 ELF linker hash table.  */

static struct bfd_link_hash_table *
elf32_mn10300_link_hash_table_create (bfd *abfd)
{
  struct elf32_mn10300_link_hash_table *ret = NULL;

  ret = bfd_zmalloc (sizeof (*ret));
  if (ret == NULL)
    goto fail_ret_alloc;

  ret->static_hash_table = bfd_zmalloc (sizeof (struct elf_link_hash_table));
  if (ret->static_hash_table == NULL)
    goto fail_static_hash_table_alloc;

  if (!_bfd_elf_link_hash_table_init (&ret->static_hash_table->root, abfd,
				      elf32_mn10300_link_hash_newfunc,
				      sizeof (struct elf32_mn10300_link_hash_entry)))
    goto fail_static_hash_table_init;

  abfd->is_linker_output = false;
  abfd->link.hash = NULL;

  if (!_bfd_elf_link_hash_table_init (&ret->root, abfd,
				      elf32_mn10300_link_hash_newfunc,
				      sizeof (struct elf32_mn10300_link_hash_entry)))
    {
      abfd->is_linker_output = true;
      abfd->link.hash = &ret->static_hash_table->root.root;
      _bfd_elf_link_hash_table_free (abfd);
      goto fail_main_hash_table_init;
    }

  ret->root.root.hash_table_free = elf32_mn10300_link_hash_table_free;

  ret->tls_ldm_got.offset = -1;

  return &ret->root.root;

fail_main_hash_table_init:
  /* In this error path, ret->static_hash_table->root was conceptually 'freed'
     via _bfd_elf_link_hash_table_free(abfd).
     The original code only freed 'ret' here, implicitly leaving 'ret->static_hash_table'
     allocated but detached from the freed root. This behavior is preserved
     to avoid altering external functionality. */
  if (ret != NULL)
    free (ret);
  return NULL;

fail_static_hash_table_init:
  /* If _bfd_elf_link_hash_table_init for static_hash_table->root failed,
     its internal structures were not fully established, so we can directly
     free the container struct. */
  if (ret->static_hash_table != NULL)
    free (ret->static_hash_table);
  /* Fall through to free 'ret' */

fail_static_hash_table_alloc:
  /* If ret->static_hash_table allocation failed, it means 'ret->static_hash_table'
     is NULL, so only 'ret' needs to be freed. */
  if (ret != NULL)
    free (ret);
  /* Fall through to return NULL */

fail_ret_alloc:
  /* If 'ret' allocation failed, 'ret' is NULL, and nothing was allocated yet. */
  return NULL;
}

static unsigned long
elf_mn10300_mach (flagword flags)
{
  switch (flags & EF_MN10300_MACH)
    {
    case E_MN10300_MACH_MN10300:
      return bfd_mach_mn10300;

    case E_MN10300_MACH_AM33:
      return bfd_mach_am33;

    case E_MN10300_MACH_AM33_2:
      return bfd_mach_am33_2;

    default: /* Handle all other cases explicitly returning the default machine. */
      return bfd_mach_mn10300;
    }
}

/* The final processing done just before writing out a MN10300 ELF object
   file.  This gets the MN10300 architecture right based on the machine
   number.  */

#include <stdbool.h>
#include "bfd.h"
#include "elf-bfd.h"

static bool
_bfd_mn10300_elf_final_write_processing (bfd *abfd)
{
  unsigned long val = E_MN10300_MACH_MN10300;
  bfd_vma mach_type = bfd_get_mach(abfd);

  switch (mach_type)
    {
    case bfd_mach_am33:
      val = E_MN10300_MACH_AM33;
      break;

    case bfd_mach_am33_2:
      val = E_MN10300_MACH_AM33_2;
      break;
    }

  Elf_Internal_Ehdr *ehdr = elf_elfheader(abfd);
  if (ehdr == NULL)
    {
      return false;
    }

  ehdr->e_flags &= ~EF_MN10300_MACH;
  ehdr->e_flags |= val;

  return _bfd_elf_final_write_processing (abfd);
}

static bool
_bfd_mn10300_elf_object_p (bfd *abfd)
{
  if (abfd == NULL)
    {
      return false;
    }

  const Elf_Internal_Ehdr *ehdr = elf_elfheader (abfd);
  if (ehdr == NULL)
    {
      return false;
    }

  bfd_default_set_arch_mach (abfd, bfd_arch_mn10300,
                             elf_mn10300_mach (ehdr->e_flags));
  return true;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bool
_bfd_mn10300_elf_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;

  if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour
      || bfd_get_flavour (obfd) != bfd_target_elf_flavour)
    {
      return true;
    }

  enum bfd_architecture input_arch = bfd_get_arch (ibfd);
  unsigned long input_mach = bfd_get_mach (ibfd);
  enum bfd_architecture output_arch = bfd_get_arch (obfd);
  unsigned long output_mach = bfd_get_mach (obfd);

  if (output_arch == input_arch && output_mach < input_mach)
    {
      if (!bfd_set_arch_mach (obfd, input_arch, input_mach))
        {
          return false;
        }
    }

  return true;
}

#define PLT0_ENTRY_SIZE     15
#define PLT_ENTRY_SIZE      20
#define PIC_PLT_ENTRY_SIZE  24

static const bfd_byte elf_mn10300_plt0_entry[PLT0_ENTRY_SIZE] =
{
  0xfc, 0xa0, 0, 0, 0, 0,	/* mov	(.got+8),a0 */
  0xfe, 0xe, 0x10, 0, 0, 0, 0,	/* mov	(.got+4),r1 */
  0xf0, 0xf4,			/* jmp	(a0) */
};

static const bfd_byte elf_mn10300_plt_entry[PLT_ENTRY_SIZE] =
{
  0xfc, 0xa0, 0, 0, 0, 0,	/* mov	(nameN@GOT + .got),a0 */
  0xf0, 0xf4,			/* jmp	(a0) */
  0xfe, 8, 0, 0, 0, 0, 0,	/* mov	reloc-table-address,r0 */
  0xdc, 0, 0, 0, 0,		/* jmp	.plt0 */
};

static const bfd_byte elf_mn10300_pic_plt_entry[PIC_PLT_ENTRY_SIZE] =
{
  0xfc, 0x22, 0, 0, 0, 0,	/* mov	(nameN@GOT,a2),a0 */
  0xf0, 0xf4,			/* jmp	(a0) */
  0xfe, 8, 0, 0, 0, 0, 0,	/* mov	reloc-table-address,r0 */
  0xf8, 0x22, 8,		/* mov	(8,a2),a0 */
  0xfb, 0xa, 0x1a, 4,		/* mov	(4,a2),r1 */
  0xf0, 0xf4,			/* jmp	(a0) */
};

/* Return size of the first PLT entry.  */
#define elf_mn10300_sizeof_plt0(info) \
  (bfd_link_pic (info) ? PIC_PLT_ENTRY_SIZE : PLT0_ENTRY_SIZE)

/* Return size of a PLT entry.  */
#define elf_mn10300_sizeof_plt(info) \
  (bfd_link_pic (info) ? PIC_PLT_ENTRY_SIZE : PLT_ENTRY_SIZE)

/* Return offset of the PLT0 address in an absolute PLT entry.  */
#define elf_mn10300_plt_plt0_offset(info) 16

/* Return offset of the linker in PLT0 entry.  */
#define elf_mn10300_plt0_linker_offset(info) 2

/* Return offset of the GOT id in PLT0 entry.  */
#define elf_mn10300_plt0_gotid_offset(info) 9

/* Return offset of the temporary in PLT entry.  */
#define elf_mn10300_plt_temp_offset(info) 8

/* Return offset of the symbol in PLT entry.  */
#define elf_mn10300_plt_symbol_offset(info) 2

/* Return offset of the relocation in PLT entry.  */
#define elf_mn10300_plt_reloc_offset(info) 11

/* The name of the dynamic interpreter.  This is put in the .interp
   section.  */

#define ELF_DYNAMIC_INTERPRETER "/lib/ld.so.1"

/* Create dynamic sections when linking against a dynamic object.  */

static bool
_bfd_mn10300_elf_create_dynamic_sections (bfd *abfd, struct bfd_link_info *info)
{
  flagword   base_flags;
  asection * s;
  const struct elf_backend_data * bed = get_elf_backend_data (abfd);
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  int ptralign;
  const char *rel_plt_name;
  const char *rel_bss_name;

  switch (bed->s->arch_size)
    {
    case 32:
      ptralign = 2;
      break;

    case 64:
      ptralign = 3;
      break;

    default:
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  base_flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY
	        | SEC_LINKER_CREATED);

  if (bed->default_use_rela_p)
    {
      rel_plt_name = ".rela.plt";
      rel_bss_name = ".rela.bss";
    }
  else
    {
      rel_plt_name = ".rel.plt";
      rel_bss_name = ".rel.bss";
    }

  s = bfd_make_section_anyway_with_flags (abfd, rel_plt_name, base_flags | SEC_READONLY);
  htab->root.srelplt = s;
  if (s == NULL
      || !bfd_set_section_alignment (s, ptralign))
    return false;

  if (!_bfd_mn10300_elf_create_got_section (abfd, info))
    return false;

  if (bed->want_dynbss)
    {
      s = bfd_make_section_anyway_with_flags (abfd, ".dynbss",
					      SEC_ALLOC | SEC_LINKER_CREATED);
      if (s == NULL)
	return false;

      if (!bfd_link_pic (info))
	{
	  s = bfd_make_section_anyway_with_flags (abfd, rel_bss_name,
						  base_flags | SEC_READONLY);
	  if (s == NULL
	      || !bfd_set_section_alignment (s, ptralign))
	    return false;
	}
    }

  return true;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bool
_bfd_mn10300_elf_adjust_dynamic_symbol (struct bfd_link_info * info,
					struct elf_link_hash_entry * h)
{
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  bfd * dynobj;
  asection * s;

  if (htab == NULL)
    return false;

  dynobj = htab->root.dynobj;

  BFD_ASSERT (dynobj != NULL
	      && (h->needs_plt
		  || h->is_weakalias
		  || (h->def_dynamic
		      && h->ref_regular
		      && !h->def_regular)));

  if (h->type == STT_FUNC
      || h->needs_plt)
    {
      if (! bfd_link_pic (info)
	  && !h->def_dynamic
	  && !h->ref_dynamic)
	{
	  BFD_ASSERT (h->needs_plt);
	  return true;
	}

      if (h->dynindx == -1)
	{
	  if (! bfd_elf_link_record_dynamic_symbol (info, h))
	    return false;
	}

      s = htab->root.splt;
      BFD_ASSERT (s != NULL);

      if (s->size == 0)
	s->size += elf_mn10300_sizeof_plt0 (info);

      if (! bfd_link_pic (info)
	  && !h->def_regular)
	{
	  h->root.u.def.section = s;
	  h->root.u.def.value = s->size;
	}

      h->plt.offset = s->size;

      s->size += elf_mn10300_sizeof_plt (info);

      s = htab->root.sgotplt;
      BFD_ASSERT (s != NULL);
      s->size += 4;

      s = htab->root.srelplt;
      BFD_ASSERT (s != NULL);
      s->size += sizeof (Elf32_External_Rela);

      return true;
    }

  if (h->is_weakalias)
    {
      struct elf_link_hash_entry *def = weakdef (h);
      BFD_ASSERT (def != NULL);
      BFD_ASSERT (def->root.type == bfd_link_hash_defined);
      h->root.u.def.section = def->root.u.def.section;
      h->root.u.def.value = def->root.u.def.value;
      return true;
    }

  if (bfd_link_pic (info))
    return true;

  if (!h->non_got_ref)
    return true;

  s = bfd_get_linker_section (dynobj, ".dynbss");
  if (s == NULL)
    return false;

  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
      asection * srel;

      srel = bfd_get_linker_section (dynobj, ".rela.bss");
      if (srel == NULL)
	return false;
      srel->size += sizeof (Elf32_External_Rela);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, s);
}

/* Set the sizes of the dynamic sections.  */

static bool
_bfd_mn10300_elf_late_size_sections (bfd * output_bfd,
				     struct bfd_link_info * info)
{
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  bfd * dynobj;
  asection * s;
  bool relocs = false;

  dynobj = htab->root.dynobj;
  if (dynobj == NULL)
    {
      return true;
    }

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      if (bfd_link_executable (info) && !info->nointerp)
	{
	  s = bfd_get_linker_section (dynobj, ".interp");
	  if (s == NULL)
	    {
	      return false;
	    }
	  s->size = sizeof ELF_DYNAMIC_INTERPRETER;
	  s->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
	  s->alloced = 1;
	}
    }
  else
    {
      s = htab->root.sgot;
      if (s != NULL)
	{
	  s->size = 0;
	}
    }

  if (htab->tls_ldm_got.refcount > 0)
    {
      s = htab->root.srelgot;
      if (s == NULL)
	{
	  return false;
	}
      s->size += sizeof (Elf32_External_Rela);
    }

  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      const char * name;
      bool allocate_section_contents = false;

      if ((s->flags & SEC_LINKER_CREATED) == 0)
	{
	  continue;
	}

      name = bfd_section_name (s);

      if (streq (name, ".plt"))
	{
	  allocate_section_contents = true;
	}
      else if (startswith (name, ".rela"))
	{
	  allocate_section_contents = true;
	  if (s->size != 0)
	    {
	      if (! streq (name, ".rela.plt"))
		{
		  relocs = true;
		}
	      s->reloc_count = 0;
	    }
	}
      else if (startswith (name, ".got") || streq (name, ".dynbss"))
	{
	  allocate_section_contents = true;
	}

      if (!allocate_section_contents)
	{
	  continue;
	}

      if (s->size == 0)
	{
	  s->flags |= SEC_EXCLUDE;
	  continue;
	}

      if ((s->flags & SEC_HAS_CONTENTS) == 0)
	{
	  continue;
	}

      s->contents = bfd_zalloc (dynobj, s->size);
      if (s->contents == NULL)
	{
	  return false;
	}
      s->alloced = 1;
    }

  return _bfd_elf_add_dynamic_tags (output_bfd, info, relocs);
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool
_bfd_mn10300_elf_finish_dynamic_symbol (bfd * output_bfd,
					struct bfd_link_info * info,
					struct elf_link_hash_entry * h,
					Elf_Internal_Sym * sym)
{
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  bfd * dynobj;

  if (htab == NULL || info == NULL || h == NULL || sym == NULL)
    return false;

  dynobj = htab->root.dynobj;
  if (dynobj == NULL)
    return false;

  const bfd_vma PLT_ENTRY_SIZE = elf_mn10300_sizeof_plt (info);
  const bfd_vma PLT0_SIZE = elf_mn10300_sizeof_plt0 (info);
  const unsigned int GOT_ENTRY_SIZE = 4;
  const unsigned int GOT_RESERVED_ENTRIES = 3;
  const size_t ELF_RELA_STRUCT_SIZE = sizeof (Elf32_External_Rela);

  if (h->plt.offset != (bfd_vma) -1)
    {
      asection *splt = htab->root.splt;
      asection *sgot_plt = htab->root.sgotplt;
      asection *srel_plt = htab->root.srelplt;

      if (splt == NULL || sgot_plt == NULL || srel_plt == NULL)
	return false;

      if (h->dynindx == -1)
        return false;

      if (h->plt.offset < PLT0_SIZE)
        return false;

      bfd_vma plt_index = (h->plt.offset - PLT0_SIZE) / PLT_ENTRY_SIZE;
      bfd_vma got_offset = (plt_index + GOT_RESERVED_ENTRIES) * GOT_ENTRY_SIZE;

      if (h->plt.offset + PLT_ENTRY_SIZE > splt->size)
          return false;
      if (h->plt.offset + elf_mn10300_plt_symbol_offset (info) + GOT_ENTRY_SIZE > splt->size)
          return false;
      if (h->plt.offset + elf_mn10300_plt_plt0_offset (info) + GOT_ENTRY_SIZE > splt->size)
          return false;
      if (h->plt.offset + elf_mn10300_plt_reloc_offset (info) + GOT_ENTRY_SIZE > splt->size)
          return false;

      bfd_byte *plt_entry_addr = splt->contents + h->plt.offset;
      bfd_vma sgot_plt_output_vma = sgot_plt->output_section->vma + sgot_plt->output_offset;
      bfd_vma splt_output_vma = splt->output_section->vma + splt->output_offset;

      if (! bfd_link_pic (info))
	{
	  memcpy (plt_entry_addr, elf_mn10300_plt_entry, PLT_ENTRY_SIZE);
	  bfd_put_32 (output_bfd, sgot_plt_output_vma + got_offset,
		      plt_entry_addr + elf_mn10300_plt_symbol_offset (info));

	  bfd_put_32 (output_bfd,
		      (1 - (h->plt.offset + elf_mn10300_plt_plt0_offset (info))),
		      plt_entry_addr + elf_mn10300_plt_plt0_offset (info));
	}
      else
	{
	  memcpy (plt_entry_addr, elf_mn10300_pic_plt_entry, PLT_ENTRY_SIZE);
	  bfd_put_32 (output_bfd, got_offset,
		      plt_entry_addr + elf_mn10300_plt_symbol_offset (info));
	}

      bfd_put_32 (output_bfd, plt_index * ELF_RELA_STRUCT_SIZE,
		  plt_entry_addr + elf_mn10300_plt_reloc_offset (info));

      if (got_offset + GOT_ENTRY_SIZE > sgot_plt->size)
        return false;
      bfd_put_32 (output_bfd,
		  splt_output_vma + h->plt.offset + elf_mn10300_plt_temp_offset (info),
		  sgot_plt->contents + got_offset);

      Elf_Internal_Rela rel = {0};
      rel.r_offset = sgot_plt_output_vma + got_offset;
      rel.r_info = ELF32_R_INFO (h->dynindx, R_MN10300_JMP_SLOT);
      rel.r_addend = 0;

      if ((plt_index + 1) * ELF_RELA_STRUCT_SIZE > srel_plt->size)
        return false;

      bfd_elf32_swap_reloca_out (output_bfd, &rel,
				 (bfd_byte *) ((Elf32_External_Rela *) srel_plt->contents + plt_index));

      if (!h->def_regular)
	sym->st_shndx = SHN_UNDEF;
    }

  if (h->got.offset != (bfd_vma) -1)
    {
      asection *sgot_reg = htab->root.sgot;
      asection *srel_got = htab->root.srelgot;

      if (sgot_reg == NULL || srel_got == NULL)
	return false;

      Elf_Internal_Rela rel = {0};
      bfd_vma got_entry_offset = h->got.offset & ~1;

      rel.r_offset = sgot_reg->output_section->vma + sgot_reg->output_offset + got_entry_offset;

      if (h->got.offset + GOT_ENTRY_SIZE > sgot_reg->size)
        return false;
      bfd_byte *got_entry_ptr = sgot_reg->contents + h->got.offset;

      enum elf_mn10300_tls_type tls_type = elf_mn10300_hash_entry (h)->tls_type;

      switch (tls_type)
	{
	case GOT_TLS_GD:
          if (h->got.offset + 2 * GOT_ENTRY_SIZE > sgot_reg->size)
            return false;
	  bfd_put_32 (output_bfd, 0, got_entry_ptr);
	  bfd_put_32 (output_bfd, 0, got_entry_ptr + GOT_ENTRY_SIZE);
	  rel.r_info = ELF32_R_INFO (h->dynindx, R_MN10300_TLS_DTPMOD);
	  rel.r_addend = 0;

          if ((srel_got->reloc_count + 2) * ELF_RELA_STRUCT_SIZE > srel_got->size)
            return false;

	  bfd_elf32_swap_reloca_out (output_bfd, &rel,
				     (bfd_byte *) ((Elf32_External_Rela *) srel_got->contents + srel_got->reloc_count));
	  srel_got->reloc_count++;

	  rel.r_info = ELF32_R_INFO (h->dynindx, R_MN10300_TLS_DTPOFF);
	  rel.r_offset += GOT_ENTRY_SIZE;
	  rel.r_addend = 0;
	  break;

	case GOT_TLS_IE:
          if (h->got.offset + GOT_ENTRY_SIZE > sgot_reg->size)
            return false;
	  rel.r_addend = bfd_get_32 (output_bfd, got_entry_ptr);
	  bfd_put_32 (output_bfd, 0, got_entry_ptr);
	  rel.r_info = ELF32_R_INFO ((h->dynindx == -1 ? 0 : h->dynindx), R_MN10300_TLS_TPOFF);
	  break;

	default:
	  if (bfd_link_pic (info) && (info->symbolic || h->dynindx == -1) && h->def_regular)
	    {
	      rel.r_info = ELF32_R_INFO (0, R_MN10300_RELATIVE);
              if (h->root.u.def.section == NULL || h->root.u.def.section->output_section == NULL)
                return false;
	      rel.r_addend = (h->root.u.def.value
			      + h->root.u.def.section->output_section->vma
			      + h->root.u.def.section->output_offset);
	    }
	  else
	    {
              if (h->got.offset + GOT_ENTRY_SIZE > sgot_reg->size)
                return false;
	      bfd_put_32 (output_bfd, 0, got_entry_ptr);
	      rel.r_info = ELF32_R_INFO (h->dynindx, R_MN10300_GLOB_DAT);
	      rel.r_addend = 0;
	    }
	}

      if (ELF32_R_TYPE (rel.r_info) != R_MN10300_NONE)
	{
          if ((srel_got->reloc_count + 1) * ELF_RELA_STRUCT_SIZE > srel_got->size)
            return false;
	  bfd_elf32_swap_reloca_out (output_bfd, &rel,
				     (bfd_byte *) ((Elf32_External_Rela *) srel_got->contents + srel_got->reloc_count));
	  srel_got->reloc_count++;
	}
    }

  if (h->needs_copy)
    {
      asection *s_rela_bss;
      Elf_Internal_Rela rel = {0};

      if (h->dynindx == -1)
	return false;
      if (! (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak))
        return false;

      s_rela_bss = bfd_get_linker_section (dynobj, ".rela.bss");
      if (s_rela_bss == NULL)
	return false;

      if (h->root.u.def.section == NULL || h->root.u.def.section->output_section == NULL)
        return false;

      rel.r_offset = (h->root.u.def.value
		      + h->root.u.def.section->output_section->vma
		      + h->root.u.def.section->output_offset);
      rel.r_info = ELF32_R_INFO (h->dynindx, R_MN10300_COPY);
      rel.r_addend = 0;

      if ((s_rela_bss->reloc_count + 1) * ELF_RELA_STRUCT_SIZE > s_rela_bss->size)
        return false;

      bfd_elf32_swap_reloca_out (output_bfd, &rel,
				 (bfd_byte *) ((Elf32_External_Rela *) s_rela_bss->contents + s_rela_bss->reloc_count));
      s_rela_bss->reloc_count++;
    }

  if (h == elf_hash_table (info)->hdynamic
      || h == elf_hash_table (info)->hgot)
    sym->st_shndx = SHN_ABS;

  return true;
}

/* Finish up the dynamic sections.  */

static bool
_bfd_mn10300_elf_finish_dynamic_sections (bfd * output_bfd,
					  struct bfd_link_info * info)
{
  bfd *      dynobj;
  asection * sgot;
  asection * sdyn;
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);

  dynobj = htab->root.dynobj;
  sgot = htab->root.sgotplt;
  BFD_ASSERT (sgot != NULL);
  sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      asection *	   splt;
      Elf32_External_Dyn * dyncon;
      Elf32_External_Dyn * dynconend;

      BFD_ASSERT (sdyn != NULL);

      dyncon = (Elf32_External_Dyn *) sdyn->contents;
      dynconend = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);

      for (; dyncon < dynconend; dyncon++)
	{
	  Elf_Internal_Dyn dyn;
	  asection * s;

	  bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);

	  switch (dyn.d_tag)
	    {
	    default:
	      break;

	    case DT_PLTGOT:
	      s = htab->root.sgot;
              dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
              bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
	      break;

	    case DT_JMPREL:
	      s = htab->root.srelplt;
              dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
              bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
	      break;

	    case DT_PLTRELSZ:
	      s = htab->root.srelplt;
	      dyn.d_un.d_val = s->size;
	      bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
	      break;
	    }
	}

      splt = htab->root.splt;
      if (splt && splt->size > 0)
	{
	  if (bfd_link_pic (info))
	    {
	      memcpy (splt->contents, elf_mn10300_pic_plt_entry,
		      elf_mn10300_sizeof_plt (info));
	    }
	  else
	    {
	      memcpy (splt->contents, elf_mn10300_plt0_entry, PLT0_ENTRY_SIZE);
	      bfd_put_32 (output_bfd,
			  sgot->output_section->vma + sgot->output_offset + 4,
			  splt->contents + elf_mn10300_plt0_gotid_offset (info));
	      bfd_put_32 (output_bfd,
			  sgot->output_section->vma + sgot->output_offset + 8,
			  splt->contents + elf_mn10300_plt0_linker_offset (info));
	    }

	  elf_section_data (splt->output_section)->this_hdr.sh_entsize = 1;
	}
    }

  if (sgot->size > 0)
    {
      if (sdyn == NULL)
	bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents);
      else
	bfd_put_32 (output_bfd,
		    sdyn->output_section->vma + sdyn->output_offset,
		    sgot->contents);
      bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents + 4);
      bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents + 8);
    }

  elf_section_data (sgot->output_section)->this_hdr.sh_entsize = 4;

  return true;
}

/* Classify relocation types, such that combreloc can sort them
   properly.  */

static enum elf_reloc_type_class
_bfd_mn10300_elf_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
				   const asection *rel_sec ATTRIBUTE_UNUSED,
				   const Elf_Internal_Rela *rela)
{
  if (rela == NULL)
    {
      return reloc_class_normal;
    }

  switch ((int) ELF32_R_TYPE (rela->r_info))
    {
    case R_MN10300_RELATIVE:
      return reloc_class_relative;
    case R_MN10300_JMP_SLOT:
      return reloc_class_plt;
    case R_MN10300_COPY:
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}

/* Allocate space for an MN10300 extension to the bfd elf data structure.  */

static bool
mn10300_elf_mkobject (bfd *abfd)
{
  bool allocation_successful = bfd_elf_allocate_object (abfd, sizeof (struct elf_mn10300_obj_tdata));
  return allocation_successful;
}

#define bfd_elf32_mkobject	mn10300_elf_mkobject

#ifndef ELF_ARCH
#define TARGET_LITTLE_SYM	mn10300_elf32_vec
#define TARGET_LITTLE_NAME	"elf32-mn10300"
#define ELF_ARCH		bfd_arch_mn10300
#define ELF_TARGET_ID		MN10300_ELF_DATA
#define ELF_MACHINE_CODE	EM_MN10300
#define ELF_MACHINE_ALT1	EM_CYGNUS_MN10300
#define ELF_MAXPAGESIZE		0x1000
#endif

#define elf_info_to_howto		mn10300_info_to_howto
#define elf_info_to_howto_rel		NULL
#define elf_backend_can_gc_sections	1
#define elf_backend_rela_normal		1
#define elf_backend_check_relocs	mn10300_elf_check_relocs
#define elf_backend_gc_mark_hook	mn10300_elf_gc_mark_hook
#define elf_backend_relocate_section	mn10300_elf_relocate_section
#define bfd_elf32_bfd_relax_section	mn10300_elf_relax_section
#define bfd_elf32_bfd_get_relocated_section_contents \
				mn10300_elf_get_relocated_section_contents
#define bfd_elf32_bfd_link_hash_table_create \
				elf32_mn10300_link_hash_table_create

#ifndef elf_symbol_leading_char
#define elf_symbol_leading_char '_'
#endif

/* So we can set bits in e_flags.  */
#define elf_backend_final_write_processing \
					_bfd_mn10300_elf_final_write_processing
#define elf_backend_object_p		_bfd_mn10300_elf_object_p

#define bfd_elf32_bfd_merge_private_bfd_data \
					_bfd_mn10300_elf_merge_private_bfd_data

#define elf_backend_can_gc_sections	1
#define elf_backend_create_dynamic_sections \
  _bfd_mn10300_elf_create_dynamic_sections
#define elf_backend_adjust_dynamic_symbol \
  _bfd_mn10300_elf_adjust_dynamic_symbol
#define elf_backend_late_size_sections \
  _bfd_mn10300_elf_late_size_sections
#define elf_backend_omit_section_dynsym _bfd_elf_omit_section_dynsym_all
#define elf_backend_finish_dynamic_symbol \
  _bfd_mn10300_elf_finish_dynamic_symbol
#define elf_backend_finish_dynamic_sections \
  _bfd_mn10300_elf_finish_dynamic_sections
#define elf_backend_copy_indirect_symbol \
  _bfd_mn10300_copy_indirect_symbol
#define elf_backend_reloc_type_class \
  _bfd_mn10300_elf_reloc_type_class

#define elf_backend_want_got_plt	1
#define elf_backend_plt_readonly	1
#define elf_backend_want_plt_sym	0
#define elf_backend_got_header_size	12
#define elf_backend_dtrel_excludes_plt	1

#include "elf32-target.h"
