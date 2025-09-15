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

static bool
create_elf_section (bfd *abfd,
		    asection **section_ptr,
		    const char *name,
		    flagword flags,
		    unsigned int alignment)
{
  asection *s = bfd_make_section_anyway_with_flags (abfd, name, flags);
  *section_ptr = s;
  if (s == NULL)
    return false;

  return bfd_set_section_alignment (s, alignment);
}

static bool
_bfd_mn10300_elf_create_got_section (bfd * abfd,
				     struct bfd_link_info * info)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);
  if (htab->sgot != NULL)
    return true;

  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  int ptralign;

  if (bed->s->arch_size == 32)
    ptralign = 2;
  else if (bed->s->arch_size == 64)
    ptralign = 3;
  else
    {
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  const flagword base_flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS
			       | SEC_IN_MEMORY | SEC_LINKER_CREATED);
  flagword plt_flags = base_flags | SEC_CODE;

  if (bed->plt_not_loaded)
    plt_flags &= ~(SEC_LOAD | SEC_HAS_CONTENTS);
  if (bed->plt_readonly)
    plt_flags |= SEC_READONLY;

  if (!create_elf_section (abfd, &htab->splt, ".plt", plt_flags,
			   bed->plt_alignment))
    return false;

  if (bed->want_plt_sym)
    {
      htab->hplt = _bfd_elf_define_linkage_sym (abfd, info, htab->splt,
					       "_PROCEDURE_LINKAGE_TABLE_");
      if (htab->hplt == NULL)
	return false;
    }

  asection *got_symbol_section;
  if (!create_elf_section (abfd, &htab->sgot, ".got", base_flags, ptralign))
    return false;
  got_symbol_section = htab->sgot;

  if (bed->want_got_plt)
    {
      if (!create_elf_section (abfd, &htab->sgotplt, ".got.plt",
			       base_flags, ptralign))
	return false;
      got_symbol_section = htab->sgotplt;
    }

  htab->hgot = _bfd_elf_define_linkage_sym (abfd, info, got_symbol_section,
					   "_GLOBAL_OFFSET_TABLE_");
  if (htab->hgot == NULL)
    return false;

  got_symbol_section->size += bed->got_header_size;

  return true;
}

static reloc_howto_type *
bfd_elf32_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 bfd_reloc_code_real_type code)
{
  const size_t map_size = ARRAY_SIZE (mn10300_reloc_map);
  for (size_t i = 0; i < map_size; ++i)
    {
      if (mn10300_reloc_map[i].bfd_reloc_val == code)
	{
	  return &elf_mn10300_howto_table[mn10300_reloc_map[i].elf_reloc_val];
	}
    }

  return NULL;
}

static reloc_howto_type *
bfd_elf32_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                 const char *r_name)
{
  if (r_name == NULL)
    {
      return NULL;
    }

  for (size_t i = 0; i < ARRAY_SIZE (elf_mn10300_howto_table); ++i)
    {
      reloc_howto_type *howto = &elf_mn10300_howto_table[i];
      if (howto->name != NULL && strcasecmp (howto->name, r_name) == 0)
        {
          return howto;
        }
    }

  return NULL;
}

/* Set the howto pointer for an MN10300 ELF reloc.  */

static bool
mn10300_info_to_howto (bfd *abfd,
		       arelent *cache_ptr,
		       Elf_Internal_Rela *dst)
{
  if (!abfd || !cache_ptr || !dst)
    {
      bfd_set_error (bfd_error_invalid_argument);
      return false;
    }

  const unsigned int r_type = ELF32_R_TYPE (dst->r_info);

  if (r_type >= R_MN10300_MAX)
    {
      /* xgettext:c-format */
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  cache_ptr->howto = elf_mn10300_howto_table + r_type;
  return true;
}

static int
elf_mn10300_tls_transition (struct bfd_link_info *info,
			    int r_type,
			    struct elf_link_hash_entry *h,
			    asection *sec,
			    bool counting)
{
  if (r_type == R_MN10300_TLS_GD
      && h != NULL
      && elf_mn10300_hash_entry (h)->tls_type == GOT_TLS_IE)
    {
      return R_MN10300_TLS_GOTIE;
    }

  if (bfd_link_pic (info))
    {
      return r_type;
    }

  if (sec == NULL || (sec->flags & SEC_CODE) == 0)
    {
      return r_type;
    }

  const bool is_local = (!counting
			 && h != NULL
			 && !elf_hash_table (info)->dynamic_sections_created)
			|| SYMBOL_CALLS_LOCAL (info, h);

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
dtpoff (const struct bfd_link_info *info, bfd_vma address)
{
  const struct elf_link_hash_table *htab = elf_hash_table (info);

  if (htab == NULL || htab->tls_sec == NULL)
    return 0;

  return address - htab->tls_sec->vma;
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma
tpoff (struct bfd_link_info *info, bfd_vma address)
{
  const struct elf_link_hash_table *htab = elf_hash_table (info);

  if (htab == NULL || htab->tls_sec == NULL)
  {
    return 0;
  }

  return address - (htab->tls_size + htab->tls_sec->vma);
}

/* Returns nonzero if there's a R_MN10300_PLT32 reloc that we now need
   to skip, after this one.  The actual value is the offset between
   this reloc and the PLT reloc.  */

static int
patch_mov_ie_to_le (bfd *abfd,
		    unsigned int r_type,
		    bfd_byte *op)
{
  if (op[-2] == 0xFC)
    {
      bfd_byte reg_bits;
      bfd_boolean is_dn_reg;
      op -= 2;

      if (r_type == R_MN10300_TLS_IE)
	{
	  is_dn_reg = (op[1] & 0xFC) == 0xA4;
	  reg_bits = op[1] & 0x03;
	}
      else
	{
	  is_dn_reg = (op[1] & 0xF0) == 0x00;
	  reg_bits = (op[1] & 0x0C) >> 2;
	}

      op[1] = reg_bits;
      if (is_dn_reg)
	op[1] |= 0xCC;
      else
	op[1] |= 0xDC;

      return 0;
    }
  else if (op[-3] == 0xFE)
    {
      op[-2] = 0x08;
      return 0;
    }

  _bfd_error_handler
    (_("%pB: unsupported instruction for %s to LE transition"),
     abfd, elf_mn10300_howto_table[r_type].name);
  return -1;
}

static int
mn10300_do_tls_transition (bfd *input_bfd,
			   unsigned int r_type,
			   unsigned int tls_r_type,
			   bfd_byte *contents,
			   bfd_vma offset)
{
  bfd_byte *op = contents + offset;
  int gotreg = 0;

#define TLS_PAIR(r1,r2) ((r1) * R_MN10300_MAX + (r2))

  if (r_type == R_MN10300_TLS_GD || r_type == R_MN10300_TLS_LD)
    {
      op -= 2;
      if (bfd_get_8 (input_bfd, op) != 0xFC
	  || bfd_get_8 (input_bfd, op + 1) != 0xCC
	  || bfd_get_8 (input_bfd, op + 6) != 0xF1
	  || bfd_get_8 (input_bfd, op + 8) != 0xDD)
	{
	  _bfd_error_handler
	    (_("%pB: unexpected instruction sequence for %s transition"),
	     input_bfd, elf_mn10300_howto_table[r_type].name);
	  return -1;
	}
      gotreg = (bfd_get_8 (input_bfd, op + 7) & 0x0c) >> 2;
    }

  switch (TLS_PAIR (r_type, tls_r_type))
    {
    case TLS_PAIR (R_MN10300_TLS_GD, R_MN10300_TLS_GOTIE):
    case TLS_PAIR (R_MN10300_TLS_GD, R_MN10300_TLS_LE):
      {
	static const bfd_byte add_e2_a0[] = { 0xF9, 0x78, 0x28 };
	static const bfd_byte nop_6_byte[] = { 0xFC, 0xE4, 0x00, 0x00, 0x00, 0x00 };
	bfd_byte mov_op[6] = { 0xFC };

	if (tls_r_type == R_MN10300_TLS_GOTIE)
	  mov_op[1] = 0x20 | gotreg;
	else
	  mov_op[1] = 0xDC;

	memcpy (op, mov_op, sizeof (mov_op));
	memcpy (op + 6, add_e2_a0, sizeof (add_e2_a0));
	memcpy (op + 9, nop_6_byte, sizeof (nop_6_byte));
	return 7;
      }

    case TLS_PAIR (R_MN10300_TLS_LD, R_MN10300_NONE):
      {
	static const bfd_byte mov_e2_a0[] = { 0xF5, 0x88 };
	static const bfd_byte nop_6_byte[] = { 0xFC, 0xE4, 0x00, 0x00, 0x00, 0x00 };
	static const bfd_byte nop_7_byte[] = { 0xFE, 0x19, 0x22, 0x00, 0x00, 0x00, 0x00 };

	memcpy (op, mov_e2_a0, sizeof (mov_e2_a0));
	memcpy (op + 2, nop_6_byte, sizeof (nop_6_byte));
	memcpy (op + 8, nop_7_byte, sizeof (nop_7_byte));
	return 7;
      }

    case TLS_PAIR (R_MN10300_TLS_LDO, R_MN10300_TLS_LE):
      return 0;

    case TLS_PAIR (R_MN10300_TLS_IE, R_MN10300_TLS_LE):
    case TLS_PAIR (R_MN10300_TLS_GOTIE, R_MN10300_TLS_LE):
      if (patch_mov_ie_to_le (input_bfd, r_type, op) != 0)
	return -1;
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
  return 0;
}

/* Look through the relocs for a section during the first phase.
   Since we don't do .gots or .plts, we just need to consider the
   virtual table relocs for gc.  */

static struct elf_link_hash_entry *
get_link_hash_entry (const Elf_Internal_Rela *rel,
                     const Elf_Internal_Shdr *symtab_hdr,
                     struct elf_link_hash_entry **sym_hashes)
{
  unsigned long r_symndx = ELF32_R_SYM (rel->r_info);

  if (r_symndx < symtab_hdr->sh_info)
    return NULL;

  struct elf_link_hash_entry *h = sym_hashes[r_symndx - symtab_hdr->sh_info];
  while (h != NULL
         && (h->root.type == bfd_link_hash_indirect
             || h->root.type == bfd_link_hash_warning))
    {
      h = (struct elf_link_hash_entry *) h->root.u.i.link;
    }
  return h;
}

static bool
reloc_needs_got_creation (unsigned int r_type)
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
ensure_dynamic_object_created (bfd *abfd, struct bfd_link_info *info)
{
  if (elf_hash_table (info)->dynobj == NULL)
    {
      elf_hash_table (info)->dynobj = abfd;
      if (!_bfd_mn10300_elf_create_got_section (abfd, info))
        return false;
    }
  return true;
}

static bfd_vma *
allocate_local_got_storage (bfd *abfd, unsigned int num_syms)
{
  size_t size = num_syms * (sizeof (bfd_vma) + sizeof (char));
  bfd_vma *local_got_offsets = (bfd_vma *) bfd_alloc (abfd, size);

  if (local_got_offsets != NULL)
    {
      elf_local_got_offsets (abfd) = local_got_offsets;
      elf_mn10300_local_got_tls_type (abfd) =
          (char *) (local_got_offsets + num_syms);

      for (unsigned int i = 0; i < num_syms; i++)
        local_got_offsets[i] = (bfd_vma) -1;
    }

  return local_got_offsets;
}

static bool
handle_global_got_entry (struct elf_link_hash_entry *h, int tls_type,
                         unsigned int r_type, bfd *abfd,
                         struct bfd_link_info *info,
                         asection *sgot, asection *srelgot)
{
  struct elf_mn10300_link_hash_entry *h_mn10300 = elf_mn10300_hash_entry (h);

  if (h_mn10300->tls_type != GOT_UNKNOWN
      && h_mn10300->tls_type != tls_type)
    {
      if (tls_type == GOT_TLS_IE && h_mn10300->tls_type == GOT_TLS_GD)
        {
        }
      else if (tls_type == GOT_TLS_GD && h_mn10300->tls_type == GOT_TLS_IE)
        {
          tls_type = GOT_TLS_IE;
        }
      else
        {
          _bfd_error_handler
            (_("%pB: %s' accessed both as normal and thread local symbol"),
             abfd, h->root.root.string);
        }
    }

  h_mn10300->tls_type = tls_type;

  if (h->got.offset != (bfd_vma) -1)
    return true;

  h->got.offset = sgot->size;

  if (ELF_ST_VISIBILITY (h->other) != STV_INTERNAL && h->dynindx == -1)
    {
      if (!bfd_elf_link_record_dynamic_symbol (info, h))
        return false;
    }

  srelgot->size += sizeof (Elf32_External_Rela);
  if (r_type == R_MN10300_TLS_GD)
    srelgot->size += sizeof (Elf32_External_Rela);

  return true;
}

static bool
handle_local_got_entry (unsigned long r_symndx, int tls_type,
                        unsigned int r_type, bfd *abfd,
                        struct bfd_link_info *info,
                        const Elf_Internal_Shdr *symtab_hdr, asection *sgot,
                        asection *srelgot, bfd_vma **local_got_offsets_p)
{
  if (*local_got_offsets_p == NULL)
    {
      *local_got_offsets_p = allocate_local_got_storage (abfd, symtab_hdr->sh_info);
      if (*local_got_offsets_p == NULL)
        return false;
    }

  if ((*local_got_offsets_p)[r_symndx] != (bfd_vma) -1)
    return true;

  (*local_got_offsets_p)[r_symndx] = sgot->size;

  if (bfd_link_pic (info))
    {
      srelgot->size += sizeof (Elf32_External_Rela);
      if (r_type == R_MN10300_TLS_GD)
        srelgot->size += sizeof (Elf32_External_Rela);
    }

  elf_mn10300_local_got_tls_type (abfd)[r_symndx] = tls_type;
  return true;
}

static bool
handle_got_entry_reloc (unsigned int r_type, struct elf_link_hash_entry *h,
                        unsigned long r_symndx, bfd *abfd,
                        struct bfd_link_info *info,
                        const Elf_Internal_Shdr *symtab_hdr,
                        bfd_vma **local_got_offsets_p)
{
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  asection *sgot = htab->root.sgot;
  asection *srelgot = htab->root.srelgot;
  int tls_type;

  BFD_ASSERT (sgot != NULL && srelgot != NULL);

  switch (r_type)
    {
    case R_MN10300_TLS_IE:
    case R_MN10300_TLS_GOTIE: tls_type = GOT_TLS_IE; break;
    case R_MN10300_TLS_GD:    tls_type = GOT_TLS_GD; break;
    case R_MN10300_TLS_LD:    tls_type = GOT_TLS_LD; break;
    default:                  tls_type = GOT_NORMAL; break;
    }

  if (r_type == R_MN10300_TLS_LD)
    {
      htab->tls_ldm_got.refcount++;
      if (htab->tls_ldm_got.got_allocated)
        return true;
      htab->tls_ldm_got.offset = sgot->size;
      htab->tls_ldm_got.got_allocated++;
    }
  else if (h != NULL)
    {
      if (!handle_global_got_entry (h, tls_type, r_type, abfd, info, sgot, srelgot))
        return false;
    }
  else
    {
      if (!handle_local_got_entry (r_symndx, tls_type, r_type, abfd, info,
                                   symtab_hdr, sgot, srelgot,
                                   local_got_offsets_p))
        return false;
    }

  sgot->size += 4;
  if (r_type == R_MN10300_TLS_GD || r_type == R_MN10300_TLS_LD)
    sgot->size += 4;

  return true;
}

static bool
maybe_create_dynamic_reloc (bfd *abfd, struct bfd_link_info *info, asection *sec,
                            struct elf_link_hash_entry *h, unsigned long r_symndx,
                            Elf_Internal_Sym **isymbuf_p,
                            const Elf_Internal_Shdr *symtab_hdr,
                            asection **sreloc_p)
{
  asection *sym_section = NULL;

  if (h == NULL)
    {
      if (*isymbuf_p == NULL)
          *isymbuf_p = bfd_elf_get_elf_syms (abfd, symtab_hdr,
                                           symtab_hdr->sh_info, 0,
                                           NULL, NULL, NULL);

      if (*isymbuf_p != NULL)
        {
          Elf_Internal_Sym *isym = *isymbuf_p + r_symndx;
          if (isym->st_shndx == SHN_ABS)
            sym_section = bfd_abs_section_ptr;
        }
    }
  else if (h->root.type == bfd_link_hash_defined
           || h->root.type == bfd_link_hash_defweak)
    {
      sym_section = h->root.u.def.section;
    }

  if (sym_section == bfd_abs_section_ptr)
    return true;

  if (*sreloc_p == NULL)
    {
      bfd *dynobj = elf_hash_table (info)->dynobj;
      *sreloc_p = _bfd_elf_make_dynamic_reloc_section (sec, dynobj, 2, abfd, true);
      if (*sreloc_p == NULL)
        return false;
    }

  (*sreloc_p)->size += sizeof (Elf32_External_Rela);
  return true;
}

static bool
mn10300_elf_check_relocs (bfd *abfd,
			  struct bfd_link_info *info,
			  asection *sec,
			  const Elf_Internal_Rela *relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Sym *isymbuf;
  struct elf_link_hash_entry **sym_hashes;
  bfd_vma *local_got_offsets;
  asection *sreloc = NULL;
  bool sym_diff_reloc_seen = false;
  bool result = false;

  if (bfd_link_relocatable (info))
    return true;

  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
  sym_hashes = elf_sym_hashes (abfd);
  local_got_offsets = elf_local_got_offsets (abfd);

  const Elf_Internal_Rela *rel_end = relocs + sec->reloc_count;
  for (const Elf_Internal_Rela *rel = relocs; rel < rel_end; rel++)
    {
      struct elf_link_hash_entry *h = get_link_hash_entry (rel, symtab_hdr,
                                                           sym_hashes);
      unsigned long r_symndx = ELF32_R_SYM (rel->r_info);
      unsigned int r_type = ELF32_R_TYPE (rel->r_info);
      r_type = elf_mn10300_tls_transition (info, r_type, h, sec, true);

      if (reloc_needs_got_creation (r_type))
        {
          if (!ensure_dynamic_object_created (abfd, info))
            goto fail;
        }

      bool needs_dynamic_reloc = false;
      switch (r_type)
	{
	case R_MN10300_GNU_VTINHERIT:
	  if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
	    goto fail;
	  break;

	case R_MN10300_GNU_VTENTRY:
	  if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
	    goto fail;
	  break;

	case R_MN10300_TLS_LD:
	case R_MN10300_GOT32:
	case R_MN10300_GOT24:
	case R_MN10300_GOT16:
	case R_MN10300_TLS_GD:
	case R_MN10300_TLS_GOTIE:
	case R_MN10300_TLS_IE:
	  if ((r_type == R_MN10300_TLS_IE || r_type == R_MN10300_TLS_GOTIE)
	      && bfd_link_pic (info))
	    info->flags |= DF_STATIC_TLS;
	  if (!handle_got_entry_reloc (r_type, h, r_symndx, abfd, info,
				       symtab_hdr, &local_got_offsets))
	    goto fail;
	  needs_dynamic_reloc = true;
	  break;

	case R_MN10300_PLT32:
	case R_MN10300_PLT16:
	  if (h != NULL
	      && ELF_ST_VISIBILITY (h->other) != STV_INTERNAL
	      && ELF_ST_VISIBILITY (h->other) != STV_HIDDEN)
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

	case R_MN10300_SYM_DIFF:
	  sym_diff_reloc_seen = true;
	  break;

	case R_MN10300_32:
	  if (h != NULL)
	    h->non_got_ref = 1;
	  needs_dynamic_reloc = true;
	  break;

	default:
	  break;
	}

      if (needs_dynamic_reloc
	  && bfd_link_pic (info)
	  && (sec->flags & SEC_ALLOC) != 0
	  && !sym_diff_reloc_seen)
	{
	  if (!maybe_create_dynamic_reloc (abfd, info, sec, h, r_symndx,
					   &isymbuf, symtab_hdr, &sreloc))
	    goto fail;
	}

      if (ELF32_R_TYPE (rel->r_info) != R_MN10300_SYM_DIFF)
	sym_diff_reloc_seen = false;
    }

  result = true;

 fail:
  if (isymbuf != NULL && isymbuf != (Elf_Internal_Sym *) symtab_hdr->contents)
    free (isymbuf);

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
  if (h != NULL)
    {
      unsigned long r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == R_MN10300_GNU_VTINHERIT
	  || r_type == R_MN10300_GNU_VTENTRY)
	{
	  return NULL;
	}
    }

  return _bfd_elf_gc_mark_hook (sec, info, rel, h, sym);
}

/* Perform a relocation as part of a final link.  */

static asection *g_sym_diff_section = NULL;
static bfd_vma g_sym_diff_value = 0;

static bool
check_signed_overflow (bfd_vma value, unsigned int bits)
{
  bfd_signed_vma val = (bfd_signed_vma) value;
  if (bits < (sizeof (bfd_signed_vma) * 8))
    {
      bfd_signed_vma min_val = -((bfd_signed_vma) 1 << (bits - 1));
      bfd_signed_vma max_val = ((bfd_signed_vma) 1 << (bits - 1)) - 1;
      return val < min_val || val > max_val;
    }
  return false;
}

static void
write_24bit_value (bfd *output_bfd, bfd_vma value, bfd_byte *dest)
{
  bfd_put_8 (output_bfd, value & 0xff, dest);
  bfd_put_8 (output_bfd, (value >> 8) & 0xff, dest + 1);
  bfd_put_8 (output_bfd, (value >> 16) & 0xff, dest + 2);
}

static bfd_reloc_status_type
relocate_absolute (bfd *input_bfd, bfd_vma value, bfd_vma addend,
		   bfd_byte *hit_data, unsigned int bits)
{
  value += addend;
  if (check_signed_overflow (value, bits))
    return bfd_reloc_overflow;

  switch (bits)
    {
    case 8:
      bfd_put_8 (input_bfd, value, hit_data);
      break;
    case 16:
      bfd_put_16 (input_bfd, value, hit_data);
      break;
    case 24:
      write_24bit_value (input_bfd, value, hit_data);
      break;
    case 32:
      bfd_put_32 (input_bfd, value, hit_data);
      break;
    default:
      return bfd_reloc_notsupported;
    }
  return bfd_reloc_ok;
}

static bfd_vma
calculate_pcrel_value (bfd_vma value, bfd_vma addend,
		       asection *input_section, bfd_vma offset)
{
  bfd_vma base = input_section->output_section->vma
    + input_section->output_offset + offset;
  return value + addend - base;
}

static bfd_reloc_status_type
relocate_pcrel (bfd *input_bfd, bfd_vma value, bfd_vma addend,
		asection *input_section, bfd_vma offset,
		bfd_byte *hit_data, unsigned int bits)
{
  value = calculate_pcrel_value (value, addend, input_section, offset);
  return relocate_absolute (input_bfd, value, 0, hit_data, bits);
}

static bfd_reloc_status_type
handle_reloc_32_dynamic (struct bfd_link_info *info, bfd *input_bfd,
			 bfd *output_bfd, asection *input_section,
			 bfd_byte *hit_data, bfd_vma offset,
			 bfd_vma value, bfd_vma addend,
			 struct elf_link_hash_entry *h, asection *sym_sec,
			 bool is_sym_diff_reloc)
{
  if (bfd_link_pic (info)
      && !is_sym_diff_reloc
      && sym_sec != bfd_abs_section_ptr
      && (input_section->flags & SEC_ALLOC) != 0)
    {
      asection *sreloc = _bfd_elf_get_dynamic_reloc_section
	(input_bfd, input_section, true);
      if (sreloc == NULL)
	return bfd_reloc_dangerous;

      Elf_Internal_Rela outrel;
      outrel.r_offset = _bfd_elf_section_offset (input_bfd, info, input_section, offset);

      if (outrel.r_offset == (bfd_vma) -1)
	{
	  memset (&outrel, 0, sizeof outrel);
	}
      else
	{
	  outrel.r_offset += (input_section->output_section->vma
			      + input_section->output_offset);
	  if (h == NULL || SYMBOL_REFERENCES_LOCAL (info, h))
	    {
	      outrel.r_info = ELF32_R_INFO (0, R_MN10300_RELATIVE);
	      outrel.r_addend = value + addend;
	      value += addend;
	    }
	  else
	    {
	      BFD_ASSERT (h->dynindx != -1);
	      outrel.r_info = ELF32_R_INFO (h->dynindx, R_MN10300_32);
	      outrel.r_addend = addend;
	    }
	}

      bfd_elf32_swap_reloca_out (output_bfd, &outrel,
				 (bfd_byte *) ((Elf32_External_Rela *) sreloc->contents)
				 + sreloc->reloc_count);
      sreloc->reloc_count++;
      bfd_put_32 (input_bfd, value, hit_data);
      return bfd_reloc_ok;
    }
  return relocate_absolute (input_bfd, value, addend, hit_data, 32);
}

static bfd_reloc_status_type
relocate_gotoff (bfd *input_bfd, bfd *output_bfd ATTRIBUTE_UNUSED,
		 struct bfd_link_info *info, bfd_vma value,
		 bfd_vma addend, bfd_byte *hit_data, unsigned int bits)
{
  if (elf_hash_table (info)->dynobj == NULL)
    return bfd_reloc_dangerous;

  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  value -= htab->root.sgot->output_section->vma;

  return relocate_absolute (input_bfd, value, addend, hit_data, bits);
}

static bfd_reloc_status_type
relocate_gotpc (bfd *input_bfd, bfd *output_bfd ATTRIBUTE_UNUSED,
		struct bfd_link_info *info, bfd_vma addend,
		asection *input_section, bfd_vma offset,
		bfd_byte *hit_data, unsigned int bits)
{
  if (elf_hash_table (info)->dynobj == NULL)
    return bfd_reloc_dangerous;

  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  bfd_vma value = htab->root.sgot->output_section->vma;

  return relocate_pcrel (input_bfd, value, addend, input_section,
			 offset, hit_data, bits);
}

static bfd_reloc_status_type
relocate_plt (bfd *input_bfd, bfd *output_bfd ATTRIBUTE_UNUSED,
	      struct bfd_link_info *info,
	      struct elf_link_hash_entry *h, bfd_vma value,
	      bfd_vma addend, asection *input_section,
	      bfd_vma offset, bfd_byte *hit_data, unsigned int bits)
{
  if (h != NULL
      && ELF_ST_VISIBILITY (h->other) != STV_INTERNAL
      && ELF_ST_VISIBILITY (h->other) != STV_HIDDEN
      && h->plt.offset != (bfd_vma) -1)
    {
      if (elf_hash_table (info)->dynobj == NULL)
	return bfd_reloc_dangerous;

      struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
      asection *splt = htab->root.splt;
      value = (splt->output_section->vma
	       + splt->output_offset + h->plt.offset);
    }

  return relocate_pcrel (input_bfd, value, addend, input_section, offset,
			 hit_data, bits == 16 ? 32 : bits);
}

static bfd_reloc_status_type
handle_got_reloc (bfd *input_bfd, bfd *output_bfd,
		  struct bfd_link_info *info,
		  struct elf_link_hash_entry *h, unsigned long symndx,
		  bfd_vma *value_ptr, bfd_vma addend,
		  bfd_byte *hit_data, unsigned long r_type)
{
  if (elf_hash_table (info)->dynobj == NULL)
    return bfd_reloc_dangerous;

  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  asection *sgot = htab->root.sgot;
  bfd_vma value = *value_ptr;
  bfd_vma off;

  if (h != NULL)
    {
      off = h->got.offset;
      if (off == (bfd_vma) -1)
	off = 0;

      if (sgot->contents != NULL
	  && (!elf_hash_table (info)->dynamic_sections_created
	      || SYMBOL_REFERENCES_LOCAL (info, h)))
	bfd_put_32 (output_bfd, value, sgot->contents + off);

      value = sgot->output_offset + off;
    }
  else
    {
      off = elf_local_got_offsets (input_bfd)[symndx];
      if ((off & 1) == 0)
	{
	  bfd_put_32 (output_bfd, value, sgot->contents + off);
	  if (bfd_link_pic (info))
	    {
	      asection *srelgot = htab->root.srelgot;
	      Elf_Internal_Rela outrel;
	      BFD_ASSERT (srelgot != NULL);
	      outrel.r_offset = sgot->output_section->vma
		+ sgot->output_offset + off;
	      outrel.r_addend = value;

	      switch (r_type)
		{
		case R_MN10300_TLS_GD:
		  outrel.r_info = ELF32_R_INFO (0, R_MN10300_TLS_DTPMOD);
		  bfd_elf32_swap_reloca_out (output_bfd, &outrel,
					     (bfd_byte *) ((Elf32_External_Rela *) srelgot->contents
							   + srelgot->reloc_count));
		  srelgot->reloc_count++;
		  outrel.r_offset += 4;
		  outrel.r_info = ELF32_R_INFO (0, R_MN10300_TLS_DTPOFF);
		  break;
		case R_MN10300_TLS_GOTIE:
		case R_MN10300_TLS_IE:
		  outrel.r_info = ELF32_R_INFO (0, R_MN10300_TLS_TPOFF);
		  break;
		default:
		  outrel.r_info = ELF32_R_INFO (0, R_MN10300_RELATIVE);
		  break;
		}

	      bfd_elf32_swap_reloca_out (output_bfd, &outrel,
					 (bfd_byte *) ((Elf32_External_Rela *) srelgot->contents)
					 + srelgot->reloc_count);
	      srelgot->reloc_count++;
	      elf_local_got_offsets (input_bfd)[symndx] |= 1;
	    }
	}
      value = sgot->output_offset + (off & ~(bfd_vma) 1);
    }

  value += addend;

  switch (r_type)
    {
    case R_MN10300_TLS_IE:
      value += sgot->output_section->vma;
      /* Fall through */
    case R_MN10300_TLS_GOTIE:
    case R_MN10300_TLS_GD:
    case R_MN10300_TLS_LD:
    case R_MN10300_GOT32:
      bfd_put_32 (input_bfd, value, hit_data);
      return bfd_reloc_ok;
    case R_MN10300_GOT24:
      return relocate_absolute (input_bfd, value, 0, hit_data, 24);
    case R_MN10300_GOT16:
      return relocate_absolute (input_bfd, value, 0, hit_data, 16);
    default:
      return bfd_reloc_notsupported;
    }
}

static bfd_vma
process_sym_diff (unsigned long r_type, bfd_vma value,
		  asection *input_section, bool *is_sym_diff)
{
  *is_sym_diff = false;
  if (g_sym_diff_section != input_section)
    {
      g_sym_diff_section = NULL;
      return value;
    }

  BFD_ASSERT (g_sym_diff_section != NULL);

  bfd_vma result = value;
  switch (r_type)
    {
    case R_MN10300_32:
    case R_MN10300_24:
    case R_MN10300_16:
    case R_MN10300_8:
      result -= g_sym_diff_value;
      if (r_type == R_MN10300_32 && result == 0
	  && strcmp (input_section->name, ".debug_loc") == 0)
	result = 1;
      *is_sym_diff = true;
      break;
    default:
      break;
    }
  g_sym_diff_section = NULL;
  return result;
}

static bfd_reloc_status_type
perform_pic_safety_checks (unsigned long r_type, struct bfd_link_info *info,
			   asection *input_section, struct elf_link_hash_entry *h)
{
  if (bfd_link_pic (info) && (input_section->flags & SEC_ALLOC) != 0 &&
      h != NULL && !SYMBOL_REFERENCES_LOCAL (info, h))
    {
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
	  return bfd_reloc_dangerous;

	case R_MN10300_GOT32:
	  if (ELF_ST_VISIBILITY (h->other) == STV_PROTECTED
	      && (h->type == STT_FUNC || h->type == STT_GNU_IFUNC))
	    return bfd_reloc_dangerous;
	  break;
	}
    }
  return bfd_reloc_ok;
}

static bfd_reloc_status_type
mn10300_elf_final_link_relocate (reloc_howto_type *howto,
				 bfd *input_bfd,
				 bfd *output_bfd,
				 asection *input_section,
				 bfd_byte *contents,
				 bfd_vma offset,
				 bfd_vma value,
				 bfd_vma addend,
				 struct elf_link_hash_entry *h,
				 unsigned long symndx,
				 struct bfd_link_info *info,
				 asection *sym_sec,
				 int is_local ATTRIBUTE_UNUSED)
{
  unsigned long r_type = howto->type;
  bfd_byte *hit_data = contents + offset;
  bool is_sym_diff_reloc;
  bfd_reloc_status_type status;

  status = perform_pic_safety_checks (r_type, info, input_section, h);
  if (status != bfd_reloc_ok)
    return status;

  value = process_sym_diff (r_type, value, input_section, &is_sym_diff_reloc);

  switch (r_type)
    {
    case R_MN10300_SYM_DIFF:
      BFD_ASSERT (addend == 0);
      g_sym_diff_section = input_section;
      g_sym_diff_value = value;
      return bfd_reloc_ok;

    case R_MN10300_ALIGN:
    case R_MN10300_NONE:
    case R_MN10300_GNU_VTINHERIT:
    case R_MN10300_GNU_VTENTRY:
      return bfd_reloc_ok;

    case R_MN10300_32:
      return handle_reloc_32_dynamic (info, input_bfd, output_bfd,
				      input_section, hit_data, offset,
				      value, addend, h, sym_sec,
				      is_sym_diff_reloc);
    case R_MN10300_24:
      return relocate_absolute (input_bfd, value, addend, hit_data, 24);
    case R_MN10300_16:
      return relocate_absolute (input_bfd, value, addend, hit_data, 16);
    case R_MN10300_8:
      return relocate_absolute (input_bfd, value, addend, hit_data, 8);
    case R_MN10300_PCREL32:
      return relocate_pcrel (input_bfd, value, addend, input_section, offset,
			     hit_data, 32);
    case R_MN10300_PCREL16:
      return relocate_pcrel (input_bfd, value, addend, input_section, offset,
			     hit_data, 16);
    case R_MN10300_PCREL8:
      return relocate_pcrel (input_bfd, value, addend, input_section, offset,
			     hit_data, 8);
    case R_MN10300_GOTOFF32:
      return relocate_gotoff (input_bfd, output_bfd, info, value, addend,
			      hit_data, 32);
    case R_MN10300_GOTOFF24:
      return relocate_gotoff (input_bfd, output_bfd, info, value, addend,
			      hit_data, 24);
    case R_MN10300_GOTOFF16:
      return relocate_gotoff (input_bfd, output_bfd, info, value, addend,
			      hit_data, 16);
    case R_MN10300_GOTPC32:
      return relocate_gotpc (input_bfd, output_bfd, info, addend,
			     input_section, offset, hit_data, 32);
    case R_MN10300_GOTPC16:
      return relocate_gotpc (input_bfd, output_bfd, info, addend,
			     input_section, offset, hit_data, 16);
    case R_MN10300_PLT32:
      return relocate_plt (input_bfd, output_bfd, info, h, value, addend,
			   input_section, offset, hit_data, 32);
    case R_MN10300_PLT16:
      return relocate_plt (input_bfd, output_bfd, info, h, value, addend,
			   input_section, offset, hit_data, 16);

    case R_MN10300_TLS_LDO:
      value = dtpoff (info, value);
      bfd_put_32 (input_bfd, value + addend, hit_data);
      return bfd_reloc_ok;
    case R_MN10300_TLS_LE:
      value = tpoff (info, value);
      bfd_put_32 (input_bfd, value + addend, hit_data);
      return bfd_reloc_ok;

    case R_MN10300_TLS_LD:
      {
	struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
	if (elf_hash_table (info)->dynobj == NULL)
	  return bfd_reloc_dangerous;
	asection *sgot = htab->root.sgot;
	BFD_ASSERT (sgot != NULL);
	value = htab->tls_ldm_got.offset + sgot->output_offset;
	bfd_put_32 (input_bfd, value, hit_data);
	if (!htab->tls_ldm_got.rel_emitted)
	  {
	    asection *srelgot = htab->root.srelgot;
	    Elf_Internal_Rela rel;
	    BFD_ASSERT (srelgot != NULL);
	    htab->tls_ldm_got.rel_emitted++;
	    rel.r_offset = sgot->output_section->vma + sgot->output_offset
	      + htab->tls_ldm_got.offset;
	    bfd_put_32 (output_bfd, 0, sgot->contents + htab->tls_ldm_got.offset);
	    bfd_put_32 (output_bfd, 0, sgot->contents + htab->tls_ldm_got.offset + 4);
	    rel.r_info = ELF32_R_INFO (0, R_MN10300_TLS_DTPMOD);
	    rel.r_addend = 0;
	    bfd_elf32_swap_reloca_out (output_bfd, &rel,
				       (bfd_byte *) ((Elf32_External_Rela *) srelgot->contents)
				       + srelgot->reloc_count);
	    srelgot->reloc_count++;
	  }
	return bfd_reloc_ok;
      }
    case R_MN10300_TLS_GOTIE:
      value = tpoff (info, value);
      /* Fall through.  */
    case R_MN10300_TLS_GD:
    case R_MN10300_TLS_IE:
    case R_MN10300_GOT32:
    case R_MN10300_GOT24:
    case R_MN10300_GOT16:
      if (r_type == R_MN10300_TLS_GD)
	value = dtpoff (info, value);
      return handle_got_reloc (input_bfd, output_bfd, info, h, symndx,
			       &value, addend, hit_data, r_type);
    default:
      return bfd_reloc_notsupported;
    }
}

/* Relocate an MN10300 ELF section.  */

static bool
should_skip_relocation_value (struct bfd_link_info *info,
			      asection *input_section,
			      struct elf32_mn10300_link_hash_entry *h,
			      struct elf_link_hash_entry *hh, int r_type)
{
  if (h->root.root.type != bfd_link_hash_defined
      && h->root.root.type != bfd_link_hash_defweak)
    return false;

  switch (r_type)
    {
    case R_MN10300_GOTPC32:
    case R_MN10300_GOTPC16:
      return true;

    case R_MN10300_PLT32:
    case R_MN10300_PLT16:
      return (ELF_ST_VISIBILITY (h->root.other) != STV_INTERNAL
	      && ELF_ST_VISIBILITY (h->root.other) != STV_HIDDEN
	      && h->root.plt.offset != (bfd_vma) -1);

    case R_MN10300_GOT32:
    case R_MN10300_GOT24:
    case R_MN10300_TLS_GD:
    case R_MN10300_TLS_LD:
    case R_MN10300_TLS_GOTIE:
    case R_MN10300_TLS_IE:
    case R_MN10300_GOT16:
      return (elf_hash_table (info)->dynamic_sections_created
	      && !SYMBOL_REFERENCES_LOCAL (info, hh));

    case R_MN10300_32:
      if (SYMBOL_REFERENCES_LOCAL (info, hh))
	return false;
      return (((input_section->flags & SEC_ALLOC) != 0
	       && !bfd_link_executable (info))
	      || ((input_section->flags & SEC_DEBUGGING) != 0
		  && h->root.def_dynamic));
    default:
      return false;
    }
}

static void
handle_tls_transition (struct bfd_link_info *info, bfd *input_bfd,
		       bfd_byte *contents, Elf_Internal_Rela *rel,
		       Elf_Internal_Rela *relend,
		       struct elf_link_hash_entry *hh,
		       asection *input_section, int *r_type_p,
		       reloc_howto_type **howto_p)
{
  int r_type = *r_type_p;
  int tls_r_type =
    elf_mn10300_tls_transition (info, r_type, hh, input_section, 0);

  if (tls_r_type == r_type)
    return;

  bool had_plt =
    mn10300_do_tls_transition (input_bfd, r_type, tls_r_type, contents,
			       rel->r_offset);
  *r_type_p = tls_r_type;
  *howto_p = elf_mn10300_howto_table + tls_r_type;

  if (had_plt)
    {
      Elf_Internal_Rela *trel;
      for (trel = rel + 1; trel < relend; trel++)
	{
	  int trel_type = ELF32_R_TYPE (trel->r_info);
	  if ((trel_type == R_MN10300_PLT32
	       || trel_type == R_MN10300_PCREL32)
	      && rel->r_offset + had_plt == trel->r_offset)
	    trel->r_info = ELF32_R_INFO (0, R_MN10300_NONE);
	}
    }
}

static bool
handle_relocation_error (struct bfd_link_info *info,
			 bfd_reloc_status_type r, bfd *input_bfd,
			 asection *input_section, bfd_vma offset,
			 const char *howto_name,
			 struct elf32_mn10300_link_hash_entry *h,
			 Elf_Internal_Sym *sym, asection *sec,
			 Elf_Internal_Shdr *symtab_hdr, int r_type)
{
  const char *name;
  const char *msg = NULL;

  if (h)
    name = h->root.root.root.string;
  else
    {
      name = bfd_elf_string_from_elf_section (input_bfd,
					      symtab_hdr->sh_link,
					      sym->st_name);
      if (name == NULL || *name == '\0')
	name = bfd_section_name (sec);
    }

  switch (r)
    {
    case bfd_reloc_ok:
      return true;

    case bfd_reloc_overflow:
      (*info->callbacks->reloc_overflow) (info, (h ? &h->root.root : NULL),
					  name, howto_name, (bfd_vma) 0,
					  input_bfd, input_section, offset);
      break;

    case bfd_reloc_undefined:
      (*info->callbacks->undefined_symbol) (info, name, input_bfd,
					    input_section, offset, true);
      break;

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

  if (msg)
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
  Elf_Internal_Rela *rel, *relend;

  relend = relocs + input_section->reloc_count;
  for (rel = relocs; rel < relend; rel++)
    {
      unsigned long r_symndx = ELF32_R_SYM (rel->r_info);
      int r_type = ELF32_R_TYPE (rel->r_info);
      reloc_howto_type *howto = elf_mn10300_howto_table + r_type;
      struct elf_link_hash_entry *hh = NULL;
      asection *sec = NULL;
      bfd_vma relocation = 0;
      bool unresolved_reloc = false;
      struct elf32_mn10300_link_hash_entry *h = NULL;
      Elf_Internal_Sym *sym = NULL;

      if (r_type == R_MN10300_GNU_VTINHERIT
	  || r_type == R_MN10300_GNU_VTENTRY)
	continue;

      if (r_symndx >= symtab_hdr->sh_info)
	{
	  bool warned, ignored;
	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   hh, sec, relocation, unresolved_reloc,
				   warned, ignored);
	  h = elf_mn10300_hash_entry (hh);
	}

      handle_tls_transition (info, input_bfd, contents, rel, relend, hh,
			     input_section, &r_type, &howto);

      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
	}
      else if (h)
	{
	  if (should_skip_relocation_value (info, input_section, h, hh,
					    r_type))
	    relocation = 0;
	  else if (!bfd_link_relocatable (info) && unresolved_reloc
		   && (_bfd_elf_section_offset (output_bfd, info,
						input_section,
						rel->r_offset)
		       != (bfd_vma) -1))
	    _bfd_error_handler (
		_ ("%pB(%pA+%#" PRIx64 "): "
		   "unresolvable %s relocation against symbol `%s'"),
		input_bfd, input_section, (uint64_t) rel->r_offset,
		howto->name, h->root.root.root.string);
	}

      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, R_MN10300_NONE,
					 howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      bfd_reloc_status_type r =
	mn10300_elf_final_link_relocate (howto, input_bfd, output_bfd,
					   input_section, contents,
					   rel->r_offset, relocation,
					   rel->r_addend,
					   (struct elf_link_hash_entry *) h,
					   r_symndx, info, sec, h == NULL);

      if (r != bfd_reloc_ok)
	{
	  if (!handle_relocation_error (info, r, input_bfd, input_section,
					rel->r_offset, howto->name, h, sym,
					sec, symtab_hdr, r_type))
	    return false;
	}
    }

  return true;
}

/* Finish initializing one hash table entry.  */

static bool
elf32_mn10300_finish_hash_table_entry (struct bfd_hash_entry *gen_entry,
				       void *in_args)
{
  struct elf32_mn10300_link_hash_entry *entry =
    (struct elf32_mn10300_link_hash_entry *) gen_entry;
  const struct bfd_link_info *link_info =
    (const struct bfd_link_info *) in_args;

  if (entry->flags == MN10300_CONVERT_CALL_TO_CALLS)
    return true;

  const bool no_prologue_to_optimize =
    (entry->stack_size == 0 && entry->movm_args == 0);
  const unsigned char visibility = ELF_ST_VISIBILITY (entry->root.other);
  const bool is_dynamic_symbol =
    elf_hash_table (link_info)->dynamic_sections_created
    && visibility != STV_INTERNAL && visibility != STV_HIDDEN;

  if (entry->direct_calls == 0 || no_prologue_to_optimize || is_dynamic_symbol)
    {
      entry->flags |= MN10300_CONVERT_CALL_TO_CALLS;
      return true;
    }

  unsigned int prologue_size_savings = 0;

  if (entry->movm_args)
    prologue_size_savings += 2;

  if (entry->stack_size > 0)
    prologue_size_savings += (entry->stack_size <= 128) ? 3 : 4;

  if (prologue_size_savings < entry->direct_calls)
    entry->flags |= MN10300_CONVERT_CALL_TO_CALLS;

  return true;
}

/* Used to count hash table entries.  */

static bool
elf32_mn10300_count_hash_table_entries (struct bfd_hash_entry *gen_entry ATTRIBUTE_UNUSED,
                                        void *in_args)
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
				       void *in_args)
{
  if (in_args == NULL)
    {
      return false;
    }

  struct bfd_hash_entry ***list_cursor_p =
    (struct bfd_hash_entry ***) in_args;

  if (*list_cursor_p == NULL)
    {
      return false;
    }

  **list_cursor_p = gen_entry;
  (*list_cursor_p)++;

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
    {
      return -1;
    }
  if (a->value > b->value)
    {
      return 1;
    }
  return 0;
}

/* Compute the stack size and movm arguments for the function
   referred to by HASH at address ADDR in section with
   contents CONTENTS, store the information in the hash table.  */

#define OPCODE_MOVM_SP 0xcf
#define OPCODE_ADD_IMM8_SP_B1 0xf8
#define OPCODE_ADD_IMM8_SP_B2 0xfe
#define OPCODE_ADD_IMM16_SP_B1 0xfa
#define OPCODE_ADD_IMM16_SP_B2 0xfe

#define MOVM_D2_MASK   0x80
#define MOVM_D3_MASK   0x40
#define MOVM_A2_MASK   0x20
#define MOVM_A3_MASK   0x10
#define MOVM_OTHER_MASK 0x08
#define MOVM_EXREG0_MASK 0x04
#define MOVM_EXREG1_MASK 0x02
#define MOVM_EXOTHER_MASK 0x01

#define SIZE_PER_REGISTER 4
#define SIZE_OTHER_GROUP (8 * SIZE_PER_REGISTER)
#define SIZE_EXOTHER_GROUP (6 * SIZE_PER_REGISTER)
#define SIZE_EXREG1_GROUP (4 * SIZE_PER_REGISTER)
#define SIZE_EXREG0_GROUP (2 * SIZE_PER_REGISTER)
#define MAX_CALL_STACK_ADJUST 255

static bfd_vma
calculate_movm_stack_size (unsigned char movm_args, bfd *abfd)
{
  static const unsigned char popcount4[16] =
    {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};
  bfd_vma size = 0;
  unsigned int mach;

  size += (bfd_vma) popcount4[(movm_args >> 4) & 0xf] * SIZE_PER_REGISTER;

  if ((movm_args & MOVM_OTHER_MASK) != 0)
    size += SIZE_OTHER_GROUP;

  mach = bfd_get_mach (abfd);
  if (mach == bfd_mach_am33 || mach == bfd_mach_am33_2)
    {
      if ((movm_args & MOVM_EXOTHER_MASK) != 0)
        size += SIZE_EXOTHER_GROUP;
      if ((movm_args & MOVM_EXREG1_MASK) != 0)
        size += SIZE_EXREG1_GROUP;
      if ((movm_args & MOVM_EXREG0_MASK) != 0)
        size += SIZE_EXREG0_GROUP;
    }

  return size;
}

static void
compute_function_info (bfd *abfd,
		       struct elf32_mn10300_link_hash_entry *hash,
		       bfd_vma addr,
		       unsigned char *contents)
{
  bfd_vma current_addr = addr;
  unsigned char byte1 = bfd_get_8 (abfd, contents + current_addr);
  unsigned char byte2 = bfd_get_8 (abfd, contents + current_addr + 1);

  if (byte1 == OPCODE_MOVM_SP)
    {
      hash->movm_args = byte2;
      hash->movm_stack_size = calculate_movm_stack_size (byte2, abfd);
      current_addr += 2;
      byte1 = bfd_get_8 (abfd, contents + current_addr);
      byte2 = bfd_get_8 (abfd, contents + current_addr + 1);
    }

  if (byte1 == OPCODE_ADD_IMM8_SP_B1 && byte2 == OPCODE_ADD_IMM8_SP_B2)
    {
      signed char imm8 = (signed char) bfd_get_8 (abfd, contents + current_addr + 2);
      if (imm8 < 0)
        hash->stack_size = (bfd_vma) -imm8;
    }
  else if (byte1 == OPCODE_ADD_IMM16_SP_B1 && byte2 == OPCODE_ADD_IMM16_SP_B2)
    {
      signed short imm16 = (signed short) bfd_get_16 (abfd, contents + current_addr + 2);
      if (imm16 < 0)
        {
          bfd_vma size = (bfd_vma) -imm16;
          if (size < MAX_CALL_STACK_ADJUST)
            hash->stack_size = size;
        }
    }

  if (hash->stack_size + hash->movm_stack_size > MAX_CALL_STACK_ADJUST)
    hash->stack_size = 0;
}

/* Delete some bytes from a section while relaxing.  */

static void
adjust_symbol_value (bfd_vma *value,
                     bfd_vma addr,
                     bfd_vma toaddr,
                     int count)
{
  if (*value > addr && *value < toaddr)
    {
      if (*value < addr + count)
        *value = addr;
      else
        *value -= count;
    }
}

static void
adjust_func_symbol_size (bfd_vma value,
                         bfd_vma *size,
                         bfd_vma addr,
                         bfd_vma toaddr,
                         int count)
{
  if ((value + *size) > addr
      && (value + *size) < toaddr)
    {
      *size -= count;
    }
}

static bool
mn10300_elf_relax_delete_bytes (bfd *abfd,
                                asection *sec,
                                bfd_vma addr,
                                int count)
{
  struct elf_section_data *sec_data = elf_section_data (sec);
  bfd_byte *contents = sec_data->this_hdr.contents;
  bfd_vma toaddr = sec->size;
  Elf_Internal_Rela *irelalign = NULL;

  Elf_Internal_Rela *all_relocs = sec_data->relocs;
  Elf_Internal_Rela *irelend = all_relocs + sec->reloc_count;

  if (sec->reloc_count > 0)
    {
      if (ELF32_R_TYPE ((irelend - 1)->r_info) == R_MN10300_ALIGN)
        --irelend;

      for (Elf_Internal_Rela *irel = all_relocs; irel < irelend; irel++)
        {
          if (ELF32_R_TYPE (irel->r_info) == R_MN10300_ALIGN
              && irel->r_offset > addr
              && irel->r_offset < toaddr)
            {
              Elf32_Sword addend = irel->r_addend;
              if (addend < 0 || addend > 30)
                continue;

              int alignment = 1 << addend;
              if (count < alignment || (alignment % count) != 0)
                {
                  irelalign = irel;
                  toaddr = irel->r_offset;
                  break;
                }
            }
        }
    }

  if (addr > toaddr || (bfd_vma) count > toaddr - addr)
    return true;

  memmove (contents + addr, contents + addr + count,
           (size_t) (toaddr - addr - count));

  if (irelalign == NULL)
    {
      sec->size -= count;
      toaddr++;
    }
  else
    {
      const bfd_byte NOP_OPCODE = 0xcb;
      memset (contents + toaddr - count, NOP_OPCODE, count);
    }

  for (Elf_Internal_Rela *irel = all_relocs; irel < irelend; irel++)
    {
      if ((irel->r_offset > addr && irel->r_offset < toaddr)
          || (ELF32_R_TYPE (irel->r_info) == R_MN10300_ALIGN
              && irel->r_offset == toaddr))
        irel->r_offset -= count;
    }

  unsigned int sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;

  Elf_Internal_Sym *isym = (Elf_Internal_Sym *) symtab_hdr->contents;
  Elf_Internal_Sym *isymend = isym + symtab_hdr->sh_info;
  for (; isym < isymend; isym++)
    {
      if (isym->st_shndx == sec_shndx)
        {
          bfd_vma old_value = isym->st_value;
          adjust_symbol_value (&isym->st_value, addr, toaddr, count);
          if (isym->st_value == old_value
              && ELF_ST_TYPE (isym->st_info) == STT_FUNC)
            adjust_func_symbol_size (isym->st_value, &isym->st_size,
                                     addr, toaddr, count);
        }
    }

  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (abfd);
  if (sym_hashes)
    {
      unsigned int symcount = (symtab_hdr->sh_size / sizeof (Elf32_External_Sym)
                               - symtab_hdr->sh_info);
      struct elf_link_hash_entry **end_hashes = sym_hashes + symcount;

      for (; sym_hashes < end_hashes; sym_hashes++)
        {
          struct elf_link_hash_entry *sym_hash = *sym_hashes;
          if (sym_hash)
            {
              bool is_defined = (sym_hash->root.type == bfd_link_hash_defined
                                 || sym_hash->root.type == bfd_link_hash_defweak);

              if (is_defined && sym_hash->root.u.def.section == sec)
                {
                  bfd_vma old_value = sym_hash->root.u.def.value;
                  adjust_symbol_value (&sym_hash->root.u.def.value,
                                       addr, toaddr, count);

                  if (sym_hash->root.u.def.value == old_value
                      && sym_hash->root.type == bfd_link_hash_defined
                      && sym_hash->type == STT_FUNC)
                    adjust_func_symbol_size (sym_hash->root.u.def.value,
                                             &sym_hash->size, addr, toaddr,
                                             count);
                }
            }
        }
    }

  if (irelalign != NULL)
    {
      Elf32_Sword addend = irelalign->r_addend;
      if (addend > 0 && addend < 31)
        {
          bfd_vma align_p2 = (bfd_vma) 1 << addend;
          bfd_vma alignto = BFD_ALIGN (toaddr, align_p2);
          bfd_vma alignaddr = BFD_ALIGN (irelalign->r_offset, align_p2);

          if (alignaddr < alignto)
            return mn10300_elf_relax_delete_bytes (abfd, sec, alignaddr,
                                                   (int) (alignto - alignaddr));
        }
    }

  return true;
}

/* Return TRUE if a symbol exists at the given address, else return
   FALSE.  */

static bool
mn10300_elf_symbol_address_p (bfd *abfd,
			      asection *sec,
			      Elf_Internal_Sym *isym,
			      bfd_vma addr)
{
  const Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  const unsigned int sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);

  const Elf_Internal_Sym * const local_isym_end = isym + symtab_hdr->sh_info;
  for (const Elf_Internal_Sym *current_isym = isym; current_isym < local_isym_end; ++current_isym)
    {
      if (current_isym->st_shndx == sec_shndx && current_isym->st_value == addr)
	{
	  return true;
	}
    }

  if (symtab_hdr->sh_entsize > 0)
    {
      struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (abfd);
      if (sym_hashes)
	{
	  const unsigned int global_sym_count =
	    (symtab_hdr->sh_size / symtab_hdr->sh_entsize) - symtab_hdr->sh_info;
	  struct elf_link_hash_entry ** const end_hashes = sym_hashes + global_sym_count;

	  for (; sym_hashes < end_hashes; ++sym_hashes)
	    {
	      const struct elf_link_hash_entry *sym_hash = *sym_hashes;
	      if (sym_hash)
		{
		  const enum bfd_link_hash_type type = sym_hash->root.type;
		  const bool is_defined = (type == bfd_link_hash_defined
					   || type == bfd_link_hash_defweak);

		  if (is_defined
		      && sym_hash->root.u.def.section == sec
		      && sym_hash->root.u.def.value == addr)
		    {
		      return true;
		    }
		}
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
get_elf_symbols (bfd *abfd, Elf_Internal_Shdr *symtab_hdr,
                 Elf_Internal_Sym **isymbuf_p, bool keep_memory)
{
  *isymbuf_p = (Elf_Internal_Sym *) symtab_hdr->contents;
  if (*isymbuf_p == NULL)
    {
      *isymbuf_p = bfd_elf_get_elf_syms (abfd, symtab_hdr,
                                       symtab_hdr->sh_info, 0,
                                       NULL, NULL, NULL);
      if (*isymbuf_p == NULL)
        return false;
      if (keep_memory)
        symtab_hdr->contents = (unsigned char *) *isymbuf_p;
    }
  return true;
}

static void
manage_elf_symbols (Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym *isymbuf,
                    bool keep_memory)
{
  if (isymbuf != NULL && symtab_hdr->contents != (unsigned char *) isymbuf)
    {
      if (!keep_memory)
        free (isymbuf);
      else
        symtab_hdr->contents = (unsigned char *) isymbuf;
    }
}

static bool
get_section_contents (bfd *abfd, asection *sec, bfd_byte **contents_p)
{
  *contents_p = elf_section_data (sec)->this_hdr.contents;
  if (*contents_p == NULL && sec->size != 0)
    {
      if (!bfd_malloc_and_get_section (abfd, sec, contents_p))
        return false;
    }
  return true;
}

static void
manage_section_contents (asection *sec, bfd_byte *contents, bool keep_memory)
{
  if (contents != NULL && elf_section_data (sec)->this_hdr.contents != contents)
    {
      if (keep_memory)
        elf_section_data (sec)->this_hdr.contents = contents;
      else
        free (contents);
    }
}

static bool
get_relocs (bfd *abfd, asection *sec, Elf_Internal_Rela **relocs_p, bool keep_memory)
{
  *relocs_p = NULL;
  if ((sec->flags & SEC_RELOC) == 0 || sec->reloc_count == 0)
    return true;

  *relocs_p = _bfd_elf_link_read_relocs (abfd, sec, NULL, NULL, keep_memory);
  return *relocs_p != NULL;
}

static void
manage_relocs (asection *sec, Elf_Internal_Rela *relocs)
{
  if (relocs && elf_section_data (sec)->relocs != relocs)
    free (relocs);
}

static struct elf32_mn10300_link_hash_entry *
get_local_sym_hash (struct elf32_mn10300_link_hash_table *hash_table,
                    bfd *input_bfd, Elf_Internal_Shdr *symtab_hdr,
                    asection *sym_sec, const char *sym_name, bool create)
{
  char *new_name;
  size_t amt = strlen (sym_name) + 10;
  struct elf_link_hash_entry *h;

  new_name = bfd_malloc (amt);
  if (new_name == NULL)
    return NULL;

  snprintf (new_name, amt, "%s_%08x", sym_name, sym_sec->id);
  h = elf_link_hash_lookup (&hash_table->static_hash_table->root, new_name,
                            create, create, false);
  free (new_name);
  return (struct elf32_mn10300_link_hash_entry *) h;
}

static bool
scan_section_relocs_for_init (bfd *input_bfd, asection *sec,
                              struct elf32_mn10300_link_hash_table *hash_table,
                              Elf_Internal_Shdr *symtab_hdr,
                              Elf_Internal_Sym *isymbuf,
                              bfd_byte *contents)
{
  Elf_Internal_Rela *internal_relocs = NULL;
  Elf_Internal_Rela *irel, *irelend;
  bool res = false;

  if (!get_relocs (input_bfd, sec, &internal_relocs, false))
    return false;

  if (internal_relocs == NULL)
    return true;

  irel = internal_relocs;
  irelend = irel + sec->reloc_count;
  for (; irel < irelend; irel++)
    {
      long r_type = ELF32_R_TYPE (irel->r_info);
      unsigned long r_index = ELF32_R_SYM (irel->r_info);
      struct elf32_mn10300_link_hash_entry *hash;

      if (r_type < 0 || r_type >= (int) R_MN10300_MAX)
        goto cleanup;

      if (r_index < symtab_hdr->sh_info)
        {
          Elf_Internal_Sym *isym = isymbuf + r_index;
          asection *sym_sec;
          const char *sym_name;

          if (ELF_ST_TYPE (isym->st_info) != STT_FUNC)
            continue;

          if (isym->st_shndx == SHN_UNDEF)
            sym_sec = bfd_und_section_ptr;
          else if (isym->st_shndx == SHN_ABS)
            sym_sec = bfd_abs_section_ptr;
          else if (isym->st_shndx == SHN_COMMON)
            sym_sec = bfd_com_section_ptr;
          else
            sym_sec = bfd_section_from_elf_index (input_bfd, isym->st_shndx);

          sym_name = bfd_elf_string_from_elf_section (input_bfd,
                                                      symtab_hdr->sh_link,
                                                      isym->st_name);
          hash = get_local_sym_hash (hash_table, input_bfd, symtab_hdr, sym_sec, sym_name, true);
          if (hash == NULL)
            goto cleanup;
        }
      else
        {
          r_index -= symtab_hdr->sh_info;
          hash = (struct elf32_mn10300_link_hash_entry *) elf_sym_hashes (input_bfd)[r_index];
        }

      if ((sec->flags & SEC_CODE) != 0)
        {
          unsigned char code = bfd_get_8 (input_bfd, contents + irel->r_offset - 1);
          if (code != 0xdd && code != 0xcd)
            hash->flags |= MN10300_CONVERT_CALL_TO_CALLS;
        }

      if (r_type == R_MN10300_PCREL32 || r_type == R_MN10300_PLT32
          || r_type == R_MN10300_PLT16 || r_type == R_MN10300_PCREL16)
        hash->direct_calls++;
      else
        hash->flags |= MN10300_CONVERT_CALL_TO_CALLS;
    }

  res = true;

cleanup:
  manage_relocs (sec, internal_relocs);
  return res;
}

static bool
scan_section_functions_for_init (bfd *input_bfd, asection *sec,
                                 struct elf32_mn10300_link_hash_table *hash_table,
                                 Elf_Internal_Shdr *symtab_hdr,
                                 Elf_Internal_Sym *isymbuf,
                                 bfd_byte *contents)
{
  unsigned int sec_shndx = _bfd_elf_section_from_bfd_section (input_bfd, sec);
  struct elf_link_hash_entry **hashes = elf_sym_hashes (input_bfd);
  unsigned int symcount = (symtab_hdr->sh_size / sizeof (Elf32_External_Sym) - symtab_hdr->sh_info);
  struct elf_link_hash_entry **end_hashes = hashes + symcount;
  Elf_Internal_Sym *isym, *isymend;

  isymend = isymbuf + symtab_hdr->sh_info;
  for (isym = isymbuf; isym < isymend; isym++)
    {
      if (isym->st_shndx == sec_shndx && ELF_ST_TYPE (isym->st_info) == STT_FUNC)
        {
          struct elf_link_hash_entry **lhashes;
          for (lhashes = hashes; lhashes < end_hashes; lhashes++)
            {
              struct elf32_mn10300_link_hash_entry *h = (struct elf32_mn10300_link_hash_entry *) *lhashes;
              if ((h->root.root.type == bfd_link_hash_defined || h->root.root.type == bfd_link_hash_defweak)
                  && h->root.root.u.def.section == sec
                  && h->root.type == STT_FUNC
                  && h->root.root.u.def.value == isym->st_value)
                break;
            }
          if (lhashes != end_hashes)
            continue;

          asection *sym_sec;
          const char *sym_name;
          struct elf32_mn10300_link_hash_entry *hash;

          if (isym->st_shndx == SHN_UNDEF)
            sym_sec = bfd_und_section_ptr;
          else if (isym->st_shndx == SHN_ABS)
            sym_sec = bfd_abs_section_ptr;
          else if (isym->st_shndx == SHN_COMMON)
            sym_sec = bfd_com_section_ptr;
          else
            sym_sec = bfd_section_from_elf_index (input_bfd, isym->st_shndx);

          sym_name = bfd_elf_string_from_elf_section (input_bfd, symtab_hdr->sh_link, isym->st_name);
          hash = get_local_sym_hash (hash_table, input_bfd, symtab_hdr, sym_sec, sym_name, true);
          if (!hash)
            return false;
          compute_function_info (input_bfd, hash, isym->st_value, contents);
          hash->value = isym->st_value;
        }
    }

  for (; hashes < end_hashes; hashes++)
    {
      struct elf32_mn10300_link_hash_entry *hash = (struct elf32_mn10300_link_hash_entry *) *hashes;
      if ((hash->root.root.type == bfd_link_hash_defined || hash->root.root.type == bfd_link_hash_defweak)
          && hash->root.root.u.def.section == sec && hash->root.type == STT_FUNC)
        compute_function_info (input_bfd, hash, hash->root.root.u.def.value, contents);
    }
  return true;
}

static bool
gather_info_from_bfd (bfd *input_bfd, struct bfd_link_info *link_info,
                      struct elf32_mn10300_link_hash_table *hash_table)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  Elf_Internal_Sym *isymbuf = NULL;
  asection *sec;
  bool success = false;

  if (symtab_hdr->sh_info != 0)
    if (!get_elf_symbols (input_bfd, symtab_hdr, &isymbuf, link_info->keep_memory))
      return false;

  for (sec = input_bfd->sections; sec != NULL; sec = sec->next)
    {
      bfd_byte *contents = NULL;
      bool contents_alloced = false;

      if ((sec->flags & (SEC_ALLOC | SEC_HAS_CONTENTS | SEC_RELOC)) == 0 || sec->reloc_count == 0)
        continue;

      contents = elf_section_data (sec)->this_hdr.contents;
      if (contents == NULL && sec->size != 0)
        {
          if (!bfd_malloc_and_get_section (input_bfd, sec, &contents))
            goto bfd_cleanup;
          contents_alloced = true;
        }

      if (!scan_section_relocs_for_init (input_bfd, sec, hash_table, symtab_hdr, isymbuf, contents))
        {
          if (contents_alloced) free (contents);
          goto bfd_cleanup;
        }

      if ((sec->flags & SEC_CODE) != 0 &&
          !scan_section_functions_for_init (input_bfd, sec, hash_table, symtab_hdr, isymbuf, contents))
        {
          if (contents_alloced) free (contents);
          goto bfd_cleanup;
        }

      if (contents_alloced)
        manage_section_contents (sec, contents, link_info->keep_memory);
    }

  success = true;

bfd_cleanup:
  manage_elf_symbols (symtab_hdr, isymbuf, link_info->keep_memory);
  return success;
}

static bool
merge_static_symbol_flags (struct elf32_mn10300_link_hash_table *hash_table)
{
  int static_count = 0;
  struct elf32_mn10300_link_hash_entry **entries, **ptr;

  elf32_mn10300_link_hash_traverse (hash_table->static_hash_table,
                                    elf32_mn10300_count_hash_table_entries,
                                    &static_count);
  if (static_count == 0)
    return true;

  entries = bfd_malloc (static_count * sizeof (*ptr));
  if (!entries)
    return false;

  ptr = entries;
  elf32_mn10300_link_hash_traverse (hash_table->static_hash_table,
                                    elf32_mn10300_list_hash_table_entries,
                                    &ptr);

  qsort (entries, static_count, sizeof (entries[0]), sort_by_value);

  for (int i = 0; i < static_count - 1; i++)
    {
      if (entries[i]->value && entries[i]->value == entries[i + 1]->value)
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
  free (entries);
  return true;
}

static bool
delete_prologue_in_section (bfd *input_bfd, asection *sec, struct bfd_link_info *link_info,
                            struct elf32_mn10300_link_hash_table *hash_table,
                            Elf_Internal_Shdr *symtab_hdr,
                            Elf_Internal_Sym *isymbuf, bool *again)
{
  bfd_byte *contents = NULL;
  Elf_Internal_Rela *internal_relocs = NULL;
  unsigned int sec_shndx;
  Elf_Internal_Sym *isym, *isymend;
  struct elf_link_hash_entry **hashes, **end_hashes;
  unsigned int symcount;
  bool res = false;

  if ((sec->flags & SEC_CODE) == 0 || (sec->flags & SEC_HAS_CONTENTS) == 0 || sec->size == 0)
    return true;

  if (!get_relocs (input_bfd, sec, &internal_relocs, link_info->keep_memory)
      || !get_section_contents (input_bfd, sec, &contents))
    goto cleanup;

  sec_shndx = _bfd_elf_section_from_bfd_section (input_bfd, sec);
  isymend = isymbuf + symtab_hdr->sh_info;
  for (isym = isymbuf; isym < isymend; isym++)
    {
      if (isym->st_shndx != sec_shndx)
        continue;

      asection *sym_sec;
      if (isym->st_shndx == SHN_UNDEF)
        sym_sec = bfd_und_section_ptr;
      else if (isym->st_shndx == SHN_ABS)
        sym_sec = bfd_abs_section_ptr;
      else if (isym->st_shndx == SHN_COMMON)
        sym_sec = bfd_com_section_ptr;
      else
        sym_sec = bfd_section_from_elf_index (input_bfd, isym->st_shndx);

      const char *sym_name = bfd_elf_string_from_elf_section (input_bfd, symtab_hdr->sh_link, isym->st_name);
      struct elf32_mn10300_link_hash_entry *sym_hash = get_local_sym_hash (hash_table, input_bfd, symtab_hdr, sym_sec, sym_name, false);

      if (sym_hash && !(sym_hash->flags & (MN10300_CONVERT_CALL_TO_CALLS | MN10300_DELETED_PROLOGUE_BYTES)))
        {
          int bytes = 0;
          if (sym_hash->movm_args) bytes += 2;
          if (sym_hash->stack_size > 0) bytes += (sym_hash->stack_size <= 128) ? 3 : 4;
          sym_hash->flags |= MN10300_DELETED_PROLOGUE_BYTES;
          if (!mn10300_elf_relax_delete_bytes (input_bfd, sec, isym->st_value, bytes))
            goto cleanup;
          *again = true;
        }
    }

  symcount = (symtab_hdr->sh_size / sizeof (Elf32_External_Sym) - symtab_hdr->sh_info);
  hashes = elf_sym_hashes (input_bfd);
  end_hashes = hashes + symcount;
  for (; hashes < end_hashes; hashes++)
    {
      struct elf32_mn10300_link_hash_entry *sym_hash = (struct elf32_mn10300_link_hash_entry *) *hashes;
      if ((sym_hash->root.root.type == bfd_link_hash_defined || sym_hash->root.root.type == bfd_link_hash_defweak)
          && sym_hash->root.root.u.def.section == sec
          && !(sym_hash->flags & (MN10300_CONVERT_CALL_TO_CALLS | MN10300_DELETED_PROLOGUE_BYTES)))
        {
          int bytes = 0;
          bfd_vma symval = sym_hash->root.root.u.def.value;
          if (sym_hash->movm_args) bytes += 2;
          if (sym_hash->stack_size > 0) bytes += (sym_hash->stack_size <= 128) ? 3 : 4;

          sym_hash->flags |= MN10300_DELETED_PROLOGUE_BYTES;
          if (!mn10300_elf_relax_delete_bytes (input_bfd, sec, symval, bytes))
            goto cleanup;

          for (struct elf_link_hash_entry **hh = elf_sym_hashes (input_bfd); hh < end_hashes; hh++)
            {
              struct elf32_mn10300_link_hash_entry *h = (struct elf32_mn10300_link_hash_entry *) *hh;
              if (h != sym_hash
                  && (h->root.root.type == bfd_link_hash_defined || h->root.root.type == bfd_link_hash_defweak)
                  && h->root.root.u.def.section == sec && !(h->flags & MN10300_CONVERT_CALL_TO_CALLS)
                  && h->root.root.u.def.value == symval && h->root.type == STT_FUNC)
                h->flags |= MN10300_DELETED_PROLOGUE_BYTES;
            }
          *again = true;
        }
    }
  res = true;

cleanup:
  manage_relocs (sec, internal_relocs);
  manage_section_contents (sec, contents, link_info->keep_memory);
  return res;
}

static bool
delete_prologues_in_bfd (bfd *input_bfd, struct bfd_link_info *link_info,
                         struct elf32_mn10300_link_hash_table *hash_table, bool *again)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  Elf_Internal_Sym *isymbuf = NULL;
  asection *sec;
  bool success = false;

  if (symtab_hdr->sh_info != 0)
    if (!get_elf_symbols (input_bfd, symtab_hdr, &isymbuf, link_info->keep_memory))
      return false;

  for (sec = input_bfd->sections; sec != NULL; sec = sec->next)
    {
      if (!delete_prologue_in_section (input_bfd, sec, link_info, hash_table, symtab_hdr, isymbuf, again))
        goto bfd_cleanup;
    }

  success = true;

bfd_cleanup:
  manage_elf_symbols (symtab_hdr, isymbuf, link_info->keep_memory);
  return success;
}

static bool
mn10300_elf_initialize_relax (struct bfd_link_info *link_info,
                              struct elf32_mn10300_link_hash_table *hash_table,
                              bool *again)
{
  bfd *input_bfd;

  for (input_bfd = link_info->input_bfds; input_bfd != NULL; input_bfd = input_bfd->link.next)
    if (!gather_info_from_bfd (input_bfd, link_info, hash_table))
      return false;

  elf32_mn10300_link_hash_traverse (hash_table, elf32_mn10300_finish_hash_table_entry, link_info);
  elf32_mn10300_link_hash_traverse (hash_table->static_hash_table, elf32_mn10300_finish_hash_table_entry, link_info);

  if (!merge_static_symbol_flags (hash_table))
    return false;

  hash_table->flags |= MN10300_HASH_ENTRIES_INITIALIZED;

  for (input_bfd = link_info->input_bfds; input_bfd != NULL; input_bfd = input_bfd->link.next)
    if (!delete_prologues_in_bfd (input_bfd, link_info, hash_table, again))
      return false;

  return true;
}

static bool
get_reloc_sym_info (bfd *abfd, asection *sec, Elf_Internal_Rela *irel,
                    Elf_Internal_Sym *isymbuf, Elf_Internal_Shdr *symtab_hdr,
                    struct elf32_mn10300_link_hash_table *hash_table,
                    bfd_vma *symval_p, asection **sym_sec_p,
                    struct elf32_mn10300_link_hash_entry **h_p)
{
  unsigned long r_sym = ELF32_R_SYM (irel->r_info);

  *h_p = NULL;

  if (r_sym < symtab_hdr->sh_info)
    {
      Elf_Internal_Sym *isym = isymbuf + r_sym;
      const char *sym_name;

      if (isym->st_shndx == SHN_UNDEF)
        *sym_sec_p = bfd_und_section_ptr;
      else if (isym->st_shndx == SHN_ABS)
        *sym_sec_p = bfd_abs_section_ptr;
      else if (isym->st_shndx == SHN_COMMON)
        *sym_sec_p = bfd_com_section_ptr;
      else
        *sym_sec_p = bfd_section_from_elf_index (abfd, isym->st_shndx);

      sym_name = bfd_elf_string_from_elf_section (abfd, symtab_hdr->sh_link, isym->st_name);
      *h_p = get_local_sym_hash (hash_table, abfd, symtab_hdr, *sym_sec_p, sym_name, false);

      if (((*sym_sec_p)->flags & SEC_MERGE) && (*sym_sec_p)->sec_info_type == SEC_INFO_TYPE_MERGE)
        {
          *symval_p = isym->st_value;
          if (ELF_ST_TYPE (isym->st_info) == STT_SECTION)
            *symval_p += irel->r_addend;
          *symval_p = _bfd_merged_section_offset (abfd, sym_sec_p, elf_section_data (*sym_sec_p)->sec_info, *symval_p);
          if (ELF_ST_TYPE (isym->st_info) != STT_SECTION)
            *symval_p += irel->r_addend;
          *symval_p += (*sym_sec_p)->output_section->vma + (*sym_sec_p)->output_offset - irel->r_addend;
        }
      else
        *symval_p = isym->st_value + (*sym_sec_p)->output_section->vma + (*sym_sec_p)->output_offset;
    }
  else
    {
      unsigned long indx = r_sym - symtab_hdr->sh_info;
      *h_p = (struct elf32_mn10300_link_hash_entry *) (elf_sym_hashes (abfd)[indx]);
      BFD_ASSERT (*h_p != NULL);

      if ((*h_p)->root.root.type != bfd_link_hash_defined && (*h_p)->root.root.type != bfd_link_hash_defweak)
        return false;

      if ((*h_p)->root.root.u.def.section->output_section == NULL)
        return false;

      *sym_sec_p = (*h_p)->root.root.u.def.section->output_section;
      *symval_p = ((*h_p)->root.root.u.def.value
                   + (*h_p)->root.root.u.def.section->output_section->vma
                   + (*h_p)->root.root.u.def.section->output_offset);
    }
  return true;
}

static bool
mn10300_elf_relax_instructions (bfd *abfd, asection *sec,
                                struct bfd_link_info *link_info, bool *again)
{
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Rela *internal_relocs = NULL;
  Elf_Internal_Rela *irel, *irelend;
  bfd_byte *contents = NULL;
  Elf_Internal_Sym *isymbuf = NULL;
  struct elf32_mn10300_link_hash_table *hash_table;
  bool success = false;
  bfd_vma align_gap_adjustment = 0;

  if (bfd_link_relocatable (link_info) || (sec->flags & SEC_RELOC) == 0
      || sec->reloc_count == 0 || (sec->flags & SEC_CODE) == 0)
    return true;

  hash_table = elf32_mn10300_hash_table (link_info);
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;

  if (!get_relocs (abfd, sec, &internal_relocs, link_info->keep_memory))
    goto cleanup;

  irelend = internal_relocs + sec->reloc_count;
  for (irel = internal_relocs; irel < irelend; irel++)
    {
      if (ELF32_R_TYPE (irel->r_info) == (int) R_MN10300_ALIGN)
        {
          bfd_vma adj = 1 << irel->r_addend;
          bfd_vma aend = BFD_ALIGN (irel->r_offset, 1 << irel->r_addend);
          adj = 2 * adj - adj - 1;
          if (align_gap_adjustment < adj
              && aend < sec->output_section->vma + sec->output_offset + sec->size)
            align_gap_adjustment = adj;
        }
    }

  for (irel = internal_relocs; irel < irelend; irel++)
    {
      long r_type = ELF32_R_TYPE (irel->r_info);

      if (r_type == R_MN10300_NONE || r_type == R_MN10300_8 || r_type >= R_MN10300_MAX)
        continue;

      if (contents == NULL && !get_section_contents (abfd, sec, &contents))
        goto cleanup;

      if (isymbuf == NULL && symtab_hdr->sh_info != 0
          && !get_elf_symbols (abfd, symtab_hdr, &isymbuf, link_info->keep_memory))
        goto cleanup;

      bfd_vma symval;
      asection *sym_sec = NULL;
      struct elf32_mn10300_link_hash_entry *h = NULL;
      if (!get_reloc_sym_info (abfd, sec, irel, isymbuf, symtab_hdr, hash_table, &symval, &sym_sec, &h))
        continue;

    }

  success = true;

cleanup:
  manage_elf_symbols (symtab_hdr, isymbuf, link_info->keep_memory);
  manage_section_contents (sec, contents, link_info->keep_memory);
  manage_relocs (sec, internal_relocs);

  return success;
}

static bool
mn10300_elf_relax_section (bfd *abfd,
                           asection *sec,
                           struct bfd_link_info *link_info,
                           bool *again)
{
  struct elf32_mn10300_link_hash_table *hash_table;
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  Elf_Internal_Rela *internal_relocs = NULL;
  Elf_Internal_Sym *isymbuf = NULL;
  bfd_byte *contents = NULL;
  bool success = false;

  if (bfd_link_relocatable (link_info))
    link_info->callbacks->fatal (_("%P: --relax and -r may not be used together\n"));

  *again = false;

  hash_table = elf32_mn10300_hash_table (link_info);
  if (hash_table == NULL)
    return false;

  if ((hash_table->flags & MN10300_HASH_ENTRIES_INITIALIZED) == 0)
    {
      if (!mn10300_elf_initialize_relax (link_info, hash_table, again))
        return false;
    }

  if ((sec->flags & SEC_RELOC) == 0 || sec->reloc_count == 0 || (sec->flags & SEC_CODE) == 0)
    return true;

  if (!get_relocs (abfd, sec, &internal_relocs, link_info->keep_memory))
    goto cleanup;

  if (internal_relocs == NULL)
    return true;


  success = true;

cleanup:
  manage_elf_symbols (symtab_hdr, isymbuf, link_info->keep_memory);
  manage_section_contents (sec, contents, link_info->keep_memory);
  if (internal_relocs && elf_section_data (sec)->relocs != internal_relocs)
    free (internal_relocs);

  return success;
}

/* This is a version of bfd_generic_get_relocated_section_contents
   which uses mn10300_elf_relocate_section.  */

static asection *
get_section_from_symbol (bfd *input_bfd, const Elf_Internal_Sym *isym)
{
  switch (isym->st_shndx)
    {
    case SHN_UNDEF:
      return bfd_und_section_ptr;
    case SHN_ABS:
      return bfd_abs_section_ptr;
    case SHN_COMMON:
      return bfd_com_section_ptr;
    default:
      return bfd_section_from_elf_index (input_bfd, isym->st_shndx);
    }
}

static bool
mn10300_elf_apply_relocations (bfd *output_bfd,
                               struct bfd_link_info *link_info,
                               asection *input_section,
                               bfd_byte *data)
{
  bfd *input_bfd = input_section->owner;
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  Elf_Internal_Rela *internal_relocs = NULL;
  Elf_Internal_Sym *isymbuf = NULL;
  asection **sections = NULL;
  bool success = false;

  internal_relocs = _bfd_elf_link_read_relocs (input_bfd, input_section,
                                               NULL, NULL, false);
  if (internal_relocs == NULL)
    return false;

  do
    {
      if (symtab_hdr->sh_info == 0)
        {
          success = mn10300_elf_relocate_section (output_bfd, link_info, input_bfd,
                                                  input_section, data, internal_relocs,
                                                  NULL, NULL);
          break;
        }

      isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
      if (isymbuf == NULL)
        {
          isymbuf = bfd_elf_get_elf_syms (input_bfd, symtab_hdr,
                                          symtab_hdr->sh_info, 0,
                                          NULL, NULL, NULL);
          if (isymbuf == NULL)
            break;
        }

      bfd_size_type amt = symtab_hdr->sh_info * sizeof (asection *);
      sections = bfd_malloc (amt);
      if (sections == NULL)
        break;

      Elf_Internal_Sym *isym_end = isymbuf + symtab_hdr->sh_info;
      for (Elf_Internal_Sym *isym = isymbuf, **secp = sections; isym < isym_end; ++isym, ++secp)
        *secp = get_section_from_symbol (input_bfd, isym);

      success = mn10300_elf_relocate_section (output_bfd, link_info, input_bfd,
                                              input_section, data, internal_relocs,
                                              isymbuf, sections);
    }
  while (0);

  free (sections);
  if (isymbuf != NULL && symtab_hdr->contents != (unsigned char *) isymbuf)
    free (isymbuf);
  if (internal_relocs != elf_section_data (input_section)->relocs)
    free (internal_relocs);

  return success;
}

static bfd_byte *
mn10300_elf_get_relocated_section_contents (bfd *output_bfd,
					    struct bfd_link_info *link_info,
					    struct bfd_link_order *link_order,
					    bfd_byte *data,
					    bool relocatable,
					    asymbol **symbols)
{
  asection *input_section = link_order->u.indirect.section;
  const bfd_byte *contents = elf_section_data (input_section)->this_hdr.contents;

  if (relocatable || contents == NULL)
    return bfd_generic_get_relocated_section_contents (output_bfd, link_info,
						       link_order, data,
						       relocatable,
						       symbols);

  bfd_byte *target_data = data;
  bool target_data_is_local = (target_data == NULL);

  if (target_data_is_local)
    {
      target_data = bfd_malloc (input_section->size);
      if (target_data == NULL)
	return NULL;
    }

  memcpy (target_data, contents, (size_t) input_section->size);

  if ((input_section->flags & SEC_RELOC) != 0
      && input_section->reloc_count > 0)
    {
      if (!mn10300_elf_apply_relocations (output_bfd, link_info, input_section,
                                          target_data))
	{
	  if (target_data_is_local)
	    free (target_data);
	  return NULL;
	}
    }

  return target_data;
}

/* Assorted hash table functions.  */

/* Initialize an entry in the link hash table.  */

/* Create an entry in an MN10300 ELF linker hash table.  */

static struct bfd_hash_entry *
elf32_mn10300_link_hash_newfunc (struct bfd_hash_entry *entry,
                                 struct bfd_hash_table *table,
                                 const char *string)
{
  struct elf32_mn10300_link_hash_entry *ret =
    (struct elf32_mn10300_link_hash_entry *) entry;

  if (ret == NULL)
    {
      ret = (struct elf32_mn10300_link_hash_entry *)
        bfd_hash_allocate (table, sizeof (*ret));
      if (ret == NULL)
        return NULL;
    }

  ret = (struct elf32_mn10300_link_hash_entry *)
    _bfd_elf_link_hash_newfunc ((struct bfd_hash_entry *) ret,
                                table, string);
  if (ret == NULL)
    return NULL;

  ret->direct_calls = 0;
  ret->stack_size = 0;
  ret->movm_args = 0;
  ret->movm_stack_size = 0;
  ret->flags = 0;
  ret->value = 0;
  ret->tls_type = GOT_UNKNOWN;

  return (struct bfd_hash_entry *) ret;
}

static void
_bfd_mn10300_copy_indirect_symbol (struct bfd_link_info *info,
				   struct elf_link_hash_entry *dir,
				   struct elf_link_hash_entry *ind)
{
  if (!info || !dir || !ind)
    {
      return;
    }

  struct elf32_mn10300_link_hash_entry *edir = elf_mn10300_hash_entry (dir);
  struct elf32_mn10300_link_hash_entry *eind = elf_mn10300_hash_entry (ind);

  const bfd_boolean is_indirect_symbol = (ind->root.type == bfd_link_hash_indirect);
  const bfd_boolean got_is_unused = (dir->got.refcount <= 0);

  if (is_indirect_symbol && got_is_unused)
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
  if (!obfd || !obfd->link.hash)
    {
      return;
    }

  struct elf32_mn10300_link_hash_table * const hash_table =
    (struct elf32_mn10300_link_hash_table *) obfd->link.hash;

  obfd->link.hash = &hash_table->static_hash_table->root.root;
  _bfd_elf_link_hash_table_free (obfd);

  obfd->is_linker_output = true;

  obfd->link.hash = &hash_table->root.root;
  _bfd_elf_link_hash_table_free (obfd);
}

/* Create an mn10300 ELF linker hash table.  */

static struct bfd_link_hash_table *
elf32_mn10300_link_hash_table_create (bfd *abfd)
{
  struct elf32_mn10300_link_hash_table *ret;

  ret = bfd_zmalloc (sizeof (*ret));
  if (ret == NULL)
    return NULL;

  ret->static_hash_table = bfd_zmalloc (sizeof (*ret->static_hash_table));
  if (ret->static_hash_table == NULL)
    {
      free (ret);
      return NULL;
    }

  if (!_bfd_elf_link_hash_table_init (&ret->static_hash_table->root, abfd,
				      elf32_mn10300_link_hash_newfunc,
				      sizeof (struct elf32_mn10300_link_hash_entry)))
    {
      goto fail_static_hash_alloc;
    }

  abfd->is_linker_output = false;
  abfd->link.hash = NULL;
  if (!_bfd_elf_link_hash_table_init (&ret->root, abfd,
				      elf32_mn10300_link_hash_newfunc,
				      sizeof (struct elf32_mn10300_link_hash_entry)))
    {
      goto fail_main_hash_init;
    }

  ret->root.root.hash_table_free = elf32_mn10300_link_hash_table_free;
  ret->tls_ldm_got.offset = -1;

  return &ret->root.root;

fail_main_hash_init:
  abfd->is_linker_output = true;
  abfd->link.hash = &ret->static_hash_table->root.root;
  _bfd_elf_link_hash_table_free (abfd);

fail_static_hash_alloc:
  free (ret->static_hash_table);
  free (ret);
  return NULL;
}

static unsigned long
elf_mn10300_mach (flagword flags)
{
  switch (flags & EF_MN10300_MACH)
    {
    case E_MN10300_MACH_AM33:
      return bfd_mach_am33;

    case E_MN10300_MACH_AM33_2:
      return bfd_mach_am33_2;

    case E_MN10300_MACH_MN10300:
    default:
      return bfd_mach_mn10300;
    }
}

/* The final processing done just before writing out a MN10300 ELF object
   file.  This gets the MN10300 architecture right based on the machine
   number.  */

static bool
_bfd_mn10300_elf_final_write_processing (bfd *abfd)
{
  unsigned long mach_flag;
  Elf_Internal_Ehdr *hdr = elf_elfheader (abfd);

  switch (bfd_get_mach (abfd))
    {
    case bfd_mach_mn10300:
      mach_flag = E_MN10300_MACH_MN10300;
      break;
    case bfd_mach_am33:
      mach_flag = E_MN10300_MACH_AM33;
      break;
    case bfd_mach_am33_2:
      mach_flag = E_MN10300_MACH_AM33_2;
      break;
    default:
      bfd_set_error (bfd_error_invalid_operation);
      return false;
    }

  hdr->e_flags = (hdr->e_flags & ~EF_MN10300_MACH) | mach_flag;
  return _bfd_elf_final_write_processing (abfd);
}

static bool
_bfd_mn10300_elf_object_p (bfd *abfd)
{
  const Elf_Internal_Ehdr *hdr = elf_elfheader (abfd);

  if (hdr == NULL)
    {
      return false;
    }

  bfd_default_set_arch_mach (abfd, bfd_arch_mn10300,
			     elf_mn10300_mach (hdr->e_flags));
  return true;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bool
_bfd_mn10300_elf_merge_private_bfd_data (const bfd *ibfd, const struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;

  if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour
      || bfd_get_flavour (obfd) != bfd_target_elf_flavour)
    {
      return true;
    }

  const enum bfd_architecture ibfd_arch = bfd_get_arch (ibfd);
  const unsigned long ibfd_mach = bfd_get_mach (ibfd);
  const enum bfd_architecture obfd_arch = bfd_get_arch (obfd);
  const unsigned long obfd_mach = bfd_get_mach (obfd);

  if (obfd_arch == ibfd_arch && obfd_mach < ibfd_mach)
    {
      return bfd_set_arch_mach (obfd, ibfd_arch, ibfd_mach);
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
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  int ptralign;

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

  const flagword flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY
			  | SEC_LINKER_CREATED);

  const char *relplt_name = bed->default_use_rela_p ? ".rela.plt" : ".rel.plt";
  asection *srelplt_sec = bfd_make_section_anyway_with_flags (abfd, relplt_name,
							      flags | SEC_READONLY);
  if (srelplt_sec == NULL || !bfd_set_section_alignment (srelplt_sec, ptralign))
    {
      return false;
    }
  htab->root.srelplt = srelplt_sec;

  if (!_bfd_mn10300_elf_create_got_section (abfd, info))
    {
      return false;
    }

  if (bed->want_dynbss)
    {
      asection *dynbss_sec = bfd_make_section_anyway_with_flags (abfd, ".dynbss",
								 SEC_ALLOC | SEC_LINKER_CREATED);
      if (dynbss_sec == NULL)
	{
	  return false;
	}

      if (!bfd_link_pic (info))
	{
	  const char *relbss_name = bed->default_use_rela_p ? ".rela.bss" : ".rel.bss";
	  asection *relbss_sec = bfd_make_section_anyway_with_flags (abfd, relbss_name,
								     flags | SEC_READONLY);
	  if (relbss_sec == NULL || !bfd_set_section_alignment (relbss_sec, ptralign))
	    {
	      return false;
	    }
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
handle_function_symbol (struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  asection *s;

  const bool can_use_rel32 = !bfd_link_pic (info) && !h->def_dynamic && !h->ref_dynamic;
  if (can_use_rel32)
    {
      BFD_ASSERT (h->needs_plt);
      return true;
    }

  if (h->dynindx == -1)
    {
      if (!bfd_elf_link_record_dynamic_symbol (info, h))
	return false;
    }

  s = htab->root.splt;
  BFD_ASSERT (s != NULL);

  if (s->size == 0)
    s->size += elf_mn10300_sizeof_plt0 (info);

  if (!bfd_link_pic (info) && !h->def_regular)
    {
      h->root.u.def.section = s;
      h->root.u.def.value = s->size;
    }

  h->plt.offset = s->size;
  s->size += elf_mn10300_sizeof_plt (info);

  s = htab->root.sgotplt;
  BFD_ASSERT (s != NULL);
  s->size += sizeof (Elf32_Addr);

  s = htab->root.srelplt;
  BFD_ASSERT (s != NULL);
  s->size += sizeof (Elf32_External_Rela);

  return true;
}

static void
handle_weak_alias_symbol (struct elf_link_hash_entry *h)
{
  struct elf_link_hash_entry *def = weakdef (h);
  BFD_ASSERT (def->root.type == bfd_link_hash_defined);
  h->root.u.def.section = def->root.u.def.section;
  h->root.u.def.value = def->root.u.def.value;
}

static bool
handle_data_symbol (struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
  if (bfd_link_pic (info) || !h->non_got_ref)
    return true;

  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  bfd *dynobj = htab->root.dynobj;
  asection *s = bfd_get_linker_section (dynobj, ".dynbss");
  BFD_ASSERT (s != NULL);

  const bool needs_reloc = (h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0;
  if (needs_reloc)
    {
      asection *srel = bfd_get_linker_section (dynobj, ".rela.bss");
      BFD_ASSERT (srel != NULL);
      srel->size += sizeof (Elf32_External_Rela);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, s);
}

static bool
_bfd_mn10300_elf_adjust_dynamic_symbol (struct bfd_link_info *info,
					struct elf_link_hash_entry *h)
{
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);

  BFD_ASSERT (htab->root.dynobj != NULL
	      && (h->needs_plt
		  || h->is_weakalias
		  || (h->def_dynamic
		      && h->ref_regular
		      && !h->def_regular)));

  if (h->type == STT_FUNC || h->needs_plt)
    return handle_function_symbol (info, h);

  if (h->is_weakalias)
    {
      handle_weak_alias_symbol (h);
      return true;
    }

  return handle_data_symbol (info, h);
}

/* Set the sizes of the dynamic sections.  */

static bool
_bfd_mn10300_elf_late_size_sections (bfd * output_bfd,
				     struct bfd_link_info * info)
{
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  bfd *dynobj = htab->root.dynobj;
  asection *s;

  if (dynobj == NULL)
    return true;

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      if (bfd_link_executable (info) && !info->nointerp)
	{
	  s = bfd_get_linker_section (dynobj, ".interp");
	  BFD_ASSERT (s != NULL);
	  s->size = sizeof ELF_DYNAMIC_INTERPRETER;
	  s->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
	  s->alloced = 1;
	}
    }
  else
    {
      s = htab->root.sgot;
      if (s != NULL)
	s->size = 0;
    }

  if (htab->tls_ldm_got.refcount > 0)
    {
      s = htab->root.srelgot;
      BFD_ASSERT (s != NULL);
      s->size += sizeof (Elf32_External_Rela);
    }

  bool relocs = false;
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
	continue;

      const char *name = bfd_section_name (s);
      bool is_rela = startswith (name, ".rela");

      if (!is_rela
	  && !startswith (name, ".got")
	  && !streq (name, ".plt")
	  && !streq (name, ".dynbss"))
	{
	  continue;
	}

      if (is_rela && s->size != 0)
	{
	  if (!streq (name, ".rela.plt"))
	    relocs = true;
	  s->reloc_count = 0;
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
	return false;
      s->alloced = 1;
    }

  return _bfd_elf_add_dynamic_tags (output_bfd, info, relocs);
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static void
setup_plt_entry (bfd *output_bfd, struct bfd_link_info *info,
                 struct elf_link_hash_entry *h, Elf_Internal_Sym *sym)
{
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  asection *splt = htab->root.splt;
  asection *sgot = htab->root.sgotplt;
  asection *srel = htab->root.srelplt;
  bfd_byte *plt_entry_base;
  bfd_vma plt_index;
  bfd_vma got_offset;
  Elf_Internal_Rela rel;

  BFD_ASSERT (h->dynindx != -1);
  BFD_ASSERT (splt != NULL && sgot != NULL && srel != NULL);

  plt_index = ((h->plt.offset - elf_mn10300_sizeof_plt0 (info))
	       / elf_mn10300_sizeof_plt (info));

  got_offset = (plt_index + 3) * 4;
  plt_entry_base = splt->contents + h->plt.offset;

  if (!bfd_link_pic (info))
    {
      memcpy (plt_entry_base, elf_mn10300_plt_entry,
	      elf_mn10300_sizeof_plt (info));
      bfd_put_32 (output_bfd,
		  (sgot->output_section->vma + sgot->output_offset + got_offset),
		  (plt_entry_base + elf_mn10300_plt_symbol_offset (info)));
      bfd_put_32 (output_bfd,
		  (1 - h->plt.offset - elf_mn10300_plt_plt0_offset (info)),
		  (plt_entry_base + elf_mn10300_plt_plt0_offset (info)));
    }
  else
    {
      memcpy (plt_entry_base, elf_mn10300_pic_plt_entry,
	      elf_mn10300_sizeof_plt (info));
      bfd_put_32 (output_bfd, got_offset,
		  (plt_entry_base + elf_mn10300_plt_symbol_offset (info)));
    }

  bfd_put_32 (output_bfd, plt_index * sizeof (Elf32_External_Rela),
	      (plt_entry_base + elf_mn10300_plt_reloc_offset (info)));

  bfd_vma got_entry_val = (splt->output_section->vma
			 + splt->output_offset
			 + h->plt.offset
			 + elf_mn10300_plt_temp_offset (info));
  bfd_put_32 (output_bfd, got_entry_val, sgot->contents + got_offset);

  rel.r_offset = sgot->output_section->vma + sgot->output_offset + got_offset;
  rel.r_info = ELF32_R_INFO (h->dynindx, R_MN10300_JMP_SLOT);
  rel.r_addend = 0;
  bfd_elf32_swap_reloca_out (output_bfd, &rel,
			     (bfd_byte *) ((Elf32_External_Rela *) srel->contents
					   + plt_index));

  if (!h->def_regular)
    sym->st_shndx = SHN_UNDEF;
}

static void
emit_got_reloc (bfd *output_bfd, asection *srel, const Elf_Internal_Rela *rel)
{
  if (ELF32_R_TYPE (rel->r_info) == R_MN10300_NONE)
    return;

  bfd_elf32_swap_reloca_out (output_bfd, rel,
			     (bfd_byte *) ((Elf32_External_Rela *) srel->contents
					   + srel->reloc_count));
  ++srel->reloc_count;
}

static void
setup_got_entry (bfd *output_bfd, struct bfd_link_info *info,
                 struct elf_link_hash_entry *h)
{
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  asection *sgot = htab->root.sgot;
  asection *srel = htab->root.srelgot;
  Elf_Internal_Rela rel;
  bool reloc_emitted = false;

  BFD_ASSERT (sgot != NULL && srel != NULL);

  rel.r_offset = (sgot->output_section->vma
		  + sgot->output_offset
		  + (h->got.offset & ~1));
  rel.r_info = ELF32_R_INFO (0, R_MN10300_NONE);
  rel.r_addend = 0;

  switch (elf_mn10300_hash_entry (h)->tls_type)
    {
    case GOT_TLS_GD:
      bfd_put_32 (output_bfd, 0, sgot->contents + h->got.offset);
      bfd_put_32 (output_bfd, 0, sgot->contents + h->got.offset + 4);

      rel.r_info = ELF32_R_INFO (h->dynindx, R_MN10300_TLS_DTPMOD);
      emit_got_reloc (output_bfd, srel, &rel);

      rel.r_offset += 4;
      rel.r_info = ELF32_R_INFO (h->dynindx, R_MN10300_TLS_DTPOFF);
      emit_got_reloc (output_bfd, srel, &rel);
      reloc_emitted = true;
      break;

    case GOT_TLS_IE:
      rel.r_addend = bfd_get_32 (output_bfd, sgot->contents + h->got.offset);
      bfd_put_32 (output_bfd, 0, sgot->contents + h->got.offset);
      rel.r_info = ELF32_R_INFO (h->dynindx != -1 ? h->dynindx : 0, R_MN10300_TLS_TPOFF);
      break;

    default:
      if (bfd_link_pic (info)
	  && (info->symbolic || h->dynindx == -1)
	  && h->def_regular)
	{
	  rel.r_info = ELF32_R_INFO (0, R_MN10300_RELATIVE);
	  rel.r_addend = (h->root.u.def.value
			  + h->root.u.def.section->output_section->vma
			  + h->root.u.def.section->output_offset);
	}
      else
	{
	  bfd_put_32 (output_bfd, 0, sgot->contents + h->got.offset);
	  rel.r_info = ELF32_R_INFO (h->dynindx, R_MN10300_GLOB_DAT);
	  rel.r_addend = 0;
	}
      break;
    }

  if (!reloc_emitted)
    emit_got_reloc (output_bfd, srel, &rel);
}

static void
setup_copy_reloc (bfd *output_bfd, bfd *dynobj, struct elf_link_hash_entry *h)
{
  asection *s;
  Elf_Internal_Rela rel;

  BFD_ASSERT (h->dynindx != -1
	      && (h->root.type == bfd_link_hash_defined
		  || h->root.type == bfd_link_hash_defweak));

  s = bfd_get_linker_section (dynobj, ".rela.bss");
  BFD_ASSERT (s != NULL);

  rel.r_offset = (h->root.u.def.value
		  + h->root.u.def.section->output_section->vma
		  + h->root.u.def.section->output_offset);
  rel.r_info = ELF32_R_INFO (h->dynindx, R_MN10300_COPY);
  rel.r_addend = 0;
  bfd_elf32_swap_reloca_out (output_bfd, &rel,
			     (bfd_byte *) ((Elf32_External_Rela *) s->contents
					   + s->reloc_count));
  ++s->reloc_count;
}

static bool
_bfd_mn10300_elf_finish_dynamic_symbol (bfd * output_bfd,
					struct bfd_link_info * info,
					struct elf_link_hash_entry * h,
					Elf_Internal_Sym * sym)
{
  if (h->plt.offset != (bfd_vma) -1)
    setup_plt_entry (output_bfd, info, h, sym);

  if (h->got.offset != (bfd_vma) -1)
    setup_got_entry (output_bfd, info, h);

  if (h->needs_copy)
    {
      struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
      setup_copy_reloc (output_bfd, htab->root.dynobj, h);
    }

  if (h == elf_hash_table (info)->hdynamic
      || h == elf_hash_table (info)->hgot)
    sym->st_shndx = SHN_ABS;

  return true;
}

/* Finish up the dynamic sections.  */

static void
_bfd_mn10300_elf_process_dynamic_entry (bfd *output_bfd,
				       bfd *dynobj,
				       Elf32_External_Dyn *dyncon,
				       struct elf32_mn10300_link_hash_table *htab)
{
  Elf_Internal_Dyn dyn;
  asection *s;

  bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);

  switch (dyn.d_tag)
    {
    case DT_PLTGOT:
    case DT_JMPREL:
      s = (dyn.d_tag == DT_PLTGOT)
	? htab->root.sgot
	: htab->root.srelplt;
      dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
      bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
      break;

    case DT_PLTRELSZ:
      s = htab->root.srelplt;
      dyn.d_un.d_val = s->size;
      bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
      break;

    default:
      break;
    }
}

static void
_bfd_mn10300_elf_process_dynamic_sections (bfd *output_bfd,
					  bfd *dynobj,
					  asection *sdyn,
					  struct elf32_mn10300_link_hash_table *htab)
{
  BFD_ASSERT (sdyn != NULL);

  Elf32_External_Dyn *dyncon = (Elf32_External_Dyn *) sdyn->contents;
  const Elf32_External_Dyn *dynconend =
    (const Elf32_External_Dyn *) (sdyn->contents + sdyn->size);

  for (; dyncon < dynconend; dyncon++)
    {
      _bfd_mn10300_elf_process_dynamic_entry (output_bfd, dynobj, dyncon, htab);
    }
}

static void
_bfd_mn10300_elf_fill_plt_entry (bfd *output_bfd,
				struct bfd_link_info *info,
				struct elf32_mn10300_link_hash_table *htab)
{
  asection *splt = htab->root.splt;

  if (splt == NULL || splt->size == 0)
    return;

  if (bfd_link_pic (info))
    {
      memcpy (splt->contents, elf_mn10300_pic_plt_entry,
	      elf_mn10300_sizeof_plt (info));
    }
  else
    {
      asection *sgot = htab->root.sgotplt;
      const bfd_vma sgot_vma = sgot->output_section->vma + sgot->output_offset;

      memcpy (splt->contents, elf_mn10300_plt0_entry, PLT0_ENTRY_SIZE);
      bfd_put_32 (output_bfd, sgot_vma + 4,
		  splt->contents + elf_mn10300_plt0_gotid_offset (info));
      bfd_put_32 (output_bfd, sgot_vma + 8,
		  splt->contents + elf_mn10300_plt0_linker_offset (info));
    }

  /* UnixWare sets the entsize of .plt to 4, but this is incorrect
     as it means that the size of the PLT0 section (15 bytes) is not
     a multiple of the sh_entsize.  Some ELF tools flag this as an
     error.  We could pad PLT0 to 16 bytes, but that would introduce
     compatibilty issues with previous toolchains, so instead we
     just set the entry size to 1.  */
  elf_section_data (splt->output_section)->this_hdr.sh_entsize = 1;
}

static void
_bfd_mn10300_elf_fill_got_header (bfd *output_bfd, asection *sgot, asection *sdyn)
{
  if (sgot->size > 0)
    {
      enum { GOT_LINK_MAP_OFFSET = 4, GOT_DL_RESOLVE_OFFSET = 8 };
      bfd_vma dynamic_addr = 0;

      if (sdyn != NULL)
	dynamic_addr = sdyn->output_section->vma + sdyn->output_offset;

      bfd_put_32 (output_bfd, dynamic_addr, sgot->contents);
      bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents + GOT_LINK_MAP_OFFSET);
      bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents + GOT_DL_RESOLVE_OFFSET);
    }

  elf_section_data (sgot->output_section)->this_hdr.sh_entsize = 4;
}

static bool
_bfd_mn10300_elf_finish_dynamic_sections (bfd * output_bfd,
					  struct bfd_link_info * info)
{
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  bfd *dynobj = htab->root.dynobj;
  asection *sgot = htab->root.sgotplt;
  asection *sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  BFD_ASSERT (sgot != NULL);

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      _bfd_mn10300_elf_process_dynamic_sections (output_bfd, dynobj, sdyn, htab);
      _bfd_mn10300_elf_fill_plt_entry (output_bfd, info, htab);
    }

  _bfd_mn10300_elf_fill_got_header (output_bfd, sgot, sdyn);

  return true;
}

/* Classify relocation types, such that combreloc can sort them
   properly.  */

static enum elf_reloc_type_class
_bfd_mn10300_elf_reloc_type_class (const Elf_Internal_Rela *rela)
{
  if (!rela)
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
  return abfd && bfd_elf_allocate_object (abfd, sizeof (struct elf_mn10300_obj_tdata));
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
