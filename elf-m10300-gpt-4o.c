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
_bfd_mn10300_elf_create_got_section(bfd *abfd, struct bfd_link_info *info) {
    const struct elf_backend_data *bed = get_elf_backend_data(abfd);
    struct elf_link_hash_table *htab = elf_hash_table(info);
    flagword flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY | SEC_LINKER_CREATED;
    flagword pltflags = flags | SEC_CODE;
    asection *s;
    int ptralign;

    if (htab->sgot)
        return true;

    switch (bed->s->arch_size) {
        case 32:
            ptralign = 2;
            break;
        case 64:
            ptralign = 3;
            break;
        default:
            bfd_set_error(bfd_error_bad_value);
            return false;
    }

    if (bed->plt_not_loaded) pltflags &= ~(SEC_LOAD | SEC_HAS_CONTENTS);
    if (bed->plt_readonly) pltflags |= SEC_READONLY;

    s = bfd_make_section_anyway_with_flags(abfd, ".plt", pltflags);
    htab->splt = s;
    if (!s || !bfd_set_section_alignment(s, bed->plt_alignment))
        return false;

    if (bed->want_plt_sym) {
        if (!(htab->hplt = _bfd_elf_define_linkage_sym(abfd, info, s, "_PROCEDURE_LINKAGE_TABLE_")))
            return false;
    }

    s = bfd_make_section_anyway_with_flags(abfd, ".got", flags);
    htab->sgot = s;
    if (!s || !bfd_set_section_alignment(s, ptralign))
        return false;

    if (bed->want_got_plt) {
        s = bfd_make_section_anyway_with_flags(abfd, ".got.plt", flags);
        htab->sgotplt = s;
        if (!s || !bfd_set_section_alignment(s, ptralign))
            return false;
    }

    if (!(htab->hgot = _bfd_elf_define_linkage_sym(abfd, info, s, "_GLOBAL_OFFSET_TABLE_")))
        return false;

    s->size += bed->got_header_size;
    return true;
}

static reloc_howto_type *bfd_elf32_bfd_reloc_type_lookup(bfd *abfd ATTRIBUTE_UNUSED, bfd_reloc_code_real_type code) {
  for (size_t i = 0; i < ARRAY_SIZE(mn10300_reloc_map); ++i) {
    if (mn10300_reloc_map[i].bfd_reloc_val == code) {
      return &elf_mn10300_howto_table[mn10300_reloc_map[i].elf_reloc_val];
    }
  }
  return NULL;
}

static reloc_howto_type *bfd_elf32_bfd_reloc_name_lookup(bfd *abfd ATTRIBUTE_UNUSED, const char *r_name) {
    for (unsigned int i = 0; i < ARRAY_SIZE(elf_mn10300_howto_table); i++) {
        if (elf_mn10300_howto_table[i].name && strcasecmp(elf_mn10300_howto_table[i].name, r_name) == 0) {
            return &elf_mn10300_howto_table[i];
        }
    }
    return NULL;
}

/* Set the howto pointer for an MN10300 ELF reloc.  */

bool mn10300_info_to_howto(bfd *abfd, arelent *cache_ptr, Elf_Internal_Rela *dst) {
    unsigned int r_type = ELF32_R_TYPE(dst->r_info);
    
    if (r_type >= R_MN10300_MAX) {
        _bfd_error_handler(_("%pB: unsupported relocation type %#x"), abfd, r_type);
        bfd_set_error(bfd_error_bad_value);
        return false;
    }
    
    cache_ptr->howto = &elf_mn10300_howto_table[r_type];
    return true;
}

static int elf_mn10300_tls_transition(struct bfd_link_info *info, int r_type, struct elf_link_hash_entry *h, asection *sec, bool counting) {
    bool is_local = false;

    if (r_type == R_MN10300_TLS_GD && h && elf_mn10300_hash_entry(h)->tls_type == GOT_TLS_IE) {
        return R_MN10300_TLS_GOTIE;
    }

    if (bfd_link_pic(info) || !(sec->flags & SEC_CODE)) {
        return r_type;
    }

    if (!counting && h && !elf_hash_table(info)->dynamic_sections_created) {
        is_local = true;
    } else {
        is_local = SYMBOL_CALLS_LOCAL(info, h);
    }

    switch (r_type) {
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

static bfd_vma dtpoff(struct bfd_link_info *info, bfd_vma address) {
    struct elf_link_hash_table *htab = elf_hash_table(info);

    if (!htab->tls_sec) {
        // Handle error according to the application context, e.g., log or abort.
        return 0;
    }

    return address - htab->tls_sec->vma;
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

#include <stdint.h>

static bfd_vma tpoff(struct bfd_link_info *info, bfd_vma address) {
    struct elf_link_hash_table *htab = elf_hash_table(info);

    if (!htab || !htab->tls_sec) {
        // Consider proper error handling or logging
        return (bfd_vma)-1;
    }

    return address - (htab->tls_size + htab->tls_sec->vma);
}

/* Returns nonzero if there's a R_MN10300_PLT32 reloc that we now need
   to skip, after this one.  The actual value is the offset between
   this reloc and the PLT reloc.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int mn10300_do_tls_transition(bfd *input_bfd, unsigned int r_type, unsigned int tls_r_type, bfd_byte *contents, bfd_vma offset) {
    bfd_byte *op = contents + offset;
    int gotreg = 0;

    #define TLS_PAIR(r1, r2) ((r1) * R_MN10300_MAX + (r2))

    if (r_type == R_MN10300_TLS_GD || r_type == R_MN10300_TLS_LD) {
        op -= 2;
        assert(bfd_get_8(input_bfd, op) == 0xFC);
        assert(bfd_get_8(input_bfd, op + 1) == 0xCC);
        assert(bfd_get_8(input_bfd, op + 6) == 0xF1);
        gotreg = (bfd_get_8(input_bfd, op + 7) & 0x0c) >> 2;
        assert(bfd_get_8(input_bfd, op + 8) == 0xDD);
    }

    switch (TLS_PAIR(r_type, tls_r_type)) {
        case TLS_PAIR(R_MN10300_TLS_GD, R_MN10300_TLS_GOTIE):
            memcpy(op, "\xFC\x20\x00\x00\x00\x00", 6);
            op[1] |= gotreg;
            memcpy(op + 6, "\xF9\x78\x28", 3);
            memcpy(op + 9, "\xFC\xE4\x00\x00\x00\x00", 6);
            return 7;

        case TLS_PAIR(R_MN10300_TLS_GD, R_MN10300_TLS_LE):
            memcpy(op, "\xFC\xDC\x00\x00\x00\x00", 6);
            memcpy(op + 6, "\xF9\x78\x28", 3);
            memcpy(op + 9, "\xFC\xE4\x00\x00\x00\x00", 6);
            return 7;

        case TLS_PAIR(R_MN10300_TLS_LD, R_MN10300_NONE):
            memcpy(op, "\xF5\x88", 2);
            memcpy(op + 2, "\xFC\xE4\x00\x00\x00\x00", 6);
            memcpy(op + 8, "\xFE\x19\x22\x00\x00\x00\x00", 7);
            return 7;

        case TLS_PAIR(R_MN10300_TLS_LDO, R_MN10300_TLS_LE):
            return 0;

        case TLS_PAIR(R_MN10300_TLS_IE, R_MN10300_TLS_LE):
            if (op[-2] == 0xFC) {
                op -= 2;
                if ((op[1] & 0xFC) == 0xA4) {
                    op[1] &= 0x03;
                    op[1] |= 0xCC;
                } else {
                    op[1] &= 0x03;
                    op[1] |= 0xDC;
                }
            } else if (op[-3] == 0xFE) {
                op[-2] = 0x08;
            } else {
                abort();
            }
            break;

        case TLS_PAIR(R_MN10300_TLS_GOTIE, R_MN10300_TLS_LE):
            if (op[-2] == 0xFC) {
                op -= 2;
                if ((op[1] & 0xF0) == 0x00) {
                    op[1] &= 0x0C;
                    op[1] >>= 2;
                    op[1] |= 0xCC;
                } else {
                    op[1] &= 0x0C;
                    op[1] >>= 2;
                    op[1] |= 0xDC;
                }
            } else if (op[-3] == 0xFE) {
                op[-2] = 0x08;
            } else {
                abort();
            }
            break;

        default:
            fprintf(stderr, "%pB: unsupported transition from %s to %s\n", input_bfd, elf_mn10300_howto_table[r_type].name, elf_mn10300_howto_table[tls_r_type].name);
            break;
    }
    
    #undef TLS_PAIR
    return 0;
}

/* Look through the relocs for a section during the first phase.
   Since we don't do .gots or .plts, we just need to consider the
   virtual table relocs for gc.  */

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

static bool mn10300_elf_check_relocs(bfd *abfd, struct bfd_link_info *info, asection *sec, const Elf_Internal_Rela *relocs) {
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
    Elf_Internal_Sym *isymbuf = (Elf_Internal_Sym *)symtab_hdr->contents;
    struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(abfd);
    bfd *dynobj = elf_hash_table(info)->dynobj;
    bfd_vma *local_got_offsets = elf_local_got_offsets(abfd);
    asection *sgot = NULL, *srelgot = NULL, *sreloc = NULL;
    const Elf_Internal_Rela *rel_end = relocs + sec->reloc_count;
    bool sym_diff_reloc_seen = false;
    bool result = false;

    if (bfd_link_relocatable(info)) return true;

    for (const Elf_Internal_Rela *rel = relocs; rel < rel_end; rel++) {
        struct elf_link_hash_entry *h = NULL;
        unsigned long r_symndx = ELF32_R_SYM(rel->r_info);
        unsigned int r_type = ELF32_R_TYPE(rel->r_info);
        int tls_type = GOT_NORMAL;

        if (r_symndx < symtab_hdr->sh_info) {
            h = NULL;
        } else {
            h = sym_hashes[r_symndx - symtab_hdr->sh_info];
            while (h->root.type == bfd_link_hash_indirect || h->root.type == bfd_link_hash_warning)
                h = (struct elf_link_hash_entry *)h->root.u.i.link;
        }

        r_type = elf_mn10300_tls_transition(info, r_type, h, sec, true);

        if (dynobj == NULL) {
            switch (r_type) {
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
                    elf_hash_table(info)->dynobj = dynobj = abfd;
                    if (!_bfd_mn10300_elf_create_got_section(dynobj, info)) goto fail;
                    break;
                default:
                    break;
            }
        }

        switch (r_type) {
            case R_MN10300_GNU_VTINHERIT:
                if (!bfd_elf_gc_record_vtinherit(abfd, sec, h, rel->r_offset)) goto fail;
                break;
            case R_MN10300_GNU_VTENTRY:
                if (!bfd_elf_gc_record_vtentry(abfd, sec, h, rel->r_addend)) goto fail;
                break;
            case R_MN10300_TLS_LD:
                htab->tls_ldm_got.refcount++;
                tls_type = GOT_TLS_LD;
                if (htab->tls_ldm_got.got_allocated) break;
                goto create_got;
            case R_MN10300_TLS_IE:
            case R_MN10300_TLS_GOTIE:
                if (bfd_link_pic(info)) info->flags |= DF_STATIC_TLS;
            case R_MN10300_TLS_GD:
            case R_MN10300_GOT32:
            case R_MN10300_GOT24:
            case R_MN10300_GOT16:
            create_got:
                switch (r_type) {
                    case R_MN10300_TLS_IE:
                    case R_MN10300_TLS_GOTIE: tls_type = GOT_TLS_IE; break;
                    case R_MN10300_TLS_GD:    tls_type = GOT_TLS_GD; break;
                    default:		      tls_type = GOT_NORMAL; break;
                }

                sgot = htab->root.sgot;
                srelgot = htab->root.srelgot;
                BFD_ASSERT(sgot != NULL && srelgot != NULL);

                if (r_type == R_MN10300_TLS_LD) {
                    htab->tls_ldm_got.offset = sgot->size;
                    htab->tls_ldm_got.got_allocated++;
                } else if (h != NULL) {
                    if (elf_mn10300_hash_entry(h)->tls_type != tls_type
                        && elf_mn10300_hash_entry(h)->tls_type != GOT_UNKNOWN) {
                        if (tls_type == GOT_TLS_IE && elf_mn10300_hash_entry(h)->tls_type == GOT_TLS_GD) {
                        } else if (tls_type == GOT_TLS_GD && elf_mn10300_hash_entry(h)->tls_type == GOT_TLS_IE) {
                            tls_type = GOT_TLS_IE;
                        } else {
                            _bfd_error_handler(_("%pB: %s' accessed both as normal and thread local symbol"),
                                               abfd, h ? h->root.root.string : "<local>");
                        }
                    }

                    elf_mn10300_hash_entry(h)->tls_type = tls_type;

                    if (h->got.offset != (bfd_vma)-1) break;

                    h->got.offset = sgot->size;

                    if (ELF_ST_VISIBILITY(h->other) != STV_INTERNAL && h->dynindx == -1) {
                        if (!bfd_elf_link_record_dynamic_symbol(info, h)) goto fail;
                    }

                    srelgot->size += sizeof(Elf32_External_Rela);
                    if (r_type == R_MN10300_TLS_GD) srelgot->size += sizeof(Elf32_External_Rela);
                } else {
                    if (local_got_offsets == NULL) {
                        size_t size = symtab_hdr->sh_info * (sizeof(bfd_vma) + sizeof(char));
                        local_got_offsets = bfd_alloc(abfd, size);

                        if (local_got_offsets == NULL) goto fail;

                        elf_local_got_offsets(abfd) = local_got_offsets;
                        elf_mn10300_local_got_tls_type(abfd) = (char *)(local_got_offsets + symtab_hdr->sh_info);

                        for (unsigned int i = 0; i < symtab_hdr->sh_info; i++) local_got_offsets[i] = (bfd_vma)-1;
                    }

                    if (local_got_offsets[r_symndx] != (bfd_vma)-1) break;

                    local_got_offsets[r_symndx] = sgot->size;

                    if (bfd_link_pic(info)) {
                        srelgot->size += sizeof(Elf32_External_Rela);
                        if (r_type == R_MN10300_TLS_GD) srelgot->size += sizeof(Elf32_External_Rela);
                    }

                    elf_mn10300_local_got_tls_type(abfd)[r_symndx] = tls_type;
                }

                sgot->size += 4;
                if (r_type == R_MN10300_TLS_GD || r_type == R_MN10300_TLS_LD) sgot->size += 4;

                goto need_shared_relocs;
            case R_MN10300_PLT32:
            case R_MN10300_PLT16:
                if (h == NULL) continue;
                if (ELF_ST_VISIBILITY(h->other) == STV_INTERNAL || ELF_ST_VISIBILITY(h->other) == STV_HIDDEN) break;
                h->needs_plt = 1;
                break;
            case R_MN10300_24:
            case R_MN10300_16:
            case R_MN10300_8:
            case R_MN10300_PCREL32:
            case R_MN10300_PCREL16:
            case R_MN10300_PCREL8:
                if (h != NULL) h->non_got_ref = 1;
                break;
            case R_MN10300_SYM_DIFF:
                sym_diff_reloc_seen = true;
                break;
            case R_MN10300_32:
                if (h != NULL) h->non_got_ref = 1;

            need_shared_relocs:
                if (bfd_link_pic(info) && (sec->flags & SEC_ALLOC) != 0 && !sym_diff_reloc_seen) {
                    asection *sym_section = NULL;

                    if (h == NULL) {
                        if (isymbuf == NULL) isymbuf = bfd_elf_get_elf_syms(abfd, symtab_hdr, symtab_hdr->sh_info, 0, NULL, NULL, NULL);
                        if (isymbuf) {
                            Elf_Internal_Sym *isym = isymbuf + r_symndx;
                            if (isym->st_shndx == SHN_ABS) sym_section = bfd_abs_section_ptr;
                        }
                    } else {
                        if (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak) {
                            sym_section = h->root.u.def.section;
                        }
                    }

                    if (sym_section != bfd_abs_section_ptr) {
                        if (sreloc == NULL) {
                            sreloc = _bfd_elf_make_dynamic_reloc_section(sec, dynobj, 2, abfd, true);
                            if (sreloc == NULL) goto fail;
                        }

                        sreloc->size += sizeof(Elf32_External_Rela);
                    }
                }

                break;
        }

        if (ELF32_R_TYPE(rel->r_info) != R_MN10300_SYM_DIFF) sym_diff_reloc_seen = false;
    }

    result = true;
fail:
    if (symtab_hdr->contents != (unsigned char *)isymbuf) free(isymbuf);

    return result;
}

/* Return the section that should be marked against GC for a given
   relocation.  */

static asection *mn10300_elf_gc_mark_hook(asection *sec, struct bfd_link_info *info, Elf_Internal_Rela *rel, struct elf_link_hash_entry *h, Elf_Internal_Sym *sym) {
    if (h == NULL || (ELF32_R_TYPE(rel->r_info) != R_MN10300_GNU_VTINHERIT && ELF32_R_TYPE(rel->r_info) != R_MN10300_GNU_VTENTRY)) {
        return _bfd_elf_gc_mark_hook(sec, info, rel, h, sym);
    }
    return NULL;
}

/* Perform a relocation as part of a final link.  */

static bfd_reloc_status_type mn10300_elf_final_link_relocate(
    reloc_howto_type *howto, bfd *input_bfd, bfd *output_bfd ATTRIBUTE_UNUSED,
    asection *input_section, bfd_byte *contents, bfd_vma offset, bfd_vma value,
    bfd_vma addend, struct elf_link_hash_entry *h, unsigned long symndx,
    struct bfd_link_info *info, asection *sym_sec ATTRIBUTE_UNUSED,
    int is_local ATTRIBUTE_UNUSED) {
    
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
    static asection *sym_diff_section;
    static bfd_vma sym_diff_value;
    bool is_sym_diff_reloc = false;
    unsigned long r_type = howto->type;
    bfd_byte *hit_data = contents + offset;
    bfd *dynobj = elf_hash_table(info)->dynobj;
    asection *sgot = NULL, *splt = NULL, *sreloc = NULL;

    switch (r_type) {
        case R_MN10300_24:
        case R_MN10300_16:
        case R_MN10300_8:
        case R_MN10300_PCREL8:
        case R_MN10300_PCREL16:
        case R_MN10300_PCREL32:
        case R_MN10300_GOTOFF32:
        case R_MN10300_GOTOFF24:
        case R_MN10300_GOTOFF16:
            if (bfd_link_pic(info) && (input_section->flags & SEC_ALLOC) != 0 && h != NULL &&
                !SYMBOL_REFERENCES_LOCAL(info, h)) {
                return bfd_reloc_dangerous;
            }
            break;
        case R_MN10300_GOT32:
            if (bfd_link_pic(info) && (input_section->flags & SEC_ALLOC) != 0 &&
                h != NULL && ELF_ST_VISIBILITY(h->other) == STV_PROTECTED && 
                (h->type == STT_FUNC || h->type == STT_GNU_IFUNC) && 
                !SYMBOL_REFERENCES_LOCAL(info, h)) {
                return bfd_reloc_dangerous;
            }
            break;
    }

    if (sym_diff_section != NULL) {
        BFD_ASSERT(sym_diff_section == input_section);
        if (r_type == R_MN10300_32 || r_type == R_MN10300_24 || 
            r_type == R_MN10300_16 || r_type == R_MN10300_8) {
            value -= sym_diff_value;
            if (r_type == R_MN10300_32 && value == 0 && 
                strcmp(input_section->name, ".debug_loc") == 0) {
                value = 1;
            }
            sym_diff_section = NULL;
            is_sym_diff_reloc = true;
        } else {
            sym_diff_section = NULL;
        }
    }

    switch (r_type) {
        case R_MN10300_SYM_DIFF:
            BFD_ASSERT(addend == 0);
            sym_diff_section = input_section;
            sym_diff_value = value;
            return bfd_reloc_ok;
        case R_MN10300_ALIGN:
        case R_MN10300_NONE:
            return bfd_reloc_ok;
        case R_MN10300_32:
            if (bfd_link_pic(info) && !is_sym_diff_reloc && sym_sec != bfd_abs_section_ptr &&
                (input_section->flags & SEC_ALLOC) != 0) {
                Elf_Internal_Rela outrel;
                bool skip, relocate;

                if (sreloc == NULL) {
                    sreloc = _bfd_elf_get_dynamic_reloc_section(input_bfd, input_section, /*rela?*/ true);
                    if (sreloc == NULL) {
                        return false;
                    }
                }

                skip = false;
                outrel.r_offset = _bfd_elf_section_offset(input_bfd, info, input_section, offset);
                if (outrel.r_offset == (bfd_vma) -1) {
                    skip = true;
                }

                outrel.r_offset += (input_section->output_section->vma + input_section->output_offset);

                if (skip) {
                    memset(&outrel, 0, sizeof outrel);
                    relocate = false;
                } else {
                    if (h == NULL || SYMBOL_REFERENCES_LOCAL(info, h)) {
                        relocate = true;
                        outrel.r_info = ELF32_R_INFO(0, R_MN10300_RELATIVE);
                        outrel.r_addend = value + addend;
                    } else {
                        BFD_ASSERT(h->dynindx != -1);
                        relocate = false;
                        outrel.r_info = ELF32_R_INFO(h->dynindx, R_MN10300_32);
                        outrel.r_addend = value + addend;
                    }
                }

                bfd_elf32_swap_reloca_out(output_bfd, &outrel, 
                    (bfd_byte *) (((Elf32_External_Rela *) sreloc->contents) + sreloc->reloc_count));
                ++sreloc->reloc_count;

                if (!relocate) {
                    return bfd_reloc_ok;
                }
            }
            value += addend;
            bfd_put_32(input_bfd, value, hit_data);
            return bfd_reloc_ok;
        case R_MN10300_24:
            value += addend;
            if ((long) value > 0x7fffff || (long) value < -0x800000) {
                return bfd_reloc_overflow;
            }
            bfd_put_8(input_bfd, value & 0xff, hit_data);
            bfd_put_8(input_bfd, (value >> 8) & 0xff, hit_data + 1);
            bfd_put_8(input_bfd, (value >> 16) & 0xff, hit_data + 2);
            return bfd_reloc_ok;
        case R_MN10300_16:
            value += addend;
            if ((long) value > 0x7fff || (long) value < -0x8000) {
                return bfd_reloc_overflow;
            }
            bfd_put_16(input_bfd, value, hit_data);
            return bfd_reloc_ok;
        case R_MN10300_8:
            value += addend;
            if ((long) value > 0x7f || (long) value < -0x80) {
                return bfd_reloc_overflow;
            }
            bfd_put_8(input_bfd, value, hit_data);
            return bfd_reloc_ok;
        case R_MN10300_PCREL8:
        case R_MN10300_PCREL16:
        case R_MN10300_PCREL32:
            value -= (input_section->output_section->vma +
                      input_section->output_offset +
                      offset);
            value += addend;

            if (r_type == R_MN10300_PCREL16 || r_type == R_MN10300_PCREL8) {
                if ((long) value > (r_type == R_MN10300_PCREL16 ? 0x7fff : 0x7f) ||
                    (long) value < (r_type == R_MN10300_PCREL16 ? -0x8000 : -0x80)) {
                    return bfd_reloc_overflow;
                }
                if (r_type == R_MN10300_PCREL16) {
                    bfd_put_16(input_bfd, value, hit_data);
                } else {
                    bfd_put_8(input_bfd, value, hit_data);
                }
                return bfd_reloc_ok;
            }
            bfd_put_32(input_bfd, value, hit_data);
            return bfd_reloc_ok;
        case R_MN10300_GNU_VTINHERIT:
        case R_MN10300_GNU_VTENTRY:
            return bfd_reloc_ok;
        case R_MN10300_GOTPC32:
            if (dynobj == NULL) {
                return bfd_reloc_dangerous;
            }
            value = htab->root.sgot->output_section->vma;
            value -= (input_section->output_section->vma +
                      input_section->output_offset +
                      offset);
            value += addend;
            bfd_put_32(input_bfd, value, hit_data);
            return bfd_reloc_ok;
        case R_MN10300_GOTPC16:
            if (dynobj == NULL) {
                return bfd_reloc_dangerous;
            }
            value = htab->root.sgot->output_section->vma;
            value -= (input_section->output_section->vma +
                      input_section->output_offset +
                      offset);
            value += addend;

            if ((long) value > 0x7fff || (long) value < -0x8000) {
                return bfd_reloc_overflow;
            }
            bfd_put_16(input_bfd, value, hit_data);
            return bfd_reloc_ok;
        case R_MN10300_GOTOFF32:
        case R_MN10300_GOTOFF24:
        case R_MN10300_GOTOFF16:
            if (dynobj == NULL) {
                return bfd_reloc_dangerous;
            }
            value -= htab->root.sgot->output_section->vma;
            value += addend;

            if (r_type == R_MN10300_GOTOFF24 && 
                ((long) value > 0x7fffff || (long) value < -0x800000)) {
                return bfd_reloc_overflow;
            }
            if (r_type == R_MN10300_GOTOFF16 && 
                ((long) value > 0x7fff || (long) value < -0x8000)) {
                return bfd_reloc_overflow;
            }
            int shift[3] = {0, 8, 16};
            int max_shift = r_type == R_MN10300_GOTOFF24 ? 3 : 2;
            for (int i = 0; i < max_shift; ++i) {
                bfd_put_8(input_bfd, (value >> shift[i]) & 0xff, hit_data + i);
            }
            return bfd_reloc_ok;
        case R_MN10300_PLT32:
            if (h != NULL && ELF_ST_VISIBILITY(h->other) != STV_INTERNAL &&
                ELF_ST_VISIBILITY(h->other) != STV_HIDDEN && h->plt.offset != (bfd_vma) -1) {
                if (dynobj == NULL) {
                    return bfd_reloc_dangerous;
                }
                splt = htab->root.splt;
                value = (splt->output_section->vma + splt->output_offset + h->plt.offset) - value;
            }
            
            value -= (input_section->output_section->vma + input_section->output_offset + offset);
            value += addend;
            bfd_put_32(input_bfd, value, hit_data);
            return bfd_reloc_ok;
        case R_MN10300_PLT16:
            if (h != NULL && ELF_ST_VISIBILITY(h->other) != STV_INTERNAL &&
                ELF_ST_VISIBILITY(h->other) != STV_HIDDEN && h->plt.offset != (bfd_vma) -1) {
                if (dynobj == NULL) {
                    return bfd_reloc_dangerous;
                }
                splt = htab->root.splt;
                value = (splt->output_section->vma + splt->output_offset + h->plt.offset) - value;
            }
            
            value -= (input_section->output_section->vma + input_section->output_offset + offset);
            value += addend;

            if ((long) value > 0x7fff || (long) value < -0x8000) {
                return bfd_reloc_overflow;
            }
            bfd_put_16(input_bfd, value, hit_data);
            return bfd_reloc_ok;
        case R_MN10300_TLS_LDO:
            value = dtpoff(info, value);
            bfd_put_32(input_bfd, value + addend, hit_data);
            return bfd_reloc_ok;
        case R_MN10300_TLS_LE:
            value = tpoff(info, value);
            bfd_put_32(input_bfd, value + addend, hit_data);
            return bfd_reloc_ok;
        case R_MN10300_TLS_LD:
            if (dynobj == NULL) {
                return bfd_reloc_dangerous;
            }
            sgot = htab->root.sgot;
            BFD_ASSERT(sgot != NULL);
            value = htab->tls_ldm_got.offset + sgot->output_offset;
            bfd_put_32(input_bfd, value, hit_data);

            if (!htab->tls_ldm_got.rel_emitted) {
                asection *srelgot = htab->root.srelgot;
                Elf_Internal_Rela rel;
                BFD_ASSERT(srelgot != NULL);
                htab->tls_ldm_got.rel_emitted++;

                rel.r_offset = sgot->output_section->vma + sgot->output_offset + htab->tls_ldm_got.offset;
                bfd_put_32(output_bfd, (bfd_vma) 0, sgot->contents + htab->tls_ldm_got.offset);
                bfd_put_32(output_bfd, (bfd_vma) 0, sgot->contents + htab->tls_ldm_got.offset+4);
                rel.r_info = ELF32_R_INFO(0, R_MN10300_TLS_DTPMOD);
                rel.r_addend = 0;
                bfd_elf32_swap_reloca_out(output_bfd, &rel,
                    (bfd_byte *)(((Elf32_External_Rela *) srelgot->contents) + srelgot->reloc_count));
                ++srelgot->reloc_count;
            }
            return bfd_reloc_ok;
        case R_MN10300_TLS_GOTIE:
            value = tpoff(info, value);
            /* Fall Through.  */
        case R_MN10300_TLS_GD:
        case R_MN10300_TLS_IE:
        case R_MN10300_GOT32:
        case R_MN10300_GOT24:
        case R_MN10300_GOT16:
            if (dynobj == NULL) {
                return bfd_reloc_dangerous;
            }

            sgot = htab->root.sgot;
            if (r_type == R_MN10300_TLS_GD) {
                value = dtpoff(info, value);
            }

            if (h != NULL) {
                bfd_vma off;
                off = h->got.offset;
                if (off == (bfd_vma) -1) {
                    off = 0;
                }

                if (sgot->contents != NULL && (!elf_hash_table(info)->dynamic_sections_created || SYMBOL_REFERENCES_LOCAL(info, h))) {
                    bfd_put_32(output_bfd, value, sgot->contents + off);
                }
                value = sgot->output_offset + off;
            } else {
                bfd_vma off = elf_local_got_offsets(input_bfd)[symndx];
                if (off & 1) {
                    bfd_put_32(output_bfd, value, sgot->contents + (off & ~1));
                } else {
                    bfd_put_32(output_bfd, value, sgot->contents + off);
                    if (bfd_link_pic(info)) {
                        asection *srelgot = htab->root.srelgot;
                        Elf_Internal_Rela outrel;
                        BFD_ASSERT(srelgot != NULL);

                        outrel.r_offset = sgot->output_section->vma + sgot->output_offset + off;
                        switch (r_type) {
                            case R_MN10300_TLS_GD:
                                outrel.r_info = ELF32_R_INFO(0, R_MN10300_TLS_DTPOFF);
                                outrel.r_offset = sgot->output_section->vma + sgot->output_offset + off + 4;
                                bfd_elf32_swap_reloca_out(output_bfd, &outrel,
                                    (bfd_byte *)((Elf32_External_Rela *)srelgot->contents + srelgot->reloc_count));
                                ++srelgot->reloc_count;
                                outrel.r_info = ELF32_R_INFO(0, R_MN10300_TLS_DTPMOD);
                                break;
                            case R_MN10300_TLS_GOTIE:
                            case R_MN10300_TLS_IE:
                                outrel.r_info = ELF32_R_INFO(0, R_MN10300_TLS_TPOFF);
                                break;
                            default:
                                outrel.r_info = ELF32_R_INFO(0, R_MN10300_RELATIVE);
                                break;
                        }
                        outrel.r_addend = value;
                        bfd_elf32_swap_reloca_out(output_bfd, &outrel,
                            (bfd_byte *)((Elf32_External_Rela *) srelgot->contents + srelgot->reloc_count));
                        ++srelgot->reloc_count;
                        elf_local_got_offsets(input_bfd)[symndx] |= 1;
                    }
                    value = sgot->output_offset + (off & ~(bfd_vma)1);
                }
            }

            value += addend;

            if (r_type == R_MN10300_TLS_IE) {
                value += sgot->output_section->vma;
                bfd_put_32(input_bfd, value, hit_data);
                return bfd_reloc_ok;
            } else if (r_type == R_MN10300_TLS_GOTIE || r_type == R_MN10300_TLS_GD ||
                       r_type == R_MN10300_TLS_LD || r_type == R_MN10300_GOT32) {
                bfd_put_32(input_bfd, value, hit_data);
                return bfd_reloc_ok;
            } else if (r_type == R_MN10300_GOT24) {
                if ((long)value > 0x7fffff || (long)value < -0x800000) {
                    return bfd_reloc_overflow;
                }
                bfd_put_8(input_bfd, value & 0xff, hit_data);
                bfd_put_8(input_bfd, (value >> 8) & 0xff, hit_data + 1);
                bfd_put_8(input_bfd, (value >> 16) & 0xff, hit_data + 2);
                return bfd_reloc_ok;
            } else if (r_type == R_MN10300_GOT16) {
                if ((long)value > 0x7fff || (long)value < -0x8000) {
                    return bfd_reloc_overflow;
                }
                bfd_put_16(input_bfd, value, hit_data);
                return bfd_reloc_ok;
            }
            /* Fall Through.  */
        default:
            return bfd_reloc_notsupported;
    }
}

/* Relocate an MN10300 ELF section.  */

static int mn10300_elf_relocate_section(bfd *output_bfd, struct bfd_link_info *info, bfd *input_bfd, asection *input_section, bfd_byte *contents, Elf_Internal_Rela *relocs, Elf_Internal_Sym *local_syms, asection **local_sections) {
    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
    struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(input_bfd);
    Elf_Internal_Rela *rel = relocs;
    Elf_Internal_Rela *relend = relocs + input_section->reloc_count;

    for (; rel < relend; rel++) {
        int r_type = ELF32_R_TYPE(rel->r_info);
        unsigned long r_symndx = ELF32_R_SYM(rel->r_info);
        reloc_howto_type *howto = elf_mn10300_howto_table + r_type;
        asection *sec = NULL;
        bfd_vma relocation = 0;
        struct elf32_mn10300_link_hash_entry *h = NULL;
        struct elf_link_hash_entry *hh = NULL;

        if (r_type == R_MN10300_GNU_VTINHERIT || r_type == R_MN10300_GNU_VTENTRY) continue;

        if(r_symndx >= symtab_hdr->sh_info) {
            RELOC_FOR_GLOBAL_SYMBOL(info, input_bfd, input_section, rel, r_symndx, symtab_hdr, sym_hashes, hh, sec, relocation, false, false, false);
        }
        h = elf_mn10300_hash_entry(hh);

        int tls_r_type = elf_mn10300_tls_transition(info, r_type, hh, input_section, 0);
        if (tls_r_type != r_type) {
            bool had_plt = mn10300_do_tls_transition(input_bfd, r_type, tls_r_type, contents, rel->r_offset);
            r_type = tls_r_type;
            howto = elf_mn10300_howto_table + r_type;
            if (had_plt) {
                for (Elf_Internal_Rela *trel = rel + 1; trel < relend; trel++) {
                    if ((ELF32_R_TYPE(trel->r_info) == R_MN10300_PLT32 || ELF32_R_TYPE(trel->r_info) == R_MN10300_PCREL32) &&
                        rel->r_offset + had_plt == trel->r_offset) {
                        trel->r_info = ELF32_R_INFO(0, R_MN10300_NONE);
                    }
                }
            }
        }

        if (r_symndx < symtab_hdr->sh_info) {
            Elf_Internal_Sym *sym = local_syms + r_symndx;
            sec = local_sections[r_symndx];
            relocation = _bfd_elf_rela_local_sym(output_bfd, sym, &sec, rel);
        } else {
            if ((h->root.root.type == bfd_link_hash_defined || h->root.root.type == bfd_link_hash_defweak) &&
                (r_type == R_MN10300_GOTPC32 || r_type == R_MN10300_GOTPC16 ||
                ((r_type == R_MN10300_PLT32 || r_type == R_MN10300_PLT16) &&
                ELF_ST_VISIBILITY(h->root.other) != STV_INTERNAL &&
                ELF_ST_VISIBILITY(h->root.other) != STV_HIDDEN && h->root.plt.offset != (bfd_vma)-1) ||
                ((r_type == R_MN10300_GOT32 || r_type == R_MN10300_GOT24 || r_type == R_MN10300_TLS_GD ||
                r_type == R_MN10300_TLS_LD || r_type == R_MN10300_TLS_GOTIE || r_type == R_MN10300_TLS_IE ||
                r_type == R_MN10300_GOT16) && elf_hash_table(info)->dynamic_sections_created &&
                !SYMBOL_REFERENCES_LOCAL(info, hh)) || (r_type == R_MN10300_32 && !SYMBOL_REFERENCES_LOCAL(info, hh) &&
                ((input_section->flags & SEC_ALLOC) != 0 && !bfd_link_executable(info) || 
                ((input_section->flags & SEC_DEBUGGING) != 0 && h->root.def_dynamic))))) {
                relocation = 0;
            } else if (!bfd_link_relocatable(info) && _bfd_elf_section_offset(output_bfd, info, input_section, rel->r_offset) != (bfd_vma)-1) {
                _bfd_error_handler(_("%pB(%pA+%#" PRIx64 "): unresolvable %s relocation against symbol `%s'"), input_bfd, input_section, (uint64_t)rel->r_offset, howto->name, h->root.root.root.string);
            }
        }

        if (sec != NULL && discarded_section(sec)) {
            RELOC_AGAINST_DISCARDED_SECTION(info, input_bfd, input_section, rel, 1, relend, R_MN10300_NONE, howto, 0, contents);
        }

        if (bfd_link_relocatable(info)) continue;

        bfd_reloc_status_type r = mn10300_elf_final_link_relocate(howto, input_bfd, output_bfd, input_section, contents, rel->r_offset, relocation, rel->r_addend, (struct elf_link_hash_entry *)h, r_symndx, info, sec, h == NULL);

        if (r != bfd_reloc_ok) {
            const char *name;
            const char *msg = NULL;

            if (h != NULL) {
                name = h->root.root.root.string;
            } else {
                name = (bfd_elf_string_from_elf_section(input_bfd, symtab_hdr->sh_link, sym->st_name));
                if (name == NULL || *name == '\0') name = bfd_section_name(sec);
            }

            switch (r) {
                case bfd_reloc_overflow:
                    (*info->callbacks->reloc_overflow)(info, (h ? &h->root.root : NULL), name, howto->name, (bfd_vma)0, input_bfd, input_section, rel->r_offset);
                    break;
                case bfd_reloc_undefined:
                    (*info->callbacks->undefined_symbol)(info, name, input_bfd, input_section, rel->r_offset, true);
                    break;
                case bfd_reloc_outofrange:
                    msg = _("internal error: out of range error");
                    goto common_error;
                case bfd_reloc_notsupported:
                    msg = _("internal error: unsupported relocation error");
                    goto common_error;
                case bfd_reloc_dangerous:
                    if (r_type == R_MN10300_PCREL32)
                        msg = _("error: inappropriate relocation type for shared library (did you forget -fpic?)");
                    else if (r_type == R_MN10300_GOT32)
                        msg = _("%pB: taking the address of protected function '%s' cannot be done when making a shared library");
                    else
                        msg = _("internal error: suspicious relocation type used in shared library");
                    goto common_error;
                default:
                    msg = _("internal error: unknown error");
                    common_error:
                    _bfd_error_handler(msg, input_bfd, name);
                    bfd_set_error(bfd_error_bad_value);
                    return false;
            }
        }
    }
    return true;
}

/* Finish initializing one hash table entry.  */

static bool elf32_mn10300_finish_hash_table_entry(struct bfd_hash_entry *gen_entry, void *in_args) {
    struct elf32_mn10300_link_hash_entry *entry = (struct elf32_mn10300_link_hash_entry *)gen_entry;
    struct bfd_link_info *link_info = (struct bfd_link_info *)in_args;
    unsigned int byte_count = 0;

    if (entry->flags == MN10300_CONVERT_CALL_TO_CALLS) {
        return true;
    }

    bool dynamic_symbol = elf_hash_table(link_info)->dynamic_sections_created
                          && ELF_ST_VISIBILITY(entry->root.other) != STV_INTERNAL
                          && ELF_ST_VISIBILITY(entry->root.other) != STV_HIDDEN;

    if (entry->direct_calls == 0 || (entry->stack_size == 0 && entry->movm_args == 0) || dynamic_symbol) {
        entry->flags |= MN10300_CONVERT_CALL_TO_CALLS;
        return true;
    }

    if (entry->movm_args) {
        byte_count += 2;
    }

    if (entry->stack_size > 0) {
        byte_count += (entry->stack_size <= 128) ? 3 : 4;
    }

    if (byte_count < entry->direct_calls) {
        entry->flags |= MN10300_CONVERT_CALL_TO_CALLS;
    }

    return true;
}

/* Used to count hash table entries.  */

static bool elf32_mn10300_count_hash_table_entries(void *in_args) {
    if (in_args == NULL) return false;
    int *count = (int *)in_args;
    (*count)++;
    return true;
}

/* Used to enumerate hash table entries into a linear array.  */

static bool elf32_mn10300_list_hash_table_entries(struct bfd_hash_entry *gen_entry, void *in_args) {
    if (!gen_entry || !in_args) {
        return false;
    }

    struct bfd_hash_entry ***ptr = (struct bfd_hash_entry ***)in_args;
    if (!ptr || !*ptr) {
        return false;
    }

    **ptr = gen_entry;
    (*ptr)++;
    return true;
}

/* Used to sort the array created by the above.  */

#include <stddef.h>

static int compare_values(const struct elf32_mn10300_link_hash_entry *a, const struct elf32_mn10300_link_hash_entry *b) {
    if (!a || !b) {
        return 0;
    }
    return (a->value > b->value) - (a->value < b->value);
}

static int sort_by_value(const void *va, const void *vb) {
    if (!va || !vb) {
        return 0;
    }
    return compare_values(*(const struct elf32_mn10300_link_hash_entry **)va, *(const struct elf32_mn10300_link_hash_entry **)vb);
}

/* Compute the stack size and movm arguments for the function
   referred to by HASH at address ADDR in section with
   contents CONTENTS, store the information in the hash table.  */

static void compute_function_info(bfd *abfd, struct elf32_mn10300_link_hash_entry *hash, bfd_vma addr, unsigned char *contents) {
    unsigned char byte1 = bfd_get_8(abfd, contents + addr);
    unsigned char byte2 = bfd_get_8(abfd, contents + addr + 1);

    if (byte1 == 0xcf) {
        hash->movm_args = byte2;
        addr += 2;
        byte1 = bfd_get_8(abfd, contents + addr);
        byte2 = bfd_get_8(abfd, contents + addr + 1);
    }

    if (hash->movm_args) {
        if (hash->movm_args & 0x80) hash->movm_stack_size += 4;
        if (hash->movm_args & 0x40) hash->movm_stack_size += 4;
        if (hash->movm_args & 0x20) hash->movm_stack_size += 4;
        if (hash->movm_args & 0x10) hash->movm_stack_size += 4;
        if (hash->movm_args & 0x08) hash->movm_stack_size += 32;

        int mach = bfd_get_mach(abfd);
        if (mach == bfd_mach_am33 || mach == bfd_mach_am33_2) {
            if (hash->movm_args & 0x01) hash->movm_stack_size += 24;
            if (hash->movm_args & 0x02) hash->movm_stack_size += 16;
            if (hash->movm_args & 0x04) hash->movm_stack_size += 8;
        }
    }

    int temp = 0;
    if (byte1 == 0xf8 && byte2 == 0xfe) {
        temp = bfd_get_8(abfd, contents + addr + 2);
        temp = ((temp & 0xff) ^ (~0x7f)) + 0x80;
        hash->stack_size = -temp;
    } else if (byte1 == 0xfa && byte2 == 0xfe) {
        temp = bfd_get_16(abfd, contents + addr + 2);
        temp = ((temp & 0xffff) ^ (~0x7fff)) + 0x8000;
        temp = -temp;
        if (temp < 255) hash->stack_size = temp;
    }

    if (hash->stack_size + hash->movm_stack_size > 255) {
        hash->stack_size = 0;
    }
}

/* Delete some bytes from a section while relaxing.  */

static bool mn10300_elf_relax_delete_bytes(bfd *abfd, asection *sec, bfd_vma addr, int count) {
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
  unsigned int sec_shndx = _bfd_elf_section_from_bfd_section(abfd, sec);
  bfd_byte *contents = elf_section_data(sec)->this_hdr.contents;
  Elf_Internal_Rela *relocs = elf_section_data(sec)->relocs;
  Elf_Internal_Rela *irel = relocs;
  Elf_Internal_Rela *irelend = relocs + sec->reloc_count;
  Elf_Internal_Rela *irelalign = NULL;
  bfd_vma toaddr = sec->size;

  if (sec->reloc_count > 0 && ELF32_R_TYPE((irelend - 1)->r_info) == (int)R_MN10300_ALIGN) {
    --irelend;
  }

  for (; irel < irelend; irel++) {
    if (ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_ALIGN && irel->r_offset > addr && irel->r_offset < toaddr) {
      int alignment = 1 << irel->r_addend;
      if (count < alignment || alignment % count != 0) {
        irelalign = irel;
        toaddr = irel->r_offset;
        break;
      }
    }
  }

  memmove(contents + addr, contents + addr + count, (size_t)(toaddr - addr - count));

  if (irelalign == NULL) {
    sec->size -= count;
  } else {
    for (int i = 0; i < count; i++) {
      bfd_put_8(abfd, (bfd_vma)NOP_OPCODE, contents + toaddr - count + i);
    }
  }

  for (irel = relocs; irel < irelend; irel++) {
    if ((irel->r_offset > addr && irel->r_offset < toaddr) || (ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_ALIGN && irel->r_offset == toaddr)) {
      irel->r_offset -= count;
    }
  }

  Elf_Internal_Sym *isym = (Elf_Internal_Sym *)symtab_hdr->contents;
  Elf_Internal_Sym *isymend = isym + symtab_hdr->sh_info;
  for (; isym < isymend; isym++) {
    if (isym->st_shndx == sec_shndx && isym->st_value > addr && isym->st_value < toaddr) {
      isym->st_value = (isym->st_value < addr + count) ? addr : isym->st_value - count;
    } else if (isym->st_shndx == sec_shndx && ELF_ST_TYPE(isym->st_info) == STT_FUNC && isym->st_value + isym->st_size > addr && isym->st_value + isym->st_size < toaddr) {
      isym->st_size -= count;
    }
  }

  unsigned int symcount = (symtab_hdr->sh_size / sizeof(Elf32_External_Sym) - symtab_hdr->sh_info);
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(abfd);
  struct elf_link_hash_entry **end_hashes = sym_hashes + symcount;
  for (; sym_hashes < end_hashes; sym_hashes++) {
    struct elf_link_hash_entry *sym_hash = *sym_hashes;
    if ((sym_hash->root.type == bfd_link_hash_defined || sym_hash->root.type == bfd_link_hash_defweak) && sym_hash->root.u.def.section == sec && sym_hash->root.u.def.value > addr && sym_hash->root.u.def.value < toaddr) {
      sym_hash->root.u.def.value = (sym_hash->root.u.def.value < addr + count) ? addr : sym_hash->root.u.def.value - count;
    } else if (sym_hash->root.type == bfd_link_hash_defined && sym_hash->root.u.def.section == sec && sym_hash->type == STT_FUNC && sym_hash->root.u.def.value + sym_hash->size > addr && sym_hash->root.u.def.value + sym_hash->size < toaddr) {
      sym_hash->size -= count;
    }
  }

  if (irelalign != NULL && (int)irelalign->r_addend > 0) {
    bfd_vma alignto = BFD_ALIGN(toaddr, 1 << irelalign->r_addend);
    bfd_vma alignaddr = BFD_ALIGN(irelalign->r_offset, 1 << irelalign->r_addend);
    if (alignaddr < alignto) {
      return mn10300_elf_relax_delete_bytes(abfd, sec, alignaddr, (int)(alignto - alignaddr));
    }
  }

  return true;
}

/* Return TRUE if a symbol exists at the given address, else return
   FALSE.  */

static bool mn10300_elf_symbol_address_p(bfd *abfd, asection *sec, Elf_Internal_Sym *isym, bfd_vma addr) {
    unsigned int sec_shndx = _bfd_elf_section_from_bfd_section(abfd, sec);
    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
    Elf_Internal_Sym *isymend = isym + symtab_hdr->sh_info;

    for (; isym < isymend; ++isym) {
        if (isym->st_shndx == sec_shndx && isym->st_value == addr) {
            return true;
        }
    }

    unsigned int symcount = (symtab_hdr->sh_size / sizeof(Elf32_External_Sym)) - symtab_hdr->sh_info;
    struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(abfd);
    struct elf_link_hash_entry **end_hashes = sym_hashes + symcount;

    for (; sym_hashes < end_hashes; ++sym_hashes) {
        struct elf_link_hash_entry *sym_hash = *sym_hashes;

        if ((sym_hash->root.type == bfd_link_hash_defined || sym_hash->root.type == bfd_link_hash_defweak)
            && sym_hash->root.u.def.section == sec && sym_hash->root.u.def.value == addr) {
            return true;
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

static bool mn10300_elf_relax_section(bfd *abfd, asection *sec, struct bfd_link_info *link_info, bool *again) {
    if (bfd_link_relocatable(link_info)) {
        link_info->callbacks->fatal(_("%P: --relax and -r may not be used together\n"));
    }

    *again = false;

    struct elf32_mn10300_link_hash_table *hash_table = elf32_mn10300_hash_table(link_info);
    if (hash_table == NULL) {
        return false;
    }

    if ((hash_table->flags & MN10300_HASH_ENTRIES_INITIALIZED) == 0) {
        for (bfd *input_bfd = link_info->input_bfds; input_bfd != NULL; input_bfd = input_bfd->link.next) {
            Elf_Internal_Shdr *symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
            Elf_Internal_Sym *isymbuf = prepare_symbol_buffer(input_bfd, symtab_hdr);
            if (isymbuf == NULL) {
                goto error_return;
            }

            for (asection *section = input_bfd->sections; section != NULL; section = section->next) {
                if (!should_process_section(section)) {
                    continue;
                }

                bfd_byte *contents = get_section_contents(input_bfd, section);
                if ((section->flags & SEC_RELOC) != 0 && section->reloc_count != 0) {
                    Elf_Internal_Rela *internal_relocs = get_internal_relocs(input_bfd, section, link_info);
                    if (internal_relocs == NULL) {
                        goto error_return;
                    }

                    process_relocations(input_bfd, section, symtab_hdr, isymbuf, link_info, internal_relocs, contents);
                    free_resources(input_bfd, section, contents, internal_relocs, link_info);
                }

                if ((section->flags & SEC_CODE) != 0) {
                    process_section_symbols(input_bfd, section, symtab_hdr, isymbuf, link_info, contents);
                }
            }

            cache_or_free_symbol_buffer(input_bfd, symtab_hdr, isymbuf, link_info);
        }

        hash_table->flags |= MN10300_HASH_ENTRIES_INITIALIZED;
        post_traversal_processing(hash_table, link_info);

        static_count = 0;
        elf32_mn10300_link_hash_traverse(hash_table->static_hash_table, elf32_mn10300_count_hash_table_entries, &static_count);

        process_static_entries(static_count, hash_table);

        for (bfd *input_bfd = link_info->input_bfds; input_bfd != NULL; input_bfd = input_bfd->link.next) {
            Elf_Internal_Shdr *symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
            Elf_Internal_Sym *isymbuf = prepare_symbol_buffer(input_bfd, symtab_hdr);
            if (isymbuf == NULL) {
                goto error_return;
            }

            for (asection *section = input_bfd->sections; section != NULL; section = section->next) {
                if (!should_process_code_section(section)) {
                    continue;
                }

                bfd_byte *contents = get_section_contents(input_bfd, section);
                if (section->reloc_count != 0) {
                    Elf_Internal_Rela *internal_relocs = get_internal_relocs(input_bfd, section, link_info);
                    if (internal_relocs == NULL) {
                        goto error_return;
                    }

                    process_prologue_deletion(input_bfd, section, symtab_hdr, isymbuf, link_info, contents, internal_relocs);
                    free_resources(input_bfd, section, contents, internal_relocs, link_info);
                }
            }

            cache_or_free_symbol_buffer(input_bfd, symtab_hdr, isymbuf, link_info);
        }
    }

    contents = NULL;
    internal_relocs = NULL;
    isymbuf = NULL;

    if (bfd_link_relocatable(link_info) || (sec->flags & SEC_RELOC) == 0 || sec->reloc_count == 0 || (sec->flags & SEC_CODE) == 0) {
        return true;
    }

    Elf_Internal_Shdr *symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
    internal_relocs = get_internal_relocs(abfd, sec, link_info);
    if (internal_relocs == NULL) {
        goto error_return;
    }

    bfd_vma align_gap_adjustment = calculate_alignment_gap(internal_relocs, sec);
    Elf_Internal_Rela *irelend = internal_relocs + sec->reloc_count;

    for (Elf_Internal_Rela *irel = internal_relocs; irel < irelend; irel++) {
        process_irel(axfd, sec, symtab_hdr, &contents, &isymbuf, irel, align_gap_adjustment, hash_table);
    }

    finalize_resources(isymbuf, symtab_hdr, contents, internal_relocs, sec, link_info);
    return true;

error_return:
    free_resources_on_error(isymbuf, symtab_hdr, contents, internal_relocs, sec);
    return false;
}

static Elf_Internal_Sym *prepare_symbol_buffer(bfd *input_bfd, Elf_Internal_Shdr *symtab_hdr) {
    if (symtab_hdr->sh_info != 0) {
        Elf_Internal_Sym *isymbuf = (Elf_Internal_Sym *)symtab_hdr->contents;
        if (isymbuf == NULL) {
            isymbuf = bfd_elf_get_elf_syms(input_bfd, symtab_hdr, symtab_hdr->sh_info, 0, NULL, NULL, NULL);
        }
        return isymbuf;
    }
    return NULL;
}

static bool should_process_section(asection *section) {
    return (section->flags & SEC_RELOC) != 0 && section->reloc_count != 0 &&
           (section->flags & SEC_ALLOC) != 0 && (section->flags & SEC_HAS_CONTENTS) != 0;
}

static bfd_byte *get_section_contents(bfd *input_bfd, asection *section) {
    if (elf_section_data(section)->this_hdr.contents != NULL) {
        return elf_section_data(section)->this_hdr.contents;
    } else if (section->size != 0) {
        if (bfd_malloc_and_get_section(input_bfd, section, &contents)) {
            return contents;
        }
    }
    return NULL;
}

static Elf_Internal_Rela *get_internal_relocs(bfd *input_bfd, asection *section, struct bfd_link_info *link_info) {
    return _bfd_elf_link_read_relocs(input_bfd, section, NULL, NULL, link_info->keep_memory);
}

static void process_relocations(bfd *input_bfd, asection *section, Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym *isymbuf, struct bfd_link_info *link_info, Elf_Internal_Rela *internal_relocs, bfd_byte *contents) {
    Elf_Internal_Rela *irelend = internal_relocs + section->reloc_count;
    for (Elf_Internal_Rela *irel = internal_relocs; irel < irelend; irel++) {
        process_individual_relocation(input_bfd, section, symtab_hdr, isymbuf, link_info, irel, contents);
    }
}

static void process_individual_relocation(bfd *input_bfd, asection *section, Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym *isymbuf, struct bfd_link_info *link_info, Elf_Internal_Rela *reloc, bfd_byte *contents) {
    long r_type = ELF32_R_TYPE(reloc->r_info);
    unsigned long r_index = ELF32_R_SYM(reloc->r_info);

    if (r_type < 0 || r_type >= (int)R_MN10300_MAX) {
        return;
    }

    struct elf32_mn10300_link_hash_entry *hash = NULL;
    asection *sym_sec = NULL;
    const char *sym_name = NULL;

    if (r_index < symtab_hdr->sh_info) {
        Elf_Internal_Sym *isym = isymbuf + r_index;
        sym_sec = get_symbol_section(input_bfd, isym);
        sym_name = bfd_elf_string_from_elf_section(input_bfd, symtab_hdr->sh_link, isym->st_name);

        if (ELF_ST_TYPE(isym->st_info) != STT_FUNC) {
            return;
        }

        char *new_name = generate_unique_symbol_name(input_bfd, sym_sec, sym_name);
        if (new_name == NULL) {
            return;
        }

        sym_name = new_name;
        hash = lookup_hash_table_entry(&hash_table->static_hash_table->root, sym_name, true);
        free(new_name);
    } else {
        r_index -= symtab_hdr->sh_info;
        hash = (struct elf32_mn10300_link_hash_entry *)elf_sym_hashes(input_bfd)[r_index];
        sym_name = hash->root.root.root.string;
    }

    if ((section->flags & SEC_CODE) != 0 && should_convert_call_to_calls(input_bfd, hash, reloc, contents)) {
        hash->flags |= MN10300_CONVERT_CALL_TO_CALLS;
    }

    if (is_jump_or_call_reloc(r_type, reloc)) {
        hash->direct_calls++;
    } else {
        hash->flags |= MN10300_CONVERT_CALL_TO_CALLS;
    }
}

static asection *get_symbol_section(bfd *input_bfd, Elf_Internal_Sym *isym) {
    if (isym->st_shndx == SHN_UNDEF) {
        return bfd_und_section_ptr;
    } else if (isym->st_shndx == SHN_ABS) {
        return bfd_abs_section_ptr;
    } else if (isym->st_shndx == SHN_COMMON) {
        return bfd_com_section_ptr;
    } else {
        return bfd_section_from_elf_index(input_bfd, isym->st_shndx);
    }
}

static char *generate_unique_symbol_name(bfd *input_bfd, asection *sym_sec, const char *sym_name) {
    size_t amt = strlen(sym_name) + 10;
    char *new_name = bfd_malloc(amt);
    if (new_name == NULL) {
        return NULL;
    }
    sprintf(new_name, "%s_%08x", sym_name, sym_sec->id);
    return new_name;
}

static struct elf32_mn10300_link_hash_entry *lookup_hash_table_entry(struct elf_link_hash_table **table, const char *name, bool create) {
    return (struct elf32_mn10300_link_hash_entry *)elf_link_hash_lookup(*table, name, true, create, false);
}

static bool should_convert_call_to_calls(bfd *input_bfd, struct elf32_mn10300_link_hash_entry *hash, Elf_Internal_Rela *reloc, bfd_byte *contents) {
    if (!hash) {
        return false;
    }

    unsigned char code = bfd_get_8(input_bfd, contents + reloc->r_offset - 1);
    return code != 0xdd && code != 0xcd;
}

static bool is_jump_or_call_reloc(long r_type, Elf_Internal_Rela *reloc) {
    return r_type == R_MN10300_PCREL32 || r_type == R_MN10300_PLT32 ||
           r_type == R_MN10300_PLT16 || r_type == R_MN10300_PCREL16;
}

static void free_resources(bfd *input_bfd, asection *section, bfd_byte *contents, Elf_Internal_Rela *internal_relocs, struct bfd_link_info *link_info) {
    if (elf_section_data(section)->relocs != internal_relocs) {
        free(internal_relocs);
    }

    if (contents != NULL && elf_section_data(section)->this_hdr.contents != contents) {
        if (!link_info->keep_memory) {
            free(contents);
        } else {
            elf_section_data(section)->this_hdr.contents = contents;
        }
    }
}

static void cache_or_free_symbol_buffer(bfd *input_bfd, Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym *isymbuf, struct bfd_link_info *link_info) {
    if (isymbuf != NULL && symtab_hdr->contents != (unsigned char *)isymbuf) {
        if (!link_info->keep_memory) {
            free(isymbuf);
        } else {
            symtab_hdr->contents = (unsigned char *)isymbuf;
        }
    }
}

static void post_traversal_processing(struct elf32_mn10300_link_hash_table *hash_table, struct bfd_link_info *link_info) {
    elf32_mn10300_link_hash_traverse(hash_table, elf32_mn10300_finish_hash_table_entry, link_info);
    elf32_mn10300_link_hash_traverse(hash_table->static_hash_table, elf32_mn10300_finish_hash_table_entry, link_info);
}

static void process_static_entries(int static_count, struct elf32_mn10300_link_hash_table *hash_table) {
    struct elf32_mn10300_link_hash_entry **entries = bfd_malloc(static_count * sizeof(*entries));
    if (entries == NULL) {
        return;
    }

    struct elf32_mn10300_link_hash_entry **ptr = entries;
    elf32_mn10300_link_hash_traverse(hash_table->static_hash_table, elf32_mn10300_list_hash_table_entries, &ptr);

    qsort(entries, static_count, sizeof(entries[0]), sort_by_value);

    for (int i = 0; i < static_count - 1; i++) {
        if (entries[i]->value && entries[i]->value == entries[i + 1]->value) {
            int merged_flags = merge_flags(static_count, entries, i);
            update_flags(static_count, entries, i, merged_flags);
            i = static_count - 1;
        }
    }

    free(entries);
}

static int merge_flags(int static_count, struct elf32_mn10300_link_hash_entry **entries, int start_index) {
    int merged_flags = entries[start_index]->flags;
    for (int j = start_index + 1; j < static_count && entries[j]->value == entries[start_index]->value; j++) {
        merged_flags |= entries[j]->flags;
    }
    return merged_flags;
}

static void update_flags(int static_count, struct elf32_mn10300_link_hash_entry **entries, int start_index, int merged_flags) {
    for (int j = start_index; j < static_count && entries[j]->value == entries[start_index]->value; j++) {
        entries[j]->flags = merged_flags;
    }
}

static bool should_process_code_section(asection *section) {
    return (section->flags & SEC_CODE) != 0 && (section->flags & SEC_HAS_CONTENTS) != 0 && section->size != 0;
}

static void process_prologue_deletion(bfd *input_bfd, asection *section, Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym *isymbuf, struct bfd_link_info *link_info, bfd_byte *contents, Elf_Internal_Rela *internal_relocs) {
    unsigned int sec_shndx = _bfd_elf_section_from_bfd_section(input_bfd, section);
    unsigned int symcount = (symtab_hdr->sh_size / sizeof(Elf32_External_Sym) - symtab_hdr->sh_info);
    struct elf_link_hash_entry **hashes = elf_sym_hashes(input_bfd);
    struct elf_link_hash_entry **end_hashes = hashes + symcount;

    process_local_symbols_for_prologue_deletion(input_bfd, section, symtab_hdr, isymbuf, link_info, contents, internal_relocs, hashes, end_hashes, sec_shndx);
    process_global_symbols_for_prologue_deletion(input_bfd, section, symtab_hdr, isymbuf, link_info, contents, internal_relocs, hashes, end_hashes);
}

static void process_local_symbols_for_prologue_deletion(bfd *input_bfd, asection *section, Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym *isymbuf, struct bfd_link_info *link_info, bfd_byte *contents, Elf_Internal_Rela *internal_relocs, struct elf_link_hash_entry **hashes, struct elf_link_hash_entry **end_hashes, unsigned int sec_shndx) {
    Elf_Internal_Sym *isymend = isymbuf + symtab_hdr->sh_info;
    for (Elf_Internal_Sym *isym = isymbuf; isym < isymend; isym++) {
        process_local_symbol_for_prologue_deletion(input_bfd, section, symtab_hdr, isym, contents, internal_relocs, hashes, end_hashes, sec_shndx);
    }
}

static void process_local_symbol_for_prologue_deletion(bfd *input_bfd, asection *section, Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym *isym, bfd_byte *contents, Elf_Internal_Rela *internal_relocs, struct elf_link_hash_entry **hashes, struct elf_link_hash_entry **end_hashes, unsigned int sec_shndx) {
    struct elf32_mn10300_link_hash_entry *sym_hash;
    asection *sym_sec = NULL;
    const char *sym_name;
    char *new_name;
    struct elf_link_hash_table *elftab;
    size_t amt;

    if (isym->st_shndx != sec_shndx || ELF_ST_TYPE(isym->st_info) != STT_FUNC) {
        return;
    }

    sym_sec = get_local_symbol_section(input_bfd, isym);
    sym_name = bfd_elf_string_from_elf_section(input_bfd, symtab_hdr->sh_link, isym->st_name);

    new_name = generate_unique_symbol_name(input_bfd, sym_sec, sym_name);
    if (new_name == NULL) {
        return;
    }

    elftab = &hash_table->static_hash_table->root;
    sym_hash = (struct elf32_mn10300_link_hash_entry *)elf_link_hash_lookup(elftab, sym_name, false, false, false);
    free(new_name);

    if (sym_hash == NULL) {
        return;
    }

    if (!(sym_hash->flags & MN10300_CONVERT_CALL_TO_CALLS) && !(sym_hash->flags & MN10300_DELETED_PROLOGUE_BYTES)) {
        int bytes = calculate_bytes_to_delete(sym_hash);

        mark_changes(input_bfd, section, symtab_hdr, contents, internal_relocs);

        sym_hash->flags |= MN10300_DELETED_PROLOGUE_BYTES;

        if (!mn10300_elf_relax_delete_bytes(input_bfd, section, isym->st_value, bytes)) {
            return;
        }
        *again = true;
    }
}

static asection *get_local_symbol_section(bfd *input_bfd, Elf_Internal_Sym *isym) {
    if (isym->st_shndx == SHN_UNDEF) {
        return bfd_und_section_ptr;
    } else if (isym->st_shndx == SHN_ABS) {
        return bfd_abs_section_ptr;
    } else if (isym->st_shndx == SHN_COMMON) {
        return bfd_com_section_ptr;
    } else {
        return bfd_section_from_elf_index(input_bfd, isym->st_shndx);
    }
}

static int calculate_bytes_to_delete(struct elf32_mn10300_link_hash_entry *sym_hash) {
    int bytes = 0;
    if (sym_hash->movm_args) {
        bytes += 2;
    }
    if (sym_hash->stack_size > 0) {
        bytes += sym_hash->stack_size <= 128 ? 3 : 4;
    }
    return bytes;
}

static void mark_changes(bfd *input_bfd, asection *section, Elf_Internal_Shdr *symtab_hdr, bfd_byte *contents, Elf_Internal_Rela *internal_relocs) {
    elf_section_data(section)->relocs = internal_relocs;
    elf_section_data(section)->this_hdr.contents = contents;
    symtab_hdr->contents = (unsigned char *)isymbuf;
}

static void process_global_symbols_for_prologue_deletion(bfd *input_bfd, asection *section, Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym *isymbuf, struct bfd_link_info *link_info, bfd_byte *contents, Elf_Internal_Rela *internal_relocs, struct elf_link_hash_entry **hashes, struct elf_link_hash_entry **end_hashes) {
    unsigned int symcount = (symtab_hdr->sh_size / sizeof(Elf32_External_Sym) - symtab_hdr->sh_info);
    for (struct elf_link_hash_entry **hash_ptr = hashes; hash_ptr < end_hashes; hash_ptr++) {
        process_global_symbol_for_prologue_deletion(input_bfd, section, symtab_hdr, isymbuf, link_info, contents, internal_relocs, hash_ptr, end_hashes);
    }
}

static void process_global_symbol_for_prologue_deletion(bfd *input_bfd, asection *section, Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym *isymbuf, struct bfd_link_info *link_info, bfd_byte *contents, Elf_Internal_Rela *internal_relocs, struct elf_link_hash_entry **hash_ptr, struct elf_link_hash_entry **end_hashes) {
    struct elf32_mn10300_link_hash_entry *sym_hash = (struct elf32_mn10300_link_hash_entry *) *hash_ptr;

    if ((sym_hash->root.root.type == bfd_link_hash_defined || sym_hash->root.root.type == bfd_link_hash_defweak) &&
        sym_hash->root.root.u.def.section == section &&
        !(sym_hash->flags & MN10300_CONVERT_CALL_TO_CALLS) &&
        !(sym_hash->flags & MN10300_DELETED_PROLOGUE_BYTES)) {

        int bytes = calculate_bytes_to_delete(sym_hash);
        bfd_vma symval = sym_hash->root.root.u.def.value;

        mark_changes(input_bfd, section, symtab_hdr, contents, internal_relocs);

        sym_hash->flags |= MN10300_DELETED_PROLOGUE_BYTES;

        if (!mn10300_elf_relax_delete_bytes(input_bfd, section, symval, bytes)) {
            return;
        }

        mark_cpp_functions_prologue_deleted(end_hashes, symval, sym_hash);

        *again = true;
    }
}

static void mark_cpp_functions_prologue_deleted(struct elf_link_hash_entry **end_hashes, bfd_vma symval, struct elf32_mn10300_link_hash_entry *sym_hash) {
    for (struct elf_link_hash_entry **hash_ptr = elf_sym_hashes(input_bfd); hash_ptr < end_hashes; hash_ptr++) {
        struct elf32_mn10300_link_hash_entry *h = (struct elf32_mn10300_link_hash_entry *) *hash_ptr;

        if (h != sym_hash &&
            (h->root.root.type == bfd_link_hash_defined || h->root.root.type == bfd_link_hash_defweak) &&
            h->root.root.u.def.section == section &&
            !(h->flags & MN10300_CONVERT_CALL_TO_CALLS) &&
            h->root.root.u.def.value == symval &&
            h->root.type == STT_FUNC) {

            h->flags |= MN10300_DELETED_PROLOGUE_BYTES;
        }
    }
}

static bfd_vma calculate_alignment_gap(Elf_Internal_Rela *internal_relocs, asection *sec) {
    bfd_vma align_gap_adjustment = 0;
    Elf_Internal_Rela *irelend = internal_relocs + sec->reloc_count;
    for (Elf_Internal_Rela *irel = internal_relocs; irel < irelend; irel++) {
        if (ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_ALIGN) {
            bfd_vma adj = 1 << irel->r_addend;
            bfd_vma aend = irel->r_offset;
            aend = BFD_ALIGN(aend, 1 << irel->r_addend);
            adj = 2 * adj - adj - 1;
            if (align_gap_adjustment < adj &&
                aend < sec->output_section->vma + sec->output_offset + sec->size) {

                align_gap_adjustment = adj;
            }
        }
    }
    return align_gap_adjustment;
}

static void process_irel(bfd *axfd, asection *sec, Elf_Internal_Shdr *symtab_hdr, bfd_byte **contents, Elf_Internal_Sym **isymbuf, Elf_Internal_Rela *irel, bfd_vma align_gap_adjustment, struct elf32_mn10300_link_hash_table *hash_table) {
    if (ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_NONE ||
        ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_8 ||
        ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_MAX) {
        return;
    }

    if (*contents == NULL) {
        if (elf_section_data(sec)->this_hdr.contents != NULL) {
            *contents = elf_section_data(sec)->this_hdr.contents;
        } else {
            if (!bfd_malloc_and_get_section(axfd, sec, contents)) {
                return;
            }
        }
    }

    if (*isymbuf == NULL && symtab_hdr->sh_info != 0) {
        *isymbuf = (Elf_Internal_Sym *)symtab_hdr->contents;
        if (*isymbuf == NULL) {
            *isymbuf = bfd_elf_get_elf_syms(axfd, symtab_hdr, symtab_hdr->sh_info, 0, NULL, NULL, NULL);
        }
        if (*isymbuf == NULL) {
            return;
        }
    }

    process_relocation_with_alignment(axfd, sec, symtab_hdr, *contents, *isymbuf, irel, align_gap_adjustment, hash_table);
}

static void process_relocation_with_alignment(bfd *axfd, asection *sec, Elf_Internal_Shdr *symtab_hdr, bfd_byte *contents, Elf_Internal_Sym *isymbuf, Elf_Internal_Rela *irel, bfd_vma align_gap_adjustment, struct elf32_mn10300_link_hash_table *hash_table) {
    bfd_vma symval = 0;
    asection *sym_sec = NULL;
    struct elf32_mn10300_link_hash_entry *h = NULL;

    if (ELF32_R_SYM(irel->r_info) < symtab_hdr->sh_info) {
        Elf_Internal_Sym *isym = isymbuf + ELF32_R_SYM(irel->r_info);
        sym_sec = get_local_symbol_section(axfd, isym);
        const char *sym_name = bfd_elf_string_from_elf_section(axfd, symtab_hdr->sh_link, isym->st_name);

        if ((sym_sec->flags & SEC_MERGE) && sym_sec->sec_info_type == SEC_INFO_TYPE_MERGE) {
            symval = handle_merge_section_relocations(axfd, sym_sec, irel, isym);
        } else {
            symval = handle_standard_relocations(axfd, sym_sec, irel, isym);
        }

        char *new_name = generate_unique_symbol_name(axfd, sym_sec, sym_name);
        if (new_name == NULL) {
            return;
        }

        h = lookup_hash_table_entry(&hash_table->static_hash_table->root, new_name, false);
        free(new_name);
    } else {
        unsigned long indx = ELF32_R_SYM(irel->r_info) - symtab_hdr->sh_info;
        h = (struct elf32_mn10300_link_hash_entry *)(elf_sym_hashes(axfd)[indx]);

        if (h->root.root.type == bfd_link_hash_defined || h->root.root.type == bfd_link_hash_defweak) {
            sym_sec = h->root.root.u.def.section->output_section;
        }

        symval = (h->root.root.u.def.value + h->root.root.u.def.section->output_section->vma + h->root.root.u.def.section->output_offset);
    }

    relax_instruction(axfd, sec, symtab_hdr, contents, isymbuf, irel, align_gap_adjustment, symval, sym_sec, h);
}

static bfd_vma handle_merge_section_relocations(bfd *axfd, asection *sym_sec, Elf_Internal_Rela *irel, Elf_Internal_Sym *isym) {
    bfd_vma symval = isym->st_value;

    if (ELF_ST_TYPE(isym->st_info) == STT_SECTION) {
        symval += irel->r_addend;
    }

    symval = _bfd_merged_section_offset(axfd, &sym_sec, elf_section_data(sym_sec)->sec_info, symval);

    if (ELF_ST_TYPE(isym->st_info) != STT_SECTION) {
        symval += irel->r_addend;
    }

    return (symval + sym_sec->output_section->vma + sym_sec->output_offset - irel->r_addend);
}

static bfd_vma handle_standard_relocations(bfd *axfd, asection *sym_sec, Elf_Internal_Rela *irel, Elf_Internal_Sym *isym) {
    return (isym->st_value + sym_sec->output_section->vma + sym_sec->output_offset);
}

static void relax_instruction(bfd *axfd, asection *sec, Elf_Internal_Shdr *symtab_hdr, bfd_byte *contents, Elf_Internal_Sym *isymbuf, Elf_Internal_Rela *irel, bfd_vma align_gap_adjustment, bfd_vma symval, asection *sym_sec, struct elf32_mn10300_link_hash_entry *h) {
    if (ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_PCREL32 || ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_PLT32) {
        relax_pcrel32_to_16(axfd, sec, symtab_hdr, contents, isymbuf, irel, align_gap_adjustment, symval, sym_sec, h);
    }

    if (ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_PCREL16) {
        relax_pcrel16_to_8(axfd, sec, symtab_hdr, contents, isymbuf, irel, symval, h);
    }

    if (ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_PCREL8) {
        reduce_branch_instruction(axfd, sec, symtab_hdr, contents, isymbuf, irel);
    }

    if (ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_24) {
        relax_24_to_8(axfd, sec, symtab_hdr, contents, isymbuf, irel, symval);
    }

    if (ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_32 || ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_GOT32 || ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_GOTOFF32) {
        relax_32_to_16(axfd, sec, symtab_hdr, contents, isymbuf, irel, symval, h);
    }
}

static void relax_pcrel32_to_16(bfd *axfd, asection *sec, Elf_Internal_Shdr *symtab_hdr, bfd_byte *contents, Elf_Internal_Sym *isymbuf, Elf_Internal_Rela *irel, bfd_vma align_gap_adjustment, bfd_vma symval, asection *sym_sec, struct elf32_mn10300_link_hash_entry *h) {
    bfd_vma value = calculate_value_for_relaxation(symval, sec, irel);
    value += addend_correction_for_plts(axfd, h, sym_sec, sec, irel, hash_table);
    bfd_signed_vma jump_offset = determine_jump_offset(sec, sym_sec);
    if (in_relaxation_range(value, jump_offset, align_gap_adjustment)) {
        modify_instruction_for_relaxation(axfd, sec, symtab_hdr, contents, isymbuf, irel);
        *again = true;
    }
}

static void relax_pcrel16_to_8(bfd *axfd, asection *sec, Elf_Internal_Shdr *symtab_hdr, bfd_byte *contents, Elf_Internal_Sym *isymbuf, Elf_Internal_Rela *irel, bfd_vma symval, struct elf32_mn10300_link_hash_entry *h) {
    bfd_vma value = calculate_value_for_relaxation(symval, sec, irel);
    if (within_eight_bit_range(value)) {
        modify_instruction_for_relaxation(axfd, sec, symtab_hdr, contents, isymbuf, irel);
        *again = true;
    }
}

static void reduce_branch_instruction(bfd *axfd, asection *sec, Elf_Internal_Shdr *symtab_hdr, bfd_byte *contents, Elf_Internal_Sym *isymbuf, Elf_Internal_Rela *irel) {
    Elf_Internal_Rela *nrel;
    if (!is_last_byte_in_section(irel, sec)) {
        return;
    }

    unsigned char code = bfd_get_8(axfd, contents + irel->r_offset + 1);
    if (code != 0xca) {
        return;
    }

    nrel = irel + 1;
    if (!is_next_instruction_reducible(irel, sec, nrel)) {
        return;
    }

    if (!is_destination_reducible(symval, sec, irel)) {
        return;
    }

    if (!is_branch_reduction_compatible(axfd, sec, isymbuf, irel)) {
        return;
    }

    modify_relocation_info_for_branch(axfd, sec, symtab_hdr, contents, isymbuf, irel, nrel);
    *again = true;
}

static void relax_24_to_8(bfd *axfd, asection *sec, Elf_Internal_Shdr *symtab_hdr, bfd_byte *contents, Elf_Internal_Sym *isymbuf, Elf_Internal_Rela *irel, bfd_vma symval) {
    bfd_vma value = symval + irel->r_addend;
    if (within_eight_bit_range(value)) {
        unsigned char code = bfd_get_8(axfd, contents + irel->r_offset - 3);
        if (is_valid_am33_instruction(code)) {
            code = bfd_get_8(axfd, contents + irel->r_offset - 2);
            if (is_am33_instruction_relaxable(code)) {
                if ((value & 0x80) == 0) {
                    modify_am33_instruction(axfd, sec, symtab_hdr, contents, isymbuf, irel);
                    *again = true;
                }
            }
        }
    }
}

static void relax_32_to_16(bfd *axfd, asection *sec, Elf_Internal_Shdr *symtab_hdr, bfd_byte *contents, Elf_Internal_Sym *isymbuf, Elf_Internal_Rela *irel, bfd_vma symval, struct elf32_mn10300_link_hash_entry *h) {
    bfd_vma value = complete_offsets_for_32(axfd, irel, symval, h);
    value += irel->r_addend;

    if (can_reduce_to_24_bits(value)) {
        unsigned char code = bfd_get_8(axfd, contents + irel->r_offset - 3);
        if (is_valid_am33_instruction(code)) {
            code = bfd_get_8(axfd, contents + irel->r_offset - 2);

            if (is_am33_instruction_relaxable_within_24(code, irel)) {
                if ((value & 0x8000) == 0) {
                    modify_am33_instruction(axfd, sec, symtab_hdr, contents, isymbuf, irel);
                    *again = true;
                }
            }
        }
    }

    if (can_reduce_to_16_bits(value, irel)) {
        process_am33_reduction_16(axfd, sec, symtab_hdr, contents, isymbuf, irel, value);
        *again = true;
    }
}

/* This is a version of bfd_generic_get_relocated_section_contents
   which uses mn10300_elf_relocate_section.  */

static bfd_byte *
mn10300_elf_get_relocated_section_contents(bfd *output_bfd,
                                           struct bfd_link_info *link_info,
                                           struct bfd_link_order *link_order,
                                           bfd_byte *data,
                                           bool relocatable,
                                           asymbol **symbols)
{
    Elf_Internal_Shdr *symtab_hdr;
    asection *input_section = link_order->u.indirect.section;
    bfd *input_bfd = input_section->owner;
    bfd_byte *orig_data = data;
    
    if (relocatable || elf_section_data(input_section)->this_hdr.contents == NULL) {
        return bfd_generic_get_relocated_section_contents(output_bfd, link_info, link_order, data, relocatable, symbols);
    }

    if ((data == NULL && (data = bfd_malloc(input_section->size)) == NULL) || 
        (symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr) == NULL) {
        return NULL;
    }

    memcpy(data, elf_section_data(input_section)->this_hdr.contents, (size_t)input_section->size);
    
    if ((input_section->flags & SEC_RELOC) != 0 && input_section->reloc_count > 0) {
        Elf_Internal_Rela *internal_relocs = _bfd_elf_link_read_relocs(input_bfd, input_section, NULL, NULL, false);
        Elf_Internal_Sym *isymbuf = NULL;
        asection **sections = NULL;
        
        if (internal_relocs == NULL ||
            (symtab_hdr->sh_info != 0 && (isymbuf = (Elf_Internal_Sym *)symtab_hdr->contents) == NULL &&
                (isymbuf = bfd_elf_get_elf_syms(input_bfd, symtab_hdr, symtab_hdr->sh_info, 0, NULL, NULL, NULL)) == NULL) ||
            ((sections = bfd_malloc(symtab_hdr->sh_info * sizeof(asection *))) == NULL && symtab_hdr->sh_info != 0)) {
            goto cleanup_and_exit;
        }

        for (Elf_Internal_Sym *isym = isymbuf, *isymend = isymbuf + symtab_hdr->sh_info;
             isym < isymend; ++isym, ++sections) {
            *sections = (isym->st_shndx == SHN_UNDEF) ? bfd_und_section_ptr :
                        (isym->st_shndx == SHN_ABS) ? bfd_abs_section_ptr :
                        (isym->st_shndx == SHN_COMMON) ? bfd_com_section_ptr :
                        bfd_section_from_elf_index(input_bfd, isym->st_shndx);
        }

        if (!mn10300_elf_relocate_section(output_bfd, link_info, input_bfd, input_section, data, internal_relocs, isymbuf, sections)) {
            goto cleanup_and_exit;
        }

        free(sections);
        if (symtab_hdr->contents != (unsigned char *)isymbuf) free(isymbuf);
        if (internal_relocs != elf_section_data(input_section)->relocs) free(internal_relocs);
    }

    return data;

cleanup_and_exit:
    free(sections);
    if (symtab_hdr->contents != (unsigned char *)isymbuf) free(isymbuf);
    if (internal_relocs != elf_section_data(input_section)->relocs) free(internal_relocs);
    if (orig_data == NULL) free(data);
    return NULL;
}

/* Assorted hash table functions.  */

/* Initialize an entry in the link hash table.  */

/* Create an entry in an MN10300 ELF linker hash table.  */

static struct bfd_hash_entry *elf32_mn10300_link_hash_newfunc(struct bfd_hash_entry *entry, struct bfd_hash_table *table, const char *string) {
    struct elf32_mn10300_link_hash_entry *ret = (struct elf32_mn10300_link_hash_entry *)entry;
    
    if (ret == NULL) {
        ret = (struct elf32_mn10300_link_hash_entry *)bfd_hash_allocate(table, sizeof(*ret));
        if (ret == NULL) {
            return NULL;
        }
    }

    ret = (struct elf32_mn10300_link_hash_entry *)_bfd_elf_link_hash_newfunc((struct bfd_hash_entry *)ret, table, string);
    if (ret == NULL) {
        return NULL;
    }

    ret->direct_calls = 0;
    ret->stack_size = 0;
    ret->movm_args = 0;
    ret->movm_stack_size = 0;
    ret->flags = 0;
    ret->value = 0;
    ret->tls_type = GOT_UNKNOWN;

    return (struct bfd_hash_entry *)ret;
}

static void
_bfd_mn10300_copy_indirect_symbol(struct bfd_link_info *info,
                                  struct elf_link_hash_entry *dir,
                                  struct elf_link_hash_entry *ind)
{
    struct elf32_mn10300_link_hash_entry *edir = elf_mn10300_hash_entry(dir);
    struct elf32_mn10300_link_hash_entry *eind = elf_mn10300_hash_entry(ind);

    if (ind->root.type == bfd_link_hash_indirect && dir->got.refcount <= 0)
    {
        edir->tls_type = eind->tls_type;
        eind->tls_type = GOT_UNKNOWN;
    }

    edir->direct_calls = eind->direct_calls;
    edir->stack_size = eind->stack_size;
    edir->movm_args = eind->movm_args;
    edir->movm_stack_size = eind->movm_stack_size;
    edir->flags = eind->flags;

    _bfd_elf_link_hash_copy_indirect(info, dir, ind);
}

/* Destroy an mn10300 ELF linker hash table.  */

static void
elf32_mn10300_link_hash_table_free (bfd *obfd)
{
  if (obfd && obfd->link.hash)
  {
    struct elf32_mn10300_link_hash_table *hash_table = (struct elf32_mn10300_link_hash_table *) obfd->link.hash;

    if (hash_table && hash_table->static_hash_table)
    {
      obfd->link.hash = &hash_table->static_hash_table->root.root;
      _bfd_elf_link_hash_table_free (obfd);

      obfd->is_linker_output = true;
      obfd->link.hash = &hash_table->root.root;
      _bfd_elf_link_hash_table_free (obfd);
    }
  }
}

/* Create an mn10300 ELF linker hash table.  */

static struct bfd_link_hash_table *elf32_mn10300_link_hash_table_create(bfd *abfd) {
    struct elf32_mn10300_link_hash_table *ret = bfd_zmalloc(sizeof(*ret));
    if (!ret)
        return NULL;

    ret->static_hash_table = bfd_zmalloc(sizeof(struct elf_link_hash_table));
    if (!ret->static_hash_table) {
        free(ret);
        return NULL;
    }

    if (!_bfd_elf_link_hash_table_init(&ret->static_hash_table->root, abfd, elf32_mn10300_link_hash_newfunc, sizeof(struct elf32_mn10300_link_hash_entry))) {
        free(ret->static_hash_table);
        free(ret);
        return NULL;
    }

    abfd->is_linker_output = false;
    abfd->link.hash = NULL;
    if (!_bfd_elf_link_hash_table_init(&ret->root, abfd, elf32_mn10300_link_hash_newfunc, sizeof(struct elf32_mn10300_link_hash_entry))) {
        abfd->is_linker_output = true;
        abfd->link.hash = &ret->static_hash_table->root.root;
        _bfd_elf_link_hash_table_free(abfd);
        free(ret);
        return NULL;
    }

    ret->root.root.hash_table_free = elf32_mn10300_link_hash_table_free;
    ret->tls_ldm_got.offset = -1;

    return &ret->root.root;
}

static unsigned long elf_mn10300_mach(flagword flags) {
    unsigned long result;
    switch (flags & EF_MN10300_MACH) {
        case E_MN10300_MACH_AM33:
            result = bfd_mach_am33;
            break;
        case E_MN10300_MACH_AM33_2:
            result = bfd_mach_am33_2;
            break;
        case E_MN10300_MACH_MN10300:
        default:
            result = bfd_mach_mn10300;
            break;
    }
    return result;
}

/* The final processing done just before writing out a MN10300 ELF object
   file.  This gets the MN10300 architecture right based on the machine
   number.  */

static bool _bfd_mn10300_elf_final_write_processing(bfd *abfd) {
    unsigned long val;
    int machine_type = bfd_get_mach(abfd);

    if (machine_type == bfd_mach_am33_2) {
        val = E_MN10300_MACH_AM33_2;
    } else if (machine_type == bfd_mach_am33) {
        val = E_MN10300_MACH_AM33;
    } else {
        val = E_MN10300_MACH_MN10300;
    }

    bfd_elf_elfheader(abfd)->e_flags = (bfd_elf_elfheader(abfd)->e_flags & ~EF_MN10300_MACH) | val;
    return _bfd_elf_final_write_processing(abfd);
}

bool bfd_mn10300_elf_object_p(bfd *abfd) {
    if (!bfd_default_set_arch_mach(abfd, bfd_arch_mn10300, elf_mn10300_mach(elf_elfheader(abfd)->e_flags))) {
        return false;
    }
    return true;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

bool _bfd_mn10300_elf_merge_private_bfd_data(bfd *ibfd, struct bfd_link_info *info) {
    bfd *obfd = info->output_bfd;

    if (bfd_get_flavour(ibfd) != bfd_target_elf_flavour || bfd_get_flavour(obfd) != bfd_target_elf_flavour) {
        return true;
    }

    if (bfd_get_arch(obfd) == bfd_get_arch(ibfd) && bfd_get_mach(obfd) < bfd_get_mach(ibfd)) {
        return bfd_set_arch_mach(obfd, bfd_get_arch(ibfd), bfd_get_mach(ibfd));
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

static bool _bfd_mn10300_elf_create_dynamic_sections(bfd *abfd, struct bfd_link_info *info) {
    flagword flags;
    asection *s;
    const struct elf_backend_data *bed = get_elf_backend_data(abfd);
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
    int ptralign;

    switch (bed->s->arch_size) {
        case 32:
            ptralign = 2;
            break;
        case 64:
            ptralign = 3;
            break;
        default:
            bfd_set_error(bfd_error_bad_value);
            return false;
    }

    flags = SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY | SEC_LINKER_CREATED;
    s = bfd_make_section_anyway_with_flags(abfd, (bed->default_use_rela_p ? ".rela.plt" : ".rel.plt"), flags | SEC_READONLY);
    htab->root.srelplt = s;
    if (!s || !bfd_set_section_alignment(s, ptralign)) return false;

    if (!_bfd_mn10300_elf_create_got_section(abfd, info)) return false;

    if (bed->want_dynbss) {
        s = bfd_make_section_anyway_with_flags(abfd, ".dynbss", SEC_ALLOC | SEC_LINKER_CREATED);
        if (!s) return false;

        if (!bfd_link_pic(info)) {
            s = bfd_make_section_anyway_with_flags(abfd, (bed->default_use_rela_p ? ".rela.bss" : ".rel.bss"), flags | SEC_READONLY);
            if (!s || !bfd_set_section_alignment(s, ptralign)) return false;
        }
    }

    return true;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

#include <stdbool.h>

static bool _bfd_mn10300_elf_adjust_dynamic_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *h) {
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
    bfd *dynobj = htab->root.dynobj;
    asection *s;

    if (dynobj == NULL || !(h->needs_plt || h->is_weakalias || (h->def_dynamic && h->ref_regular && !h->def_regular))) {
        return false;
    }

    if (h->type == STT_FUNC || h->needs_plt) {
        if (!bfd_link_pic(info) && !h->def_dynamic && !h->ref_dynamic) {
            return h->needs_plt;
        }

        if (h->dynindx == -1) {
            if (!bfd_elf_link_record_dynamic_symbol(info, h)) {
                return false;
            }
        }

        s = htab->root.splt;
        if (s == NULL) return false;

        if (s->size == 0) s->size += elf_mn10300_sizeof_plt0(info);

        if (!bfd_link_pic(info) && !h->def_regular) {
            h->root.u.def.section = s;
            h->root.u.def.value = s->size;
        }

        h->plt.offset = s->size;
        s->size += elf_mn10300_sizeof_plt(info);

        s = htab->root.sgotplt;
        if (s == NULL) return false;
        s->size += 4;

        s = htab->root.srelplt;
        if (s == NULL) return false;
        s->size += sizeof(Elf32_External_Rela);

        return true;
    }

    if (h->is_weakalias) {
        struct elf_link_hash_entry *def = weakdef(h);
        if (def->root.type != bfd_link_hash_defined) return false;
        h->root.u.def.section = def->root.u.def.section;
        h->root.u.def.value = def->root.u.def.value;
        return true;
    }

    if (bfd_link_pic(info) || !h->non_got_ref) {
        return true;
    }

    s = bfd_get_linker_section(dynobj, ".dynbss");
    if (s == NULL) return false;

    if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0) {
        asection *srel = bfd_get_linker_section(dynobj, ".rela.bss");
        if (srel == NULL) return false;
        srel->size += sizeof(Elf32_External_Rela);
        h->needs_copy = 1;
    }

    return _bfd_elf_adjust_dynamic_copy(info, h, s);
}

/* Set the sizes of the dynamic sections.  */

static bool _bfd_mn10300_elf_late_size_sections(bfd *output_bfd, struct bfd_link_info *info) {
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
    bfd *dynobj = htab->root.dynobj;
    asection *s;
    bool needs_relocs = false;

    if (dynobj == NULL) return true;

    if (elf_hash_table(info)->dynamic_sections_created) {
        if (bfd_link_executable(info) && !info->nointerp) {
            s = bfd_get_linker_section(dynobj, ".interp");
            BFD_ASSERT(s != NULL);
            s->size = sizeof ELF_DYNAMIC_INTERPRETER;
            s->contents = (unsigned char *)ELF_DYNAMIC_INTERPRETER;
            s->alloced = 1;
        }
    } else {
        s = htab->root.sgot;
        if (s != NULL) s->size = 0;
    }

    if (htab->tls_ldm_got.refcount > 0) {
        s = htab->root.srelgot;
        BFD_ASSERT(s != NULL);
        s->size += sizeof(Elf32_External_Rela);
    }

    for (s = dynobj->sections; s != NULL; s = s->next) {
        const char *name = bfd_section_name(s);

        if ((s->flags & SEC_LINKER_CREATED) == 0 || s->size == 0) {
            if (s->size == 0) s->flags |= SEC_EXCLUDE;
            continue;
        }

        if (startswith(name, ".rela") && !streq(name, ".rela.plt")) needs_relocs = true;

        if ((s->flags & SEC_HAS_CONTENTS) != 0) {
            s->contents = bfd_zalloc(dynobj, s->size);
            if (s->contents == NULL) return false;
            s->alloced = 1;
        }
    }

    return _bfd_elf_add_dynamic_tags(output_bfd, info, needs_relocs);
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool _bfd_mn10300_elf_finish_dynamic_symbol(bfd *output_bfd, struct bfd_link_info *info, struct elf_link_hash_entry *h, Elf_Internal_Sym *sym) {
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
    bfd *dynobj = htab->root.dynobj;

    if (h->plt.offset != (bfd_vma)-1) {
        asection *splt = htab->root.splt;
        asection *sgot = htab->root.sgotplt;
        asection *srel = htab->root.srelplt;
        bfd_vma plt_index = (h->plt.offset - elf_mn10300_sizeof_plt0(info)) / elf_mn10300_sizeof_plt(info);
        bfd_vma got_offset = (plt_index + 3) * 4;
        Elf_Internal_Rela rel;

        if (!bfd_link_pic(info)) {
            memcpy(splt->contents + h->plt.offset, elf_mn10300_plt_entry, elf_mn10300_sizeof_plt(info));
            bfd_put_32(output_bfd, sgot->output_section->vma + sgot->output_offset + got_offset, splt->contents + h->plt.offset + elf_mn10300_plt_symbol_offset(info));
            bfd_put_32(output_bfd, 1 - h->plt.offset - elf_mn10300_plt_plt0_offset(info), splt->contents + h->plt.offset + elf_mn10300_plt_plt0_offset(info));
        } else {
            memcpy(splt->contents + h->plt.offset, elf_mn10300_pic_plt_entry, elf_mn10300_sizeof_plt(info));
            bfd_put_32(output_bfd, got_offset, splt->contents + h->plt.offset + elf_mn10300_plt_symbol_offset(info));
        }

        bfd_put_32(output_bfd, plt_index * sizeof(Elf32_External_Rela), splt->contents + h->plt.offset + elf_mn10300_plt_reloc_offset(info));
        bfd_put_32(output_bfd, splt->output_section->vma + splt->output_offset + h->plt.offset + elf_mn10300_plt_temp_offset(info), sgot->contents + got_offset);

        rel.r_offset = sgot->output_section->vma + sgot->output_offset + got_offset;
        rel.r_info = ELF32_R_INFO(h->dynindx, R_MN10300_JMP_SLOT);
        rel.r_addend = 0;
        bfd_elf32_swap_reloca_out(output_bfd, &rel, (bfd_byte *)((Elf32_External_Rela *)srel->contents + plt_index));

        if (!h->def_regular) sym->st_shndx = SHN_UNDEF;
    }

    if (h->got.offset != (bfd_vma)-1) {
        asection *sgot = htab->root.sgot;
        asection *srel = htab->root.srelgot;
        Elf_Internal_Rela rel;
        rel.r_offset = sgot->output_section->vma + sgot->output_offset + (h->got.offset & ~1);

        switch (elf_mn10300_hash_entry(h)->tls_type) {
            case GOT_TLS_GD:
                bfd_put_32(output_bfd, 0, sgot->contents + h->got.offset);
                bfd_put_32(output_bfd, 0, sgot->contents + h->got.offset + 4);
                rel.r_info = ELF32_R_INFO(h->dynindx, R_MN10300_TLS_DTPMOD);
                rel.r_addend = 0;
                bfd_elf32_swap_reloca_out(output_bfd, &rel, (bfd_byte *)((Elf32_External_Rela *)srel->contents + srel->reloc_count++));
                rel.r_info = ELF32_R_INFO(h->dynindx, R_MN10300_TLS_DTPOFF);
                rel.r_offset += 4;
                rel.r_addend = 0;
                break;
            case GOT_TLS_IE:
                rel.r_addend = bfd_get_32(output_bfd, sgot->contents + h->got.offset);
                bfd_put_32(output_bfd, 0, sgot->contents + h->got.offset);
                rel.r_info = ELF32_R_INFO(h->dynindx == -1 ? 0 : h->dynindx, R_MN10300_TLS_TPOFF);
                break;
            default:
                if (bfd_link_pic(info) && (info->symbolic || h->dynindx == -1) && h->def_regular) {
                    rel.r_info = ELF32_R_INFO(0, R_MN10300_RELATIVE);
                    rel.r_addend = h->root.u.def.value + h->root.u.def.section->output_section->vma + h->root.u.def.section->output_offset;
                } else {
                    bfd_put_32(output_bfd, 0, sgot->contents + h->got.offset);
                    rel.r_info = ELF32_R_INFO(h->dynindx, R_MN10300_GLOB_DAT);
                    rel.r_addend = 0;
                }
                break;
        }

        if (ELF32_R_TYPE(rel.r_info) != R_MN10300_NONE) {
            bfd_elf32_swap_reloca_out(output_bfd, &rel, (bfd_byte *)((Elf32_External_Rela *)srel->contents + srel->reloc_count++));
        }
    }

    if (h->needs_copy) {
        asection *s = bfd_get_linker_section(dynobj, ".rela.bss");
        Elf_Internal_Rela rel;
        rel.r_offset = h->root.u.def.value + h->root.u.def.section->output_section->vma + h->root.u.def.section->output_offset;
        rel.r_info = ELF32_R_INFO(h->dynindx, R_MN10300_COPY);
        rel.r_addend = 0;
        bfd_elf32_swap_reloca_out(output_bfd, &rel, (bfd_byte *)((Elf32_External_Rela *)s->contents + s->reloc_count++));
    }

    if (h == elf_hash_table(info)->hdynamic || h == elf_hash_table(info)->hgot) {
        sym->st_shndx = SHN_ABS;
    }

    return true;
}

/* Finish up the dynamic sections.  */

static bool _bfd_mn10300_elf_finish_dynamic_sections(bfd *output_bfd, struct bfd_link_info *info) {
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);

    if (!htab || !htab->root.sgotplt) {
        return false;
    }

    bfd *dynobj = htab->root.dynobj;
    asection *sgot = htab->root.sgotplt;
    asection *sdyn = bfd_get_linker_section(dynobj, ".dynamic");

    if (elf_hash_table(info)->dynamic_sections_created && sdyn) {
        Elf32_External_Dyn *dyncon = (Elf32_External_Dyn *)sdyn->contents;
        Elf32_External_Dyn *dynconend = (Elf32_External_Dyn *)(sdyn->contents + sdyn->size);

        while (dyncon < dynconend) {
            Elf_Internal_Dyn dyn;
            bfd_elf32_swap_dyn_in(dynobj, dyncon, &dyn);
            asection *s = NULL;

            switch (dyn.d_tag) {
                case DT_PLTGOT:
                    s = htab->root.sgot;
                    break;
                case DT_JMPREL:
                    s = htab->root.srelplt;
                    break;
                case DT_PLTRELSZ:
                    s = htab->root.srelplt;
                    dyn.d_un.d_val = s->size;
                    break;
                default:
                    dyncon++;
                    continue;
            }

            if (s) {
                dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
                bfd_elf32_swap_dyn_out(output_bfd, &dyn, dyncon);
            }

            dyncon++;
        }

        asection *splt = htab->root.splt;
        if (splt && splt->size > 0) {
            if (bfd_link_pic(info)) {
                memcpy(splt->contents, elf_mn10300_pic_plt_entry, elf_mn10300_sizeof_plt(info));
            } else {
                memcpy(splt->contents, elf_mn10300_plt0_entry, PLT0_ENTRY_SIZE);
                bfd_put_32(output_bfd, sgot->output_section->vma + sgot->output_offset + 4, splt->contents + elf_mn10300_plt0_gotid_offset(info));
                bfd_put_32(output_bfd, sgot->output_section->vma + sgot->output_offset + 8, splt->contents + elf_mn10300_plt0_linker_offset(info));
            }
            elf_section_data(splt->output_section)->this_hdr.sh_entsize = 1;
        }
    }

    if (sgot->size > 0) {
        bfd_put_32(output_bfd, sdyn ? sdyn->output_section->vma + sdyn->output_offset : 0, sgot->contents);
        bfd_put_32(output_bfd, 0, sgot->contents + 4);
        bfd_put_32(output_bfd, 0, sgot->contents + 8);
    }

    elf_section_data(sgot->output_section)->this_hdr.sh_entsize = 4;

    return true;
}

/* Classify relocation types, such that combreloc can sort them
   properly.  */

static enum elf_reloc_type_class _bfd_mn10300_elf_reloc_type_class(const struct bfd_link_info *info, const asection *rel_sec, const Elf_Internal_Rela *rela) {
    switch (ELF32_R_TYPE(rela->r_info)) {
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

bool mn10300_elf_mkobject(bfd *abfd) {
    if (abfd == NULL) {
        return false;
    }
    return bfd_elf_allocate_object(abfd, sizeof(struct elf_mn10300_obj_tdata));
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
