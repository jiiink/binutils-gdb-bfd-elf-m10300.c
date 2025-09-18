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

static int get_ptr_alignment(const struct elf_backend_data *bed)
{
  switch (bed->s->arch_size)
    {
    case 32:
      return 2;
    case 64:
      return 3;
    default:
      bfd_set_error (bfd_error_bad_value);
      return -1;
    }
}

static flagword get_plt_flags(const struct elf_backend_data *bed, flagword base_flags)
{
  flagword pltflags = base_flags | SEC_CODE;
  
  if (bed->plt_not_loaded)
    pltflags &= ~ (SEC_LOAD | SEC_HAS_CONTENTS);
  if (bed->plt_readonly)
    pltflags |= SEC_READONLY;
    
  return pltflags;
}

static bool create_section_and_align(bfd *abfd, const char *name, flagword flags, 
                                     int alignment, asection **section_ptr)
{
  asection *s = bfd_make_section_anyway_with_flags (abfd, name, flags);
  *section_ptr = s;
  return s != NULL && bfd_set_section_alignment (s, alignment);
}

static bool create_plt_section(bfd *abfd, struct bfd_link_info *info,
                               const struct elf_backend_data *bed,
                               struct elf_link_hash_table *htab)
{
  flagword base_flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY
                         | SEC_LINKER_CREATED);
  flagword pltflags = get_plt_flags(bed, base_flags);
  
  if (!create_section_and_align(abfd, ".plt", pltflags, 
                                bed->plt_alignment, &htab->splt))
    return false;
    
  if (bed->want_plt_sym)
    {
      htab->hplt = _bfd_elf_define_linkage_sym (abfd, info, htab->splt,
                                                "_PROCEDURE_LINKAGE_TABLE_");
      if (htab->hplt == NULL)
        return false;
    }
    
  return true;
}

static bool create_got_sections(bfd *abfd, struct bfd_link_info *info,
                                const struct elf_backend_data *bed,
                                struct elf_link_hash_table *htab,
                                int ptralign)
{
  flagword flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY
                   | SEC_LINKER_CREATED);
  
  if (!create_section_and_align(abfd, ".got", flags, ptralign, &htab->sgot))
    return false;
    
  if (bed->want_got_plt)
    {
      if (!create_section_and_align(abfd, ".got.plt", flags, 
                                    ptralign, &htab->sgotplt))
        return false;
    }
    
  asection *got_section = htab->sgotplt ? htab->sgotplt : htab->sgot;
  htab->hgot = _bfd_elf_define_linkage_sym (abfd, info, got_section,
                                            "_GLOBAL_OFFSET_TABLE_");
  if (htab->hgot == NULL)
    return false;
    
  got_section->size += bed->got_header_size;
  return true;
}

static bool
_bfd_mn10300_elf_create_got_section (bfd * abfd,
                                     struct bfd_link_info * info)
{
  const struct elf_backend_data * bed = get_elf_backend_data (abfd);
  struct elf_link_hash_table *htab = elf_hash_table (info);

  if (htab->sgot != NULL)
    return true;

  int ptralign = get_ptr_alignment(bed);
  if (ptralign < 0)
    return false;

  if (!create_plt_section(abfd, info, bed, htab))
    return false;
    
  return create_got_sections(abfd, info, bed, htab, ptralign);
}

static reloc_howto_type *
bfd_elf32_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 bfd_reloc_code_real_type code)
{
  unsigned int i;

  for (i = 0; i < ARRAY_SIZE (mn10300_reloc_map); i++)
    {
      if (mn10300_reloc_map[i].bfd_reloc_val == code)
        return &elf_mn10300_howto_table[mn10300_reloc_map[i].elf_reloc_val];
    }

  return NULL;
}

static reloc_howto_type *
find_howto_by_name(const char *r_name)
{
  unsigned int i;

  for (i = ARRAY_SIZE (elf_mn10300_howto_table); i--;)
    {
      if (elf_mn10300_howto_table[i].name == NULL)
        continue;
      
      if (strcasecmp (elf_mn10300_howto_table[i].name, r_name) == 0)
        return elf_mn10300_howto_table + i;
    }

  return NULL;
}

static reloc_howto_type *
bfd_elf32_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 const char *r_name)
{
  return find_howto_by_name(r_name);
}

/* Set the howto pointer for an MN10300 ELF reloc.  */

static bool
mn10300_info_to_howto (bfd *abfd,
		       arelent *cache_ptr,
		       Elf_Internal_Rela *dst)
{
  unsigned int r_type;

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

static bool
should_use_gotie_for_tls_gd(int r_type, struct elf_link_hash_entry *h)
{
    return r_type == R_MN10300_TLS_GD
           && h != NULL
           && elf_mn10300_hash_entry(h)->tls_type == GOT_TLS_IE;
}

static bool
should_keep_original_reloc(struct bfd_link_info *info, asection *sec)
{
    return bfd_link_pic(info) || !(sec->flags & SEC_CODE);
}

static bool
is_symbol_local(struct bfd_link_info *info,
                struct elf_link_hash_entry *h,
                bool counting)
{
    if (!counting && h != NULL && !elf_hash_table(info)->dynamic_sections_created)
        return true;
    return SYMBOL_CALLS_LOCAL(info, h);
}

static int
get_tls_gd_transition(bool is_local)
{
    return is_local ? R_MN10300_TLS_LE : R_MN10300_TLS_GOTIE;
}

static int
get_tls_ie_transition(int r_type, bool is_local)
{
    return is_local ? R_MN10300_TLS_LE : r_type;
}

static int
apply_tls_transition(int r_type, bool is_local)
{
    switch (r_type)
    {
    case R_MN10300_TLS_GD:
        return get_tls_gd_transition(is_local);
    case R_MN10300_TLS_LD:
        return R_MN10300_NONE;
    case R_MN10300_TLS_LDO:
        return R_MN10300_TLS_LE;
    case R_MN10300_TLS_IE:
    case R_MN10300_TLS_GOTIE:
        return get_tls_ie_transition(r_type, is_local);
    }
    return r_type;
}

static int
elf_mn10300_tls_transition(struct bfd_link_info *info,
                           int r_type,
                           struct elf_link_hash_entry *h,
                           asection *sec,
                           bool counting)
{
    if (should_use_gotie_for_tls_gd(r_type, h))
        return R_MN10300_TLS_GOTIE;

    if (should_keep_original_reloc(info, sec))
        return r_type;

    bool is_local = is_symbol_local(info, h, counting);
    return apply_tls_transition(r_type, is_local);
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma
dtpoff (struct bfd_link_info * info, bfd_vma address)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);

  if (htab->tls_sec == NULL)
    return 0;
  return address - htab->tls_sec->vma;
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma
tpoff (struct bfd_link_info * info, bfd_vma address)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);

  if (htab->tls_sec == NULL)
    return 0;
  return address - (htab->tls_size + htab->tls_sec->vma);
}

/* Returns nonzero if there's a R_MN10300_PLT32 reloc that we now need
   to skip, after this one.  The actual value is the offset between
   this reloc and the PLT reloc.  */

#define TLS_PAIR(r1,r2) ((r1) * R_MN10300_MAX + (r2))
#define MOV_IMM_D0_OPCODE 0xFC
#define MOV_IMM_D0_OPCODE2 0xCC
#define ADD_AN_D0_OPCODE 0xF1
#define CALL_OPCODE 0xDD
#define GOTREG_MASK 0x0c
#define GOTREG_SHIFT 2
#define DN_MASK_A4 0xFC
#define DN_VALUE_A4 0xA4
#define AN_MASK_F0 0xF0
#define AN_VALUE_00 0x00
#define OPCODE_FE 0xFE
#define OPCODE_FC 0xFC
#define OPCODE_08 0x08

static void validate_gd_ld_transition(bfd *input_bfd, bfd_byte *op)
{
    BFD_ASSERT (bfd_get_8 (input_bfd, op) == MOV_IMM_D0_OPCODE);
    BFD_ASSERT (bfd_get_8 (input_bfd, op + 1) == MOV_IMM_D0_OPCODE2);
    BFD_ASSERT (bfd_get_8 (input_bfd, op + 6) == ADD_AN_D0_OPCODE);
    BFD_ASSERT (bfd_get_8 (input_bfd, op + 8) == CALL_OPCODE);
}

static int extract_gotreg(bfd *input_bfd, bfd_byte *op)
{
    return (bfd_get_8 (input_bfd, op + 7) & GOTREG_MASK) >> GOTREG_SHIFT;
}

static void apply_gd_gotie_transition(bfd_byte *op, int gotreg)
{
    memcpy (op, "\xFC\x20\x00\x00\x00\x00", 6);
    op[1] |= gotreg;
    memcpy (op+6, "\xF9\x78\x28", 3);
    memcpy (op+9, "\xFC\xE4\x00\x00\x00\x00", 6);
}

static void apply_gd_le_transition(bfd_byte *op)
{
    memcpy (op, "\xFC\xDC\x00\x00\x00\x00", 6);
    memcpy (op+6, "\xF9\x78\x28", 3);
    memcpy (op+9, "\xFC\xE4\x00\x00\x00\x00", 6);
}

static void apply_ld_none_transition(bfd_byte *op)
{
    memcpy (op, "\xF5\x88", 2);
    memcpy (op+2, "\xFC\xE4\x00\x00\x00\x00", 6);
    memcpy (op+8, "\xFE\x19\x22\x00\x00\x00\x00", 7);
}

static void handle_ie_le_fc_transition(bfd_byte *op)
{
    if ((op[1] & DN_MASK_A4) == DN_VALUE_A4)
    {
        op[1] &= 0x03;
        op[1] |= 0xCC;
    }
    else
    {
        op[1] &= 0x03;
        op[1] |= 0xDC;
    }
}

static void handle_gotie_le_fc_transition(bfd_byte *op)
{
    if ((op[1] & AN_MASK_F0) == AN_VALUE_00)
    {
        op[1] &= 0x0C;
        op[1] >>= 2;
        op[1] |= 0xCC;
    }
    else
    {
        op[1] &= 0x0C;
        op[1] >>= 2;
        op[1] |= 0xDC;
    }
}

static void handle_ie_le_transition(bfd_byte *op)
{
    if (op[-2] == OPCODE_FC)
    {
        op -= 2;
        handle_ie_le_fc_transition(op);
    }
    else if (op[-3] == OPCODE_FE)
    {
        op[-2] = OPCODE_08;
    }
    else
    {
        abort ();
    }
}

static void handle_gotie_le_transition(bfd_byte *op)
{
    if (op[-2] == OPCODE_FC)
    {
        op -= 2;
        handle_gotie_le_fc_transition(op);
    }
    else if (op[-3] == OPCODE_FE)
    {
        op[-2] = OPCODE_08;
    }
    else
    {
        abort ();
    }
}

static int
mn10300_do_tls_transition (bfd *	 input_bfd,
			   unsigned int	 r_type,
			   unsigned int	 tls_r_type,
			   bfd_byte *	 contents,
			   bfd_vma	 offset)
{
  bfd_byte *op = contents + offset;
  int gotreg = 0;

  if (r_type == R_MN10300_TLS_GD || r_type == R_MN10300_TLS_LD)
    {
      op -= 2;
      validate_gd_ld_transition(input_bfd, op);
      gotreg = extract_gotreg(input_bfd, op);
    }

  switch (TLS_PAIR (r_type, tls_r_type))
    {
    case TLS_PAIR (R_MN10300_TLS_GD, R_MN10300_TLS_GOTIE):
      apply_gd_gotie_transition(op, gotreg);
      return 7;

    case TLS_PAIR (R_MN10300_TLS_GD, R_MN10300_TLS_LE):
      apply_gd_le_transition(op);
      return 7;

    case TLS_PAIR (R_MN10300_TLS_LD, R_MN10300_NONE):
      apply_ld_none_transition(op);
      return 7;

    case TLS_PAIR (R_MN10300_TLS_LDO, R_MN10300_TLS_LE):
      return 0;

    case TLS_PAIR (R_MN10300_TLS_IE, R_MN10300_TLS_LE):
      handle_ie_le_transition(op);
      break;

    case TLS_PAIR (R_MN10300_TLS_GOTIE, R_MN10300_TLS_LE):
      handle_gotie_le_transition(op);
      break;

    default:
      _bfd_error_handler
	(_("%pB: unsupported transition from %s to %s"),
	 input_bfd,
	 elf_mn10300_howto_table[r_type].name,
	 elf_mn10300_howto_table[tls_r_type].name);
      break;
    }
#undef TLS_PAIR
  return 0;
}

/* Look through the relocs for a section during the first phase.
   Since we don't do .gots or .plts, we just need to consider the
   virtual table relocs for gc.  */

static bool
mn10300_elf_check_relocs (bfd *abfd,
			  struct bfd_link_info *info,
			  asection *sec,
			  const Elf_Internal_Rela *relocs)
{
  struct elf32_mn10300_link_hash_table * htab = elf32_mn10300_hash_table (info);
  bool sym_diff_reloc_seen;
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Sym * isymbuf = NULL;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  bfd *      dynobj;
  bfd_vma *  local_got_offsets;
  asection * sgot;
  asection * srelgot;
  asection * sreloc;
  bool result = false;

  sgot    = NULL;
  srelgot = NULL;
  sreloc  = NULL;

  if (bfd_link_relocatable (info))
    return true;

  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
  sym_hashes = elf_sym_hashes (abfd);

  dynobj = elf_hash_table (info)->dynobj;
  local_got_offsets = elf_local_got_offsets (abfd);
  rel_end = relocs + sec->reloc_count;
  sym_diff_reloc_seen = false;

  for (rel = relocs; rel < rel_end; rel++)
    {
      struct elf_link_hash_entry *h;
      unsigned long r_symndx;
      unsigned int r_type;
      int tls_type = GOT_NORMAL;

      r_symndx = ELF32_R_SYM (rel->r_info);
      h = get_hash_entry(sym_hashes, r_symndx, symtab_hdr);

      r_type = ELF32_R_TYPE (rel->r_info);
      r_type = elf_mn10300_tls_transition (info, r_type, h, sec, true);

      if (dynobj == NULL && requires_got_table(r_type))
	{
	  elf_hash_table (info)->dynobj = dynobj = abfd;
	  if (! _bfd_mn10300_elf_create_got_section (dynobj, info))
	    goto fail;
	}

      if (!process_relocation_type(abfd, info, sec, rel, h, r_symndx, r_type, 
                                   &tls_type, &sym_diff_reloc_seen, htab,
                                   &sgot, &srelgot, &sreloc, dynobj,
                                   &local_got_offsets, symtab_hdr, &isymbuf))
        goto fail;

      if (ELF32_R_TYPE (rel->r_info) != R_MN10300_SYM_DIFF)
	sym_diff_reloc_seen = false;
    }

  result = true;
 fail:
  if (symtab_hdr->contents != (unsigned char *) isymbuf)
    free (isymbuf);

  return result;
}

static struct elf_link_hash_entry *
get_hash_entry(struct elf_link_hash_entry **sym_hashes, 
               unsigned long r_symndx,
               Elf_Internal_Shdr *symtab_hdr)
{
  struct elf_link_hash_entry *h;
  
  if (r_symndx < symtab_hdr->sh_info)
    return NULL;
    
  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
  while (h->root.type == bfd_link_hash_indirect || 
         h->root.type == bfd_link_hash_warning)
    h = (struct elf_link_hash_entry *) h->root.u.i.link;
    
  return h;
}

static bool
requires_got_table(unsigned int r_type)
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
process_relocation_type(bfd *abfd, struct bfd_link_info *info, asection *sec,
                        const Elf_Internal_Rela *rel, struct elf_link_hash_entry *h,
                        unsigned long r_symndx, unsigned int r_type, int *tls_type,
                        bool *sym_diff_reloc_seen, struct elf32_mn10300_link_hash_table *htab,
                        asection **sgot, asection **srelgot, asection **sreloc,
                        bfd *dynobj, bfd_vma **local_got_offsets,
                        Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym **isymbuf)
{
  switch (r_type)
    {
    case R_MN10300_GNU_VTINHERIT:
      return bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset);

    case R_MN10300_GNU_VTENTRY:
      return bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend);

    case R_MN10300_TLS_LD:
      return process_tls_ld(htab, tls_type, sgot, srelgot);

    case R_MN10300_TLS_IE:
    case R_MN10300_TLS_GOTIE:
      if (bfd_link_pic (info))
        info->flags |= DF_STATIC_TLS;
      /* Fall through */

    case R_MN10300_TLS_GD:
    case R_MN10300_GOT32:
    case R_MN10300_GOT24:
    case R_MN10300_GOT16:
      return process_got_entry(abfd, info, h, r_symndx, r_type, tls_type,
                              htab, sgot, srelgot, local_got_offsets,
                              symtab_hdr);

    case R_MN10300_PLT32:
    case R_MN10300_PLT16:
      return process_plt_entry(h);

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
      *sym_diff_reloc_seen = true;
      break;

    case R_MN10300_32:
      if (h != NULL)
        h->non_got_ref = 1;
      return process_shared_relocs(abfd, info, sec, h, r_symndx,
                                   *sym_diff_reloc_seen, sreloc, dynobj,
                                   symtab_hdr, isymbuf);
    }
  return true;
}

static bool
process_tls_ld(struct elf32_mn10300_link_hash_table *htab, int *tls_type,
               asection **sgot, asection **srelgot)
{
  htab->tls_ldm_got.refcount++;
  *tls_type = GOT_TLS_LD;

  if (htab->tls_ldm_got.got_allocated)
    return true;

  *sgot = htab->root.sgot;
  *srelgot = htab->root.srelgot;
  BFD_ASSERT (*sgot != NULL && *srelgot != NULL);

  htab->tls_ldm_got.offset = (*sgot)->size;
  htab->tls_ldm_got.got_allocated++;
  (*sgot)->size += 8;
  return true;
}

static bool
process_got_entry(bfd *abfd, struct bfd_link_info *info, struct elf_link_hash_entry *h,
                 unsigned long r_symndx, unsigned int r_type, int *tls_type,
                 struct elf32_mn10300_link_hash_table *htab, asection **sgot,
                 asection **srelgot, bfd_vma **local_got_offsets,
                 Elf_Internal_Shdr *symtab_hdr)
{
  set_tls_type(r_type, tls_type);

  *sgot = htab->root.sgot;
  *srelgot = htab->root.srelgot;
  BFD_ASSERT (*sgot != NULL && *srelgot != NULL);

  if (r_type == R_MN10300_TLS_LD)
    {
      htab->tls_ldm_got.offset = (*sgot)->size;
      htab->tls_ldm_got.got_allocated++;
    }
  else if (h != NULL)
    {
      if (!process_global_got_entry(abfd, info, h, *tls_type, *sgot, *srelgot, r_type))
        return false;
    }
  else
    {
      if (!process_local_got_entry(abfd, info, r_symndx, *tls_type, *sgot, *srelgot,
                                   local_got_offsets, symtab_hdr, r_type))
        return false;
    }

  (*sgot)->size += 4;
  if (r_type == R_MN10300_TLS_GD || r_type == R_MN10300_TLS_LD)
    (*sgot)->size += 4;

  return true;
}

static void
set_tls_type(unsigned int r_type, int *tls_type)
{
  switch (r_type)
    {
    case R_MN10300_TLS_IE:
    case R_MN10300_TLS_GOTIE:
      *tls_type = GOT_TLS_IE;
      break;
    case R_MN10300_TLS_GD:
      *tls_type = GOT_TLS_GD;
      break;
    default:
      *tls_type = GOT_NORMAL;
      break;
    }
}

static bool
process_global_got_entry(bfd *abfd, struct bfd_link_info *info,
                        struct elf_link_hash_entry *h, int tls_type,
                        asection *sgot, asection *srelgot, unsigned int r_type)
{
  validate_and_update_tls_type(abfd, h, &tls_type);
  elf_mn10300_hash_entry (h)->tls_type = tls_type;

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

static void
validate_and_update_tls_type(bfd *abfd, struct elf_link_hash_entry *h, int *tls_type)
{
  if (elf_mn10300_hash_entry (h)->tls_type == *tls_type ||
      elf_mn10300_hash_entry (h)->tls_type == GOT_UNKNOWN)
    return;

  if (*tls_type == GOT_TLS_IE && elf_mn10300_hash_entry (h)->tls_type == GOT_TLS_GD)
    return;

  if (*tls_type == GOT_TLS_GD && elf_mn10300_hash_entry (h)->tls_type == GOT_TLS_IE)
    {
      *tls_type = GOT_TLS_IE;
      return;
    }

  _bfd_error_handler
    (_("%pB: %s' accessed both as normal and thread local symbol"),
     abfd, h ? h->root.root.string : "<local>");
}

static bool
process_local_got_entry(bfd *abfd, struct bfd_link_info *info, unsigned long r_symndx,
                       int tls_type, asection *sgot, asection *srelgot,
                       bfd_vma **local_got_offsets, Elf_Internal_Shdr *symtab_hdr,
                       unsigned int r_type)
{
  if (*local_got_offsets == NULL)
    {
      if (!allocate_local_got_offsets(abfd, local_got_offsets, symtab_hdr))
        return false;
    }

  if ((*local_got_offsets)[r_symndx] != (bfd_vma) -1)
    return true;

  (*local_got_offsets)[r_symndx] = sgot->size;

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
allocate_local_got_offsets(bfd *abfd, bfd_vma **local_got_offsets,
                           Elf_Internal_Shdr *symtab_hdr)
{
  size_t size;
  unsigned int i;

  size = symtab_hdr->sh_info * (sizeof (bfd_vma) + sizeof (char));
  *local_got_offsets = bfd_alloc (abfd, size);

  if (*local_got_offsets == NULL)
    return false;

  elf_local_got_offsets (abfd) = *local_got_offsets;
  elf_mn10300_local_got_tls_type (abfd) =
    (char *) (*local_got_offsets + symtab_hdr->sh_info);

  for (i = 0; i < symtab_hdr->sh_info; i++)
    (*local_got_offsets)[i] = (bfd_vma) -1;

  return true;
}

static bool
process_plt_entry(struct elf_link_hash_entry *h)
{
  if (h == NULL)
    return true;

  if (ELF_ST_VISIBILITY (h->other) == STV_INTERNAL ||
      ELF_ST_VISIBILITY (h->other) == STV_HIDDEN)
    return true;

  h->needs_plt = 1;
  return true;
}

static bool
process_shared_relocs(bfd *abfd, struct bfd_link_info *info, asection *sec,
                     struct elf_link_hash_entry *h, unsigned long r_symndx,
                     bool sym_diff_reloc_seen, asection **sreloc, bfd *dynobj,
                     Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym **isymbuf)
{
  asection *sym_section = NULL;

  if (!bfd_link_pic (info) || (sec->flags & SEC_ALLOC) == 0 || sym_diff_reloc_seen)
    return true;

  sym_section = get_symbol_section(abfd, h, r_symndx, symtab_hdr, isymbuf);

  if (sym_section == bfd_abs_section_ptr)
    return true;

  if (*sreloc == NULL)
    {
      *sreloc = _bfd_elf_make_dynamic_reloc_section
        (sec, dynobj, 2, abfd, true);
      if (*sreloc == NULL)
        return false;
    }

  (*sreloc)->size += sizeof (Elf32_External_Rela);
  return true;
}

static asection *
get_symbol_section(bfd *abfd, struct elf_link_hash_entry *h, unsigned long r_symndx,
                  Elf_Internal_Shdr *symtab_hdr, Elf_Internal_Sym **isymbuf)
{
  if (h == NULL)
    {
      Elf_Internal_Sym *isym;

      if (*isymbuf == NULL)
        *isymbuf = bfd_elf_get_elf_syms (abfd, symtab_hdr,
                                        symtab_hdr->sh_info, 0,
                                        NULL, NULL, NULL);
      if (*isymbuf)
        {
          isym = *isymbuf + r_symndx;
          if (isym->st_shndx == SHN_ABS)
            return bfd_abs_section_ptr;
        }
    }
  else
    {
      if (h->root.type == bfd_link_hash_defined ||
          h->root.type == bfd_link_hash_defweak)
        return h->root.u.def.section;
    }

  return NULL;
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
      unsigned int r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == R_MN10300_GNU_VTINHERIT || r_type == R_MN10300_GNU_VTENTRY)
        return NULL;
    }

  return _bfd_elf_gc_mark_hook (sec, info, rel, h, sym);
}

/* Perform a relocation as part of a final link.  */

#define SIGNED_8BIT_MAX 0x7f
#define SIGNED_8BIT_MIN -0x80
#define SIGNED_16BIT_MAX 0x7fff
#define SIGNED_16BIT_MIN -0x8000
#define SIGNED_24BIT_MAX 0x7fffff
#define SIGNED_24BIT_MIN -0x800000

static bool
is_protected_function_in_shared_lib(struct bfd_link_info *info,
                                   struct elf_link_hash_entry *h)
{
  return (bfd_link_pic(info)
          && h != NULL
          && ELF_ST_VISIBILITY(h->other) == STV_PROTECTED
          && (h->type == STT_FUNC || h->type == STT_GNU_IFUNC)
          && !SYMBOL_REFERENCES_LOCAL(info, h));
}

static bool
needs_dynamic_relocation(struct bfd_link_info *info,
                        asection *input_section,
                        struct elf_link_hash_entry *h)
{
  return (bfd_link_pic(info)
          && (input_section->flags & SEC_ALLOC) != 0
          && h != NULL
          && !SYMBOL_REFERENCES_LOCAL(info, h));
}

static bfd_reloc_status_type
check_relocation_safety(unsigned long r_type,
                       struct bfd_link_info *info,
                       asection *input_section,
                       struct elf_link_hash_entry *h)
{
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
      if (needs_dynamic_relocation(info, input_section, h))
        return bfd_reloc_dangerous;
      break;
    case R_MN10300_GOT32:
      if (is_protected_function_in_shared_lib(info, h) &&
          (input_section->flags & SEC_ALLOC) != 0)
        return bfd_reloc_dangerous;
      break;
  }
  return bfd_reloc_ok;
}

static void
write_24bit_value(bfd *input_bfd, bfd_vma value, bfd_byte *hit_data)
{
  bfd_put_8(input_bfd, value & 0xff, hit_data);
  bfd_put_8(input_bfd, (value >> 8) & 0xff, hit_data + 1);
  bfd_put_8(input_bfd, (value >> 16) & 0xff, hit_data + 2);
}

static bfd_reloc_status_type
check_24bit_overflow(long value)
{
  if (value > SIGNED_24BIT_MAX || value < SIGNED_24BIT_MIN)
    return bfd_reloc_overflow;
  return bfd_reloc_ok;
}

static bfd_reloc_status_type
check_16bit_overflow(long value)
{
  if (value > SIGNED_16BIT_MAX || value < SIGNED_16BIT_MIN)
    return bfd_reloc_overflow;
  return bfd_reloc_ok;
}

static bfd_reloc_status_type
check_8bit_overflow(long value)
{
  if (value > SIGNED_8BIT_MAX || value < SIGNED_8BIT_MIN)
    return bfd_reloc_overflow;
  return bfd_reloc_ok;
}

static bfd_vma
calculate_pcrel_value(bfd_vma value, asection *input_section, bfd_vma offset)
{
  return value - (input_section->output_section->vma + input_section->output_offset) - offset;
}

static bfd_vma
calculate_plt_value(struct elf32_mn10300_link_hash_table *htab,
                   struct elf_link_hash_entry *h,
                   bfd_vma value)
{
  asection *splt = htab->root.splt;
  return (splt->output_section->vma + splt->output_offset + h->plt.offset) - value;
}

static bool
should_use_plt(struct elf_link_hash_entry *h)
{
  return (h != NULL
          && ELF_ST_VISIBILITY(h->other) != STV_INTERNAL
          && ELF_ST_VISIBILITY(h->other) != STV_HIDDEN
          && h->plt.offset != (bfd_vma)-1);
}

static void
setup_dynamic_relocation(Elf_Internal_Rela *outrel,
                        bfd *input_bfd,
                        struct bfd_link_info *info,
                        asection *input_section,
                        bfd_vma offset,
                        struct elf_link_hash_entry *h,
                        bfd_vma value,
                        bfd_vma addend)
{
  outrel->r_offset = _bfd_elf_section_offset(input_bfd, info, input_section, offset);
  
  if (outrel->r_offset != (bfd_vma)-1) {
    outrel->r_offset += (input_section->output_section->vma + input_section->output_offset);
    
    if (h == NULL || SYMBOL_REFERENCES_LOCAL(info, h)) {
      outrel->r_info = ELF32_R_INFO(0, R_MN10300_RELATIVE);
      outrel->r_addend = value + addend;
    } else {
      BFD_ASSERT(h->dynindx != -1);
      outrel->r_info = ELF32_R_INFO(h->dynindx, R_MN10300_32);
      outrel->r_addend = value + addend;
    }
  } else {
    memset(outrel, 0, sizeof(*outrel));
  }
}

static void
emit_tls_ldm_relocation(struct elf32_mn10300_link_hash_table *htab, bfd *output_bfd)
{
  asection *sgot = htab->root.sgot;
  asection *srelgot = htab->root.srelgot;
  Elf_Internal_Rela rel;
  
  BFD_ASSERT(srelgot != NULL);
  htab->tls_ldm_got.rel_emitted++;
  
  rel.r_offset = sgot->output_section->vma + sgot->output_offset + htab->tls_ldm_got.offset;
  bfd_put_32(output_bfd, 0, sgot->contents + htab->tls_ldm_got.offset);
  bfd_put_32(output_bfd, 0, sgot->contents + htab->tls_ldm_got.offset + 4);
  rel.r_info = ELF32_R_INFO(0, R_MN10300_TLS_DTPMOD);
  rel.r_addend = 0;
  
  bfd_elf32_swap_reloca_out(output_bfd, &rel,
                           (bfd_byte *)((Elf32_External_Rela *)srelgot->contents + srelgot->reloc_count));
  srelgot->reloc_count++;
}

static bfd_vma
get_got_offset_for_symbol(struct elf_link_hash_entry *h,
                         bfd *input_bfd,
                         unsigned long symndx)
{
  if (h != NULL) {
    bfd_vma off = h->got.offset;
    return (off == (bfd_vma)-1) ? 0 : off;
  }
  return elf_local_got_offsets(input_bfd)[symndx];
}

static void
emit_got_relocation(bfd *output_bfd,
                   struct elf32_mn10300_link_hash_table *htab,
                   asection *sgot,
                   bfd_vma off,
                   unsigned long r_type,
                   bfd_vma value)
{
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
      srelgot->reloc_count++;
      outrel.r_info = ELF32_R_INFO(0, R_MN10300_TLS_DTPMOD);
      outrel.r_offset = sgot->output_section->vma + sgot->output_offset + off;
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
                           (bfd_byte *)((Elf32_External_Rela *)srelgot->contents + srelgot->reloc_count));
  srelgot->reloc_count++;
}

static bfd_reloc_status_type
handle_sym_diff_relocation(unsigned long r_type,
                          bfd_vma *value,
                          bfd_vma sym_diff_value,
                          asection *input_section,
                          bool *is_sym_diff_reloc)
{
  switch (r_type) {
    case R_MN10300_32:
    case R_MN10300_24:
    case R_MN10300_16:
    case R_MN10300_8:
      *value -= sym_diff_value;
      if (r_type == R_MN10300_32 && *value == 0 && 
          strcmp(input_section->name, ".debug_loc") == 0)
        *value = 1;
      *is_sym_diff_reloc = true;
      return bfd_reloc_ok;
    default:
      return bfd_reloc_ok;
  }
}

static bfd_reloc_status_type
handle_got_relocation(bfd *input_bfd,
                     bfd *output_bfd,
                     struct elf32_mn10300_link_hash_table *htab,
                     struct bfd_link_info *info,
                     unsigned long r_type,
                     struct elf_link_hash_entry *h,
                     unsigned long symndx,
                     bfd_vma value,
                     bfd_vma addend,
                     bfd_byte *hit_data)
{
  asection *sgot;
  bfd_vma off;
  
  if (htab->root.sgot == NULL)
    return bfd_reloc_dangerous;
    
  sgot = htab->root.sgot;
  
  if (r_type == R_MN10300_TLS_GD)
    value = dtpoff(info, value);
  else if (r_type == R_MN10300_TLS_GOTIE)
    value = tpoff(info, value);
    
  off = get_got_offset_for_symbol(h, input_bfd, symndx);
  
  if (h != NULL) {
    if (sgot->contents != NULL &&
        (!elf_hash_table(info)->dynamic_sections_created || SYMBOL_REFERENCES_LOCAL(info, h)))
      bfd_put_32(output_bfd, value, sgot->contents + off);
    value = sgot->output_offset + off;
  } else {
    if (off & 1) {
      bfd_put_32(output_bfd, value, sgot->contents + (off & ~1));
    } else {
      bfd_put_32(output_bfd, value, sgot->contents + off);
      if (bfd_link_pic(info)) {
        emit_got_relocation(output_bfd, htab, sgot, off, r_type, value);
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
  }
  
  if (r_type == R_MN10300_TLS_GOTIE || r_type == R_MN10300_TLS_GD || 
      r_type == R_MN10300_TLS_LD || r_type == R_MN10300_GOT32) {
    bfd_put_32(input_bfd, value, hit_data);
    return bfd_reloc_ok;
  }
  
  if (r_type == R_MN10300_GOT24) {
    bfd_reloc_status_type status = check_24bit_overflow((long)value);
    if (status != bfd_reloc_ok)
      return status;
    write_24bit_value(input_bfd, value, hit_data);
    return bfd_reloc_ok;
  }
  
  if (r_type == R_MN10300_GOT16) {
    bfd_reloc_status_type status = check_16bit_overflow((long)value);
    if (status != bfd_reloc_ok)
      return status;
    bfd_put_16(input_bfd, value, hit_data);
    return bfd_reloc_ok;
  }
  
  return bfd_reloc_notsupported;
}

static bfd_reloc_status_type
mn10300_elf_final_link_relocate(reloc_howto_type *howto,
                               bfd *input_bfd,
                               bfd *output_bfd ATTRIBUTE_UNUSED,
                               asection *input_section,
                               bfd_byte *contents,
                               bfd_vma offset,
                               bfd_vma value,
                               bfd_vma addend,
                               struct elf_link_hash_entry *h,
                               unsigned long symndx,
                               struct bfd_link_info *info,
                               asection *sym_sec ATTRIBUTE_UNUSED,
                               int is_local ATTRIBUTE_UNUSED)
{
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
  static asection *sym_diff_section;
  static bfd_vma sym_diff_value;
  bool is_sym_diff_reloc = false;
  unsigned long r_type = howto->type;
  bfd_byte *hit_data = contents + offset;
  bfd *dynobj = elf_hash_table(info)->dynobj;
  asection *sgot = NULL;
  asection *splt = NULL;
  asection *sreloc = NULL;
  bfd_reloc_status_type status;
  
  status = check_relocation_safety(r_type, info, input_section, h);
  if (status != bfd_reloc_ok)
    return status;
  
  if (sym_diff_section != NULL) {
    BFD_ASSERT(sym_diff_section == input_section);
    status = handle_sym_diff_relocation(r_type, &value, sym_diff_value, 
                                       input_section, &is_sym_diff_reloc);
    sym_diff_section = NULL;
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
      if (bfd_link_pic(info) && !is_sym_diff_reloc && 
          sym_sec != bfd_abs_section_ptr && (input_section->flags & SEC_ALLOC) != 0) {
        Elf_Internal_Rela outrel;
        bool skip, relocate;
        
        if (sreloc == NULL) {
          sreloc = _bfd_elf_get_dynamic_reloc_section(input_bfd, input_section, true);
          if (sreloc == NULL)
            return false;
        }
        
        setup_dynamic_relocation(&outrel, input_bfd, info, input_section, 
                                offset, h, value, addend);
        skip = (outrel.r_offset == (bfd_vma)-1);
        relocate = (h == NULL || SYMBOL_REFERENCES_LOCAL(info, h));
        
        bfd_elf32_swap_reloca_out(output_bfd, &outrel,
                                 (bfd_byte *)((Elf32_External_Rela *)sreloc->contents + sreloc->reloc_count));
        sreloc->reloc_count++;
        
        if (!relocate)
          return bfd_reloc_ok;
      }
      value += addend;
      bfd_put_32(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_24:
      value += addend;
      status = check_24bit_overflow((long)value);
      if (status != bfd_reloc_ok)
        return status;
      write_24bit_value(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_16:
      value += addend;
      status = check_16bit_overflow((long)value);
      if (status != bfd_reloc_ok)
        return status;
      bfd_put_16(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_8:
      value += addend;
      status = check_8bit_overflow((long)value);
      if (status != bfd_reloc_ok)
        return status;
      bfd_put_8(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_PCREL8:
      value = calculate_pcrel_value(value, input_section, offset) + addend;
      status = check_8bit_overflow((long)value);
      if (status != bfd_reloc_ok)
        return status;
      bfd_put_8(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_PCREL16:
      value = calculate_pcrel_value(value, input_section, offset) + addend;
      status = check_16bit_overflow((long)value);
      if (status != bfd_reloc_ok)
        return status;
      bfd_put_16(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_PCREL32:
      value = calculate_pcrel_value(value, input_section, offset) + addend;
      bfd_put_32(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_GNU_VTINHERIT:
    case R_MN10300_GNU_VTENTRY:
      return bfd_reloc_ok;
      
    case R_MN10300_GOTPC32:
      if (dynobj == NULL)
        return bfd_reloc_dangerous;
      value = htab->root.sgot->output_section->vma;
      value = calculate_pcrel_value(value, input_section, offset) + addend;
      bfd_put_32(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_GOTPC16:
      if (dynobj == NULL)
        return bfd_reloc_dangerous;
      value = htab->root.sgot->output_section->vma;
      value = calculate_pcrel_value(value, input_section, offset) + addend;
      status = check_16bit_overflow((long)value);
      if (status != bfd_reloc_ok)
        return status;
      bfd_put_16(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_GOTOFF32:
      if (dynobj == NULL)
        return bfd_reloc_dangerous;
      value = value - htab->root.sgot->output_section->vma + addend;
      bfd_put_32(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_GOTOFF24:
      if (dynobj == NULL)
        return bfd_reloc_dangerous;
      value = value - htab->root.sgot->output_section->vma + addend;
      status = check_24bit_overflow((long)value);
      if (status != bfd_reloc_ok)
        return status;
      write_24bit_value(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_GOTOFF16:
      if (dynobj == NULL)
        return bfd_reloc_dangerous;
      value = value - htab->root.sgot->output_section->vma + addend;
      status = check_16bit_overflow((long)value);
      if (status != bfd_reloc_ok)
        return status;
      bfd_put_16(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_PLT32:
      if (should_use_plt(h)) {
        if (dynobj == NULL)
          return bfd_reloc_dangerous;
        value = calculate_plt_value(htab, h, value);
      }
      value = calculate_pcrel_value(value, input_section, offset) + addend;
      bfd_put_32(input_bfd, value, hit_data);
      return bfd_reloc_ok;
      
    case R_MN10300_PLT16:
      if (should_use_plt(h)) {
        if (dynobj == NULL)
          return bfd_reloc_dangerous;
        value = calculate_plt_value(htab, h, value);
      }
      value = calculate_pcrel_value(value, input_section, offset) + addend;
      status = check_16bit_overflow((long)value);
      if (status != bfd_reloc_ok)
        return status;
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
      if (dynobj == NULL)
        return bfd_reloc_dangerous;
      sgot = htab->root.sgot;
      BFD_ASSERT(sgot != NULL);
      value = htab->tls_ldm_got.offset + sgot->output_offset;
      bfd_put_32(input_bfd, value, hit_data);
      if (!htab->tls_ldm_got.rel_emitted)
        emit_tls_ldm_relocation(htab, output_bfd);
      return bfd_reloc_ok;
      
    case R_MN10300_TLS_GOTIE:
    case R_MN10300_TLS_GD:
    case R_MN10300_TLS_IE:
    case R_MN10300_GOT32:
    case R_MN10300_GOT24:
    case R_MN10300_GOT16:
      return handle_got_relocation(input_bfd, output_bfd, htab, info, r_type,
                                  h, symndx, value, addend, hit_data);
      
    default:
      return bfd_reloc_notsupported;
  }
}

/* Relocate an MN10300 ELF section.  */

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
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  Elf_Internal_Rela *rel, *relend;

  symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (input_bfd);

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      if (!process_relocation(output_bfd, info, input_bfd, input_section,
                             contents, rel, relend, local_syms, local_sections,
                             symtab_hdr, sym_hashes))
        return false;
    }

  return true;
}

static bool
should_skip_relocation(int r_type)
{
  return r_type == R_MN10300_GNU_VTINHERIT || r_type == R_MN10300_GNU_VTENTRY;
}

static void
handle_tls_transition(bfd *input_bfd, int *r_type, int tls_r_type,
                      bfd_byte *contents, bfd_vma offset,
                      Elf_Internal_Rela *rel, Elf_Internal_Rela *relend,
                      reloc_howto_type **howto)
{
  bool had_plt;
  Elf_Internal_Rela *trel;

  had_plt = mn10300_do_tls_transition(input_bfd, *r_type, tls_r_type,
                                      contents, offset);
  *r_type = tls_r_type;
  *howto = elf_mn10300_howto_table + *r_type;

  if (had_plt)
    for (trel = rel + 1; trel < relend; trel++)
      if ((ELF32_R_TYPE(trel->r_info) == R_MN10300_PLT32
           || ELF32_R_TYPE(trel->r_info) == R_MN10300_PCREL32)
          && offset + had_plt == trel->r_offset)
        trel->r_info = ELF32_R_INFO(0, R_MN10300_NONE);
}

static bool
needs_zero_relocation(struct elf32_mn10300_link_hash_entry *h,
                      struct elf_link_hash_entry *hh,
                      int r_type, struct bfd_link_info *info,
                      asection *input_section)
{
  if (h->root.root.type != bfd_link_hash_defined &&
      h->root.root.type != bfd_link_hash_defweak)
    return false;

  if (r_type == R_MN10300_GOTPC32 || r_type == R_MN10300_GOTPC16)
    return true;

  if ((r_type == R_MN10300_PLT32 || r_type == R_MN10300_PLT16) &&
      ELF_ST_VISIBILITY(h->root.other) != STV_INTERNAL &&
      ELF_ST_VISIBILITY(h->root.other) != STV_HIDDEN &&
      h->root.plt.offset != (bfd_vma)-1)
    return true;

  if ((r_type == R_MN10300_GOT32 || r_type == R_MN10300_GOT24 ||
       r_type == R_MN10300_TLS_GD || r_type == R_MN10300_TLS_LD ||
       r_type == R_MN10300_TLS_GOTIE || r_type == R_MN10300_TLS_IE ||
       r_type == R_MN10300_GOT16) &&
      elf_hash_table(info)->dynamic_sections_created &&
      !SYMBOL_REFERENCES_LOCAL(info, hh))
    return true;

  if (r_type == R_MN10300_32 && !SYMBOL_REFERENCES_LOCAL(info, hh) &&
      (((input_section->flags & SEC_ALLOC) != 0 && !bfd_link_executable(info)) ||
       ((input_section->flags & SEC_DEBUGGING) != 0 && h->root.def_dynamic)))
    return true;

  return false;
}

static void
get_symbol_info(unsigned long r_symndx, Elf_Internal_Shdr *symtab_hdr,
               Elf_Internal_Sym *local_syms, asection **local_sections,
               struct elf_link_hash_entry **sym_hashes,
               struct bfd_link_info *info, bfd *input_bfd,
               asection *input_section, Elf_Internal_Rela *rel,
               struct elf32_mn10300_link_hash_entry **h,
               struct elf_link_hash_entry **hh,
               Elf_Internal_Sym **sym, asection **sec,
               bfd_vma *relocation, bool *unresolved_reloc,
               bool *warned, bool *ignored)
{
  if (r_symndx < symtab_hdr->sh_info)
    {
      *hh = NULL;
      *sym = local_syms + r_symndx;
      *sec = local_sections[r_symndx];
    }
  else
    {
      RELOC_FOR_GLOBAL_SYMBOL(info, input_bfd, input_section, rel,
                             r_symndx, symtab_hdr, sym_hashes,
                             *hh, *sec, *relocation,
                             *unresolved_reloc, *warned, *ignored);
    }
  *h = elf_mn10300_hash_entry(*hh);
}

static void
compute_local_relocation(bfd *output_bfd, Elf_Internal_Sym *sym,
                        asection **sec, Elf_Internal_Rela *rel,
                        bfd_vma *relocation)
{
  *relocation = _bfd_elf_rela_local_sym(output_bfd, sym, sec, rel);
}

static void
compute_global_relocation(struct elf32_mn10300_link_hash_entry *h,
                         struct elf_link_hash_entry *hh,
                         int r_type, struct bfd_link_info *info,
                         asection *input_section, bfd_vma *relocation,
                         bool unresolved_reloc, bfd *input_bfd,
                         bfd *output_bfd, Elf_Internal_Rela *rel,
                         reloc_howto_type *howto)
{
  if (needs_zero_relocation(h, hh, r_type, info, input_section))
    {
      *relocation = 0;
    }
  else if (!bfd_link_relocatable(info) && unresolved_reloc &&
           _bfd_elf_section_offset(output_bfd, info, input_section,
                                  rel->r_offset) != (bfd_vma)-1)
    {
      _bfd_error_handler
        (_("%pB(%pA+%#" PRIx64 "): "
           "unresolvable %s relocation against symbol `%s'"),
         input_bfd,
         input_section,
         (uint64_t)rel->r_offset,
         howto->name,
         h->root.root.root.string);
    }
}

static const char*
get_symbol_name(struct elf32_mn10300_link_hash_entry *h,
               Elf_Internal_Sym *sym, bfd *input_bfd,
               Elf_Internal_Shdr *symtab_hdr, asection *sec)
{
  const char *name;
  
  if (h != NULL)
    return h->root.root.root.string;
    
  name = bfd_elf_string_from_elf_section(input_bfd, symtab_hdr->sh_link,
                                         sym->st_name);
  if (name == NULL || *name == '\0')
    name = bfd_section_name(sec);
    
  return name;
}

static const char*
get_error_message(bfd_reloc_status_type r, int r_type)
{
  switch (r)
    {
    case bfd_reloc_outofrange:
      return _("internal error: out of range error");
    case bfd_reloc_notsupported:
      return _("internal error: unsupported relocation error");
    case bfd_reloc_dangerous:
      if (r_type == R_MN10300_PCREL32)
        return _("error: inappropriate relocation type for shared"
                " library (did you forget -fpic?)");
      else if (r_type == R_MN10300_GOT32)
        return _("%pB: taking the address of protected function"
                " '%s' cannot be done when making a shared library");
      else
        return _("internal error: suspicious relocation type used"
                " in shared library");
    default:
      return _("internal error: unknown error");
    }
}

static bool
handle_relocation_error(bfd_reloc_status_type r, int r_type,
                        struct elf32_mn10300_link_hash_entry *h,
                        Elf_Internal_Sym *sym, bfd *input_bfd,
                        asection *input_section, Elf_Internal_Rela *rel,
                        Elf_Internal_Shdr *symtab_hdr, asection *sec,
                        struct bfd_link_info *info, reloc_howto_type *howto)
{
  const char *name;
  const char *msg;

  if (r == bfd_reloc_ok)
    return true;

  name = get_symbol_name(h, sym, input_bfd, symtab_hdr, sec);

  switch (r)
    {
    case bfd_reloc_overflow:
      (*info->callbacks->reloc_overflow)
        (info, (h ? &h->root.root : NULL), name, howto->name,
         (bfd_vma)0, input_bfd, input_section, rel->r_offset);
      return true;

    case bfd_reloc_undefined:
      (*info->callbacks->undefined_symbol)
        (info, name, input_bfd, input_section, rel->r_offset, true);
      return true;

    default:
      msg = get_error_message(r, r_type);
      _bfd_error_handler(msg, input_bfd, name);
      bfd_set_error(bfd_error_bad_value);
      return false;
    }
}

static bool
process_relocation(bfd *output_bfd, struct bfd_link_info *info,
                  bfd *input_bfd, asection *input_section,
                  bfd_byte *contents, Elf_Internal_Rela *rel,
                  Elf_Internal_Rela *relend, Elf_Internal_Sym *local_syms,
                  asection **local_sections, Elf_Internal_Shdr *symtab_hdr,
                  struct elf_link_hash_entry **sym_hashes)
{
  int r_type;
  reloc_howto_type *howto;
  unsigned long r_symndx;
  Elf_Internal_Sym *sym = NULL;
  asection *sec = NULL;
  struct elf32_mn10300_link_hash_entry *h = NULL;
  bfd_vma relocation = 0;
  bfd_reloc_status_type r;
  int tls_r_type;
  bool unresolved_reloc = false;
  bool warned, ignored;
  struct elf_link_hash_entry *hh = NULL;

  r_symndx = ELF32_R_SYM(rel->r_info);
  r_type = ELF32_R_TYPE(rel->r_info);
  howto = elf_mn10300_howto_table + r_type;

  if (should_skip_relocation(r_type))
    return true;

  get_symbol_info(r_symndx, symtab_hdr, local_syms, local_sections,
                 sym_hashes, info, input_bfd, input_section, rel,
                 &h, &hh, &sym, &sec, &relocation, &unresolved_reloc,
                 &warned, &ignored);

  tls_r_type = elf_mn10300_tls_transition(info, r_type, hh, input_section, 0);
  if (tls_r_type != r_type)
    handle_tls_transition(input_bfd, &r_type, tls_r_type, contents,
                         rel->r_offset, rel, relend, &howto);

  if (r_symndx < symtab_hdr->sh_info)
    compute_local_relocation(output_bfd, sym, &sec, rel, &relocation);
  else
    compute_global_relocation(h, hh, r_type, info, input_section,
                             &relocation, unresolved_reloc, input_bfd,
                             output_bfd, rel, howto);

  if (sec != NULL && discarded_section(sec))
    RELOC_AGAINST_DISCARDED_SECTION(info, input_bfd, input_section,
                                   rel, 1, relend, R_MN10300_NONE,
                                   howto, 0, contents);

  if (bfd_link_relocatable(info))
    return true;

  r = mn10300_elf_final_link_relocate(howto, input_bfd, output_bfd,
                                      input_section, contents, rel->r_offset,
                                      relocation, rel->r_addend,
                                      (struct elf_link_hash_entry *)h,
                                      r_symndx, info, sec, h == NULL);

  return handle_relocation_error(r, r_type, h, sym, input_bfd, input_section,
                                 rel, symtab_hdr, sec, info, howto);
}

/* Finish initializing one hash table entry.  */

static bool should_convert_to_calls(struct elf32_mn10300_link_hash_entry *entry,
                                    struct bfd_link_info *link_info)
{
    if (entry->direct_calls == 0)
        return true;
    
    if (entry->stack_size == 0 && entry->movm_args == 0)
        return true;
    
    if (elf_hash_table(link_info)->dynamic_sections_created &&
        ELF_ST_VISIBILITY(entry->root.other) != STV_INTERNAL &&
        ELF_ST_VISIBILITY(entry->root.other) != STV_HIDDEN)
        return true;
    
    return false;
}

static unsigned int calculate_stack_allocation_size(unsigned int stack_size)
{
    #define SMALL_STACK_THRESHOLD 128
    #define SMALL_STACK_INSN_SIZE 3
    #define LARGE_STACK_INSN_SIZE 4
    
    if (stack_size == 0)
        return 0;
    
    if (stack_size <= SMALL_STACK_THRESHOLD)
        return SMALL_STACK_INSN_SIZE;
    
    return LARGE_STACK_INSN_SIZE;
}

static unsigned int calculate_byte_count(struct elf32_mn10300_link_hash_entry *entry)
{
    #define MOVM_INSN_SIZE 2
    
    unsigned int byte_count = 0;
    
    if (entry->movm_args)
        byte_count += MOVM_INSN_SIZE;
    
    byte_count += calculate_stack_allocation_size(entry->stack_size);
    
    return byte_count;
}

static bool
elf32_mn10300_finish_hash_table_entry(struct bfd_hash_entry *gen_entry,
                                      void *in_args)
{
    struct elf32_mn10300_link_hash_entry *entry;
    struct bfd_link_info *link_info = (struct bfd_link_info *) in_args;
    
    entry = (struct elf32_mn10300_link_hash_entry *) gen_entry;
    
    if (entry->flags == MN10300_CONVERT_CALL_TO_CALLS)
        return true;
    
    if (should_convert_to_calls(entry, link_info))
    {
        entry->flags |= MN10300_CONVERT_CALL_TO_CALLS;
        return true;
    }
    
    unsigned int byte_count = calculate_byte_count(entry);
    
    if (byte_count < entry->direct_calls)
        entry->flags |= MN10300_CONVERT_CALL_TO_CALLS;
    
    return true;
}

/* Used to count hash table entries.  */

static bool
elf32_mn10300_count_hash_table_entries (struct bfd_hash_entry *gen_entry ATTRIBUTE_UNUSED,
					void * in_args)
{
  int *count = (int *) in_args;
  (*count)++;
  return true;
}

/* Used to enumerate hash table entries into a linear array.  */

static bool
elf32_mn10300_list_hash_table_entries (struct bfd_hash_entry *gen_entry,
				       void * in_args)
{
  struct bfd_hash_entry ***ptr = (struct bfd_hash_entry ***) in_args;

  **ptr = gen_entry;
  (*ptr)++;
  return true;
}

/* Used to sort the array created by the above.  */

static int
sort_by_value (const void *va, const void *vb)
{
  struct elf32_mn10300_link_hash_entry *a
    = *(struct elf32_mn10300_link_hash_entry **) va;
  struct elf32_mn10300_link_hash_entry *b
    = *(struct elf32_mn10300_link_hash_entry **) vb;

  return a->value - b->value;
}

/* Compute the stack size and movm arguments for the function
   referred to by HASH at address ADDR in section with
   contents CONTENTS, store the information in the hash table.  */

static void
compute_movm_stack_size(struct elf32_mn10300_link_hash_entry *hash, bfd *abfd)
{
    #define MOVM_D2_MASK    0x80
    #define MOVM_D3_MASK    0x40
    #define MOVM_A2_MASK    0x20
    #define MOVM_A3_MASK    0x10
    #define MOVM_OTHER_MASK 0x08
    #define MOVM_EXOTHER_MASK 0x01
    #define MOVM_EXREG1_MASK  0x02
    #define MOVM_EXREG0_MASK  0x04
    #define REGISTER_SIZE 4
    #define OTHER_REGISTERS_COUNT 8
    #define EXOTHER_REGISTERS_COUNT 6
    #define EXREG1_REGISTERS_COUNT 4
    #define EXREG0_REGISTERS_COUNT 2

    if (!hash->movm_args)
        return;

    if (hash->movm_args & MOVM_D2_MASK)
        hash->movm_stack_size += REGISTER_SIZE;

    if (hash->movm_args & MOVM_D3_MASK)
        hash->movm_stack_size += REGISTER_SIZE;

    if (hash->movm_args & MOVM_A2_MASK)
        hash->movm_stack_size += REGISTER_SIZE;

    if (hash->movm_args & MOVM_A3_MASK)
        hash->movm_stack_size += REGISTER_SIZE;

    if (hash->movm_args & MOVM_OTHER_MASK)
        hash->movm_stack_size += OTHER_REGISTERS_COUNT * REGISTER_SIZE;

    if (bfd_get_mach(abfd) == bfd_mach_am33 || bfd_get_mach(abfd) == bfd_mach_am33_2) {
        if (hash->movm_args & MOVM_EXOTHER_MASK)
            hash->movm_stack_size += EXOTHER_REGISTERS_COUNT * REGISTER_SIZE;

        if (hash->movm_args & MOVM_EXREG1_MASK)
            hash->movm_stack_size += EXREG1_REGISTERS_COUNT * REGISTER_SIZE;

        if (hash->movm_args & MOVM_EXREG0_MASK)
            hash->movm_stack_size += EXREG0_REGISTERS_COUNT * REGISTER_SIZE;
    }
}

static int
calculate_stack_adjustment_8bit(bfd *abfd, unsigned char *contents, bfd_vma addr)
{
    #define SIGN_EXTEND_8BIT_MASK 0x7f
    #define SIGN_EXTEND_8BIT_ADD 0x80
    
    int temp = bfd_get_8(abfd, contents + addr + 2);
    temp = ((temp & 0xff) ^ (~SIGN_EXTEND_8BIT_MASK)) + SIGN_EXTEND_8BIT_ADD;
    return -temp;
}

static int
calculate_stack_adjustment_16bit(bfd *abfd, unsigned char *contents, bfd_vma addr)
{
    #define SIGN_EXTEND_16BIT_MASK 0x7fff
    #define SIGN_EXTEND_16BIT_ADD 0x8000
    #define MAX_STACK_SIZE 255
    
    int temp = bfd_get_16(abfd, contents + addr + 2);
    temp = ((temp & 0xffff) ^ (~SIGN_EXTEND_16BIT_MASK)) + SIGN_EXTEND_16BIT_ADD;
    temp = -temp;
    
    if (temp < MAX_STACK_SIZE)
        return temp;
    return 0;
}

static void
process_stack_adjustment(struct elf32_mn10300_link_hash_entry *hash,
                         bfd *abfd,
                         unsigned char *contents,
                         bfd_vma addr,
                         unsigned char byte1,
                         unsigned char byte2)
{
    #define STACK_ADJ_8BIT_BYTE1 0xf8
    #define STACK_ADJ_8BIT_BYTE2 0xfe
    #define STACK_ADJ_16BIT_BYTE1 0xfa
    #define STACK_ADJ_16BIT_BYTE2 0xfe
    
    if (byte1 == STACK_ADJ_8BIT_BYTE1 && byte2 == STACK_ADJ_8BIT_BYTE2) {
        hash->stack_size = calculate_stack_adjustment_8bit(abfd, contents, addr);
    } else if (byte1 == STACK_ADJ_16BIT_BYTE1 && byte2 == STACK_ADJ_16BIT_BYTE2) {
        hash->stack_size = calculate_stack_adjustment_16bit(abfd, contents, addr);
    }
}

static void
compute_function_info(bfd *abfd,
                     struct elf32_mn10300_link_hash_entry *hash,
                     bfd_vma addr,
                     unsigned char *contents)
{
    #define MOVM_OPCODE 0xcf
    #define MAX_TOTAL_STACK_SIZE 255
    
    unsigned char byte1, byte2;

    byte1 = bfd_get_8(abfd, contents + addr);
    byte2 = bfd_get_8(abfd, contents + addr + 1);

    if (byte1 == MOVM_OPCODE) {
        hash->movm_args = byte2;
        addr += 2;
        byte1 = bfd_get_8(abfd, contents + addr);
        byte2 = bfd_get_8(abfd, contents + addr + 1);
    }

    compute_movm_stack_size(hash, abfd);
    process_stack_adjustment(hash, abfd, contents, addr, byte1, byte2);

    if (hash->stack_size + hash->movm_stack_size > MAX_TOTAL_STACK_SIZE)
        hash->stack_size = 0;
}

/* Delete some bytes from a section while relaxing.  */

#define NOP_OPCODE 0xcb

static bool is_align_reloc(Elf_Internal_Rela *irel)
{
  return ELF32_R_TYPE(irel->r_info) == (int)R_MN10300_ALIGN;
}

static bool is_function_symbol(Elf_Internal_Sym *isym)
{
  return ELF_ST_TYPE(isym->st_info) == STT_FUNC;
}

static bool is_defined_hash(struct elf_link_hash_entry *sym_hash)
{
  return sym_hash->root.type == bfd_link_hash_defined ||
         sym_hash->root.type == bfd_link_hash_defweak;
}

static void adjust_relocation_if_needed(Elf_Internal_Rela *irel, bfd_vma addr, 
                                        bfd_vma toaddr, int count)
{
  if ((irel->r_offset > addr && irel->r_offset < toaddr) ||
      (is_align_reloc(irel) && irel->r_offset == toaddr))
    irel->r_offset -= count;
}

static Elf_Internal_Rela* find_alignment_constraint(Elf_Internal_Rela *irel,
                                                    Elf_Internal_Rela *irelend,
                                                    bfd_vma addr, bfd_vma *toaddr,
                                                    int count)
{
  for (; irel < irelend; irel++)
    {
      if (is_align_reloc(irel) && irel->r_offset > addr && 
          irel->r_offset < *toaddr)
        {
          int alignment = 1 << irel->r_addend;
          if (count < alignment || alignment % count != 0)
            {
              *toaddr = irel->r_offset;
              return irel;
            }
        }
    }
  return NULL;
}

static void handle_section_resize(bfd *abfd, asection *sec, bfd_byte *contents,
                                  Elf_Internal_Rela *irelalign, bfd_vma *toaddr,
                                  int count)
{
  if (irelalign == NULL)
    {
      sec->size -= count;
      (*toaddr)++;
    }
  else
    {
      for (int i = 0; i < count; i++)
        bfd_put_8(abfd, (bfd_vma)NOP_OPCODE, contents + *toaddr - count + i);
    }
}

static void adjust_relocations(asection *sec, Elf_Internal_Rela *irelend,
                               bfd_vma addr, bfd_vma toaddr, int count)
{
  Elf_Internal_Rela *irel = elf_section_data(sec)->relocs;
  for (; irel < irelend; irel++)
    adjust_relocation_if_needed(irel, addr, toaddr, count);
}

static void adjust_symbol_value(Elf_Internal_Sym *isym, bfd_vma addr, 
                                bfd_vma toaddr, int count)
{
  if (isym->st_value < addr + count)
    isym->st_value = addr;
  else
    isym->st_value -= count;
}

static void adjust_local_symbols(bfd *abfd, unsigned int sec_shndx,
                                 bfd_vma addr, bfd_vma toaddr, int count)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
  Elf_Internal_Sym *isym = (Elf_Internal_Sym *)symtab_hdr->contents;
  Elf_Internal_Sym *isymend = isym + symtab_hdr->sh_info;

  for (; isym < isymend; isym++)
    {
      if (isym->st_shndx == sec_shndx)
        {
          if (isym->st_value > addr && isym->st_value < toaddr)
            adjust_symbol_value(isym, addr, toaddr, count);
          else if (is_function_symbol(isym) &&
                   isym->st_value + isym->st_size > addr &&
                   isym->st_value + isym->st_size < toaddr)
            isym->st_size -= count;
        }
    }
}

static void adjust_hash_symbol_value(struct elf_link_hash_entry *sym_hash,
                                     bfd_vma addr, int count)
{
  if (sym_hash->root.u.def.value < addr + count)
    sym_hash->root.u.def.value = addr;
  else
    sym_hash->root.u.def.value -= count;
}

static void adjust_global_symbols(bfd *abfd, asection *sec, bfd_vma addr,
                                  bfd_vma toaddr, int count)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
  unsigned int symcount = (symtab_hdr->sh_size / sizeof(Elf32_External_Sym) -
                          symtab_hdr->sh_info);
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(abfd);
  struct elf_link_hash_entry **end_hashes = sym_hashes + symcount;

  for (; sym_hashes < end_hashes; sym_hashes++)
    {
      struct elf_link_hash_entry *sym_hash = *sym_hashes;
      if (!sym_hash)
        continue;

      if (is_defined_hash(sym_hash) && sym_hash->root.u.def.section == sec)
        {
          bfd_vma value = sym_hash->root.u.def.value;
          if (value > addr && value < toaddr)
            adjust_hash_symbol_value(sym_hash, addr, count);
          else if (sym_hash->type == STT_FUNC &&
                   value + sym_hash->size > addr &&
                   value + sym_hash->size < toaddr)
            sym_hash->size -= count;
        }
    }
}

static bool handle_align_reloc_adjustment(bfd *abfd, asection *sec,
                                          Elf_Internal_Rela *irelalign,
                                          bfd_vma toaddr)
{
  if (irelalign && (int)irelalign->r_addend > 0)
    {
      bfd_vma alignto = BFD_ALIGN(toaddr, 1 << irelalign->r_addend);
      bfd_vma alignaddr = BFD_ALIGN(irelalign->r_offset,
                                    1 << irelalign->r_addend);
      if (alignaddr < alignto)
        return mn10300_elf_relax_delete_bytes(abfd, sec, alignaddr,
                                              (int)(alignto - alignaddr));
    }
  return true;
}

static bool
mn10300_elf_relax_delete_bytes(bfd *abfd, asection *sec, bfd_vma addr, int count)
{
  unsigned int sec_shndx = _bfd_elf_section_from_bfd_section(abfd, sec);
  bfd_byte *contents = elf_section_data(sec)->this_hdr.contents;
  bfd_vma toaddr = sec->size;
  Elf_Internal_Rela *irel = elf_section_data(sec)->relocs;
  Elf_Internal_Rela *irelend = irel + sec->reloc_count;
  Elf_Internal_Rela *irelalign = NULL;

  if (sec->reloc_count > 0)
    {
      if (is_align_reloc(irelend - 1))
        --irelend;
      
      irelalign = find_alignment_constraint(irel, irelend, addr, &toaddr, count);
    }

  memmove(contents + addr, contents + addr + count,
          (size_t)(toaddr - addr - count));

  handle_section_resize(abfd, sec, contents, irelalign, &toaddr, count);
  adjust_relocations(sec, irelend, addr, toaddr, count);
  adjust_local_symbols(abfd, sec_shndx, addr, toaddr, count);
  adjust_global_symbols(abfd, sec, addr, toaddr, count);

  return handle_align_reloc_adjustment(abfd, sec, irelalign, toaddr);
}

/* Return TRUE if a symbol exists at the given address, else return
   FALSE.  */

static bool
check_local_symbols(Elf_Internal_Sym *isym, Elf_Internal_Sym *isymend, 
                   unsigned int sec_shndx, bfd_vma addr)
{
    for (; isym < isymend; isym++)
        if (isym->st_shndx == sec_shndx && isym->st_value == addr)
            return true;
    return false;
}

static bool
check_global_symbols(struct elf_link_hash_entry **sym_hashes,
                    struct elf_link_hash_entry **end_hashes,
                    asection *sec, bfd_vma addr)
{
    for (; sym_hashes < end_hashes; sym_hashes++)
    {
        struct elf_link_hash_entry *sym_hash = *sym_hashes;
        
        if (sym_hash == NULL)
            continue;
            
        if ((sym_hash->root.type == bfd_link_hash_defined ||
             sym_hash->root.type == bfd_link_hash_defweak) &&
            sym_hash->root.u.def.section == sec &&
            sym_hash->root.u.def.value == addr)
            return true;
    }
    return false;
}

static bool
mn10300_elf_symbol_address_p (bfd *abfd,
                              asection *sec,
                              Elf_Internal_Sym *isym,
                              bfd_vma addr)
{
    Elf_Internal_Shdr *symtab_hdr;
    unsigned int sec_shndx;
    Elf_Internal_Sym *isymend;
    struct elf_link_hash_entry **sym_hashes;
    struct elf_link_hash_entry **end_hashes;
    unsigned int symcount;

    sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);
    symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
    
    isymend = isym + symtab_hdr->sh_info;
    if (check_local_symbols(isym, isymend, sec_shndx, addr))
        return true;

    symcount = (symtab_hdr->sh_size / sizeof (Elf32_External_Sym)
                - symtab_hdr->sh_info);
    sym_hashes = elf_sym_hashes (abfd);
    end_hashes = sym_hashes + symcount;
    
    return check_global_symbols(sym_hashes, end_hashes, sec, addr);
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

static bool should_skip_section(asection *section)
{
  return !((section->flags & SEC_RELOC) != 0 && section->reloc_count != 0) ||
         (section->flags & SEC_ALLOC) == 0 ||
         (section->flags & SEC_HAS_CONTENTS) == 0;
}

static bool should_skip_code_section(asection *section)
{
  return (section->flags & SEC_CODE) == 0 ||
         (section->flags & SEC_HAS_CONTENTS) == 0 ||
         section->size == 0;
}

static Elf_Internal_Sym *load_symbols(bfd *input_bfd, Elf_Internal_Shdr *symtab_hdr)
{
  Elf_Internal_Sym *isymbuf = NULL;
  if (symtab_hdr->sh_info != 0) {
    isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
    if (isymbuf == NULL)
      isymbuf = bfd_elf_get_elf_syms(input_bfd, symtab_hdr,
                                    symtab_hdr->sh_info, 0,
                                    NULL, NULL, NULL);
  }
  return isymbuf;
}

static bfd_byte *load_section_contents(bfd *input_bfd, asection *section)
{
  bfd_byte *contents = NULL;
  if (elf_section_data(section)->this_hdr.contents != NULL)
    contents = elf_section_data(section)->this_hdr.contents;
  else if (section->size != 0) {
    if (!bfd_malloc_and_get_section(input_bfd, section, &contents))
      return NULL;
  }
  return contents;
}

static asection *get_symbol_section(bfd *input_bfd, Elf_Internal_Sym *isym)
{
  if (isym->st_shndx == SHN_UNDEF)
    return bfd_und_section_ptr;
  else if (isym->st_shndx == SHN_ABS)
    return bfd_abs_section_ptr;
  else if (isym->st_shndx == SHN_COMMON)
    return bfd_com_section_ptr;
  else
    return bfd_section_from_elf_index(input_bfd, isym->st_shndx);
}

static char *create_unique_symbol_name(const char *sym_name, asection *sym_sec)
{
  size_t amt = strlen(sym_name) + 10;
  char *new_name = bfd_malloc(amt);
  if (new_name != NULL)
    sprintf(new_name, "%s_%08x", sym_name, sym_sec->id);
  return new_name;
}

static void cache_or_free_contents(asection *section, bfd_byte *contents,
                                  struct bfd_link_info *link_info)
{
  if (contents != NULL && 
      elf_section_data(section)->this_hdr.contents != contents) {
    if (!link_info->keep_memory)
      free(contents);
    else
      elf_section_data(section)->this_hdr.contents = contents;
  }
}

static void cache_or_free_symbols(Elf_Internal_Shdr *symtab_hdr,
                                 Elf_Internal_Sym *isymbuf,
                                 struct bfd_link_info *link_info)
{
  if (isymbuf != NULL &&
      symtab_hdr->contents != (unsigned char *) isymbuf) {
    if (!link_info->keep_memory)
      free(isymbuf);
    else
      symtab_hdr->contents = (unsigned char *) isymbuf;
  }
}

static void cache_or_free_relocs(asection *section,
                                Elf_Internal_Rela *internal_relocs)
{
  if (elf_section_data(section)->relocs != internal_relocs)
    free(internal_relocs);
}

static bool process_local_symbol(bfd *input_bfd, asection *section,
                                Elf_Internal_Rela *irel,
                                Elf_Internal_Sym *isym,
                                Elf_Internal_Shdr *symtab_hdr,
                                struct elf32_mn10300_link_hash_table *hash_table,
                                bfd_byte *contents)
{
  asection *sym_sec = get_symbol_section(input_bfd, isym);
  const char *sym_name = bfd_elf_string_from_elf_section(input_bfd,
                                                        symtab_hdr->sh_link,
                                                        isym->st_name);
  
  if (ELF_ST_TYPE(isym->st_info) != STT_FUNC)
    return true;
  
  char *new_name = create_unique_symbol_name(sym_name, sym_sec);
  if (new_name == NULL)
    return false;
  
  struct elf_link_hash_table *elftab = &hash_table->static_hash_table->root;
  struct elf32_mn10300_link_hash_entry *hash = 
    (struct elf32_mn10300_link_hash_entry *)
    elf_link_hash_lookup(elftab, new_name, true, true, false);
  free(new_name);
  
  if ((section->flags & SEC_CODE) != 0) {
    unsigned char code = bfd_get_8(input_bfd, contents + irel->r_offset - 1);
    if (code != 0xdd && code != 0xcd)
      hash->flags |= MN10300_CONVERT_CALL_TO_CALLS;
  }
  
  return true;
}

#define PROLOGUE_DELETED_FLAG MN10300_DELETED_PROLOGUE_BYTES
#define CONVERT_CALL_FLAG MN10300_CONVERT_CALL_TO_CALLS

static int calculate_prologue_bytes_to_delete(struct elf32_mn10300_link_hash_entry *sym_hash)
{
  int bytes = 0;
  if (sym_hash->movm_args)
    bytes += 2;
  if (sym_hash->stack_size > 0) {
    if (sym_hash->stack_size <= 128)
      bytes += 3;
    else
      bytes += 4;
  }
  return bytes;
}

static bool delete_prologue_bytes_for_symbol(bfd *input_bfd, asection *section,
                                            struct elf32_mn10300_link_hash_entry *sym_hash,
                                            bfd_vma offset,
                                            Elf_Internal_Rela *internal_relocs,
                                            bfd_byte *contents,
                                            Elf_Internal_Sym *isymbuf,
                                            Elf_Internal_Shdr *symtab_hdr,
                                            bool *again)
{
  if ((sym_hash->flags & CONVERT_CALL_FLAG) ||
      (sym_hash->flags & PROLOGUE_DELETED_FLAG))
    return true;
  
  int bytes = calculate_prologue_bytes_to_delete(sym_hash);
  if (bytes == 0)
    return true;
  
  elf_section_data(section)->relocs = internal_relocs;
  elf_section_data(section)->this_hdr.contents = contents;
  symtab_hdr->contents = (unsigned char *) isymbuf;
  
  sym_hash->flags |= PROLOGUE_DELETED_FLAG;
  
  if (!mn10300_elf_relax_delete_bytes(input_bfd, section, offset, bytes))
    return false;
  
  *again = true;
  return true;
}

static bool process_relocation(bfd *input_bfd, asection *section,
                              Elf_Internal_Rela *irel,
                              Elf_Internal_Shdr *symtab_hdr,
                              Elf_Internal_Sym *isymbuf,
                              struct elf32_mn10300_link_hash_table *hash_table,
                              bfd_byte *contents)
{
  long r_type = ELF32_R_TYPE(irel->r_info);
  unsigned long r_index = ELF32_R_SYM(irel->r_info);
  
  if (r_type < 0 || r_type >= (int) R_MN10300_MAX)
    return false;
  
  struct elf32_mn10300_link_hash_entry *hash = NULL;
  
  if (r_index < symtab_hdr->sh_info) {
    Elf_Internal_Sym *isym = isymbuf + r_index;
    if (!process_local_symbol(input_bfd, section, irel, isym, symtab_hdr,
                             hash_table, contents))
      return false;
    return true;
  }
  
  r_index -= symtab_hdr->sh_info;
  hash = (struct elf32_mn10300_link_hash_entry *)
         elf_sym_hashes(input_bfd)[r_index];
  
  if ((section->flags & SEC_CODE) != 0) {
    unsigned char code = bfd_get_8(input_bfd, contents + irel->r_offset - 1);
    if (code != 0xdd && code != 0xcd)
      hash->flags |= MN10300_CONVERT_CALL_TO_CALLS;
  }
  
  if (r_type == R_MN10300_PCREL32 || r_type == R_MN10300_PLT32 ||
      r_type == R_MN10300_PLT16 || r_type == R_MN10300_PCREL16)
    hash->direct_calls++;
  else
    hash->flags |= MN10300_CONVERT_CALL_TO_CALLS;
  
  return true;
}

static void merge_static_symbol_flags(struct elf32_mn10300_link_hash_table *hash_table)
{
  int static_count = 0;
  elf32_mn10300_link_hash_traverse(hash_table->static_hash_table,
                                  elf32_mn10300_count_hash_table_entries,
                                  &static_count);
  
  struct elf32_mn10300_link_hash_entry **entries = 
    bfd_malloc(static_count * sizeof(struct elf32_mn10300_link_hash_entry *));
  
  struct elf32_mn10300_link_hash_entry **ptr = entries;
  elf32_mn10300_link_hash_traverse(hash_table->static_hash_table,
                                  elf32_mn10300_list_hash_table_entries,
                                  &ptr);
  
  qsort(entries, static_count, sizeof(entries[0]), sort_by_value);
  
  for (int i = 0; i < static_count - 1; i++) {
    if (entries[i]->value && entries[i]->value == entries[i+1]->value) {
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

#define INIT_FLAG MN10300_HASH_ENTRIES_INITIALIZED

static bool initialize_hash_table_entries(bfd *abfd,
                                         struct bfd_link_info *link_info,
                                         struct elf32_mn10300_link_hash_table *hash_table)
{
  bfd *input_bfd;
  asection *section;
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Sym *isymbuf = NULL;
  bfd_byte *contents = NULL;
  Elf_Internal_Rela *internal_relocs = NULL;
  
  for (input_bfd = link_info->input_bfds; input_bfd != NULL; 
       input_bfd = input_bfd->link.next) {
    symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
    isymbuf = load_symbols(input_bfd, symtab_hdr);
    if (isymbuf == NULL && symtab_hdr->sh_info != 0)
      goto error_return;
    
    for (section = input_bfd->sections; section != NULL; section = section->next) {
      if (should_skip_section(section))
        continue;
      
      contents = load_section_contents(input_bfd, section);
      if (section->size != 0 && contents == NULL)
        goto error_return;
      
      if ((section->flags & SEC_RELOC) != 0 && section->reloc_count != 0) {
        internal_relocs = _bfd_elf_link_read_relocs(input_bfd, section,
                                                   NULL, NULL,
                                                   link_info->keep_memory);
        if (internal_relocs == NULL)
          goto error_return;
        
        Elf_Internal_Rela *irel, *irelend;
        irelend = internal_relocs + section->reloc_count;
        for (irel = internal_relocs; irel < irelend; irel++) {
          if (!process_relocation(input_bfd, section, irel, symtab_hdr,
                                 isymbuf, hash_table, contents))
            goto error_return;
        }
      }
      
      cache_or_free_relocs(section, internal_relocs);
      internal_relocs = NULL;
      cache_or_free_contents(section, contents, link_info);
      contents = NULL;
    }
    
    cache_or_free_symbols(symtab_hdr, isymbuf, link_info);
    isymbuf = NULL;
  }
  
  elf32_mn10300_link_hash_traverse(hash_table,
                                  elf32_mn10300_finish_hash_table_entry,
                                  link_info);
  elf32_mn10300_link_hash_traverse(hash_table->static_hash_table,
                                  elf32_mn10300_finish_hash_table_entry,
                                  link_info);
  
  merge_static_symbol_flags(hash_table);
  hash_table->flags |= INIT_FLAG;
  
  return true;
  
error_return:
  if (internal_relocs != NULL)
    cache_or_free_relocs(section, internal_relocs);
  if (contents != NULL)
    cache_or_free_contents(section, contents, link_info);
  if (isymbuf != NULL)
    cache_or_free_symbols(symtab_hdr, isymbuf, link_info);
  return false;
}

static unsigned char reverse_condition_code(unsigned char code)
{
  switch (code) {
    case 0xc8: return 0xc9;
    case 0xc9: return 0xc8;
    case 0xc0: return 0xc2;
    case 0xc2: return 0xc0;
    case 0xc3: return 0xc1;
    case 0xc1: return 0xc3;
    case 0xc4: return 0xc6;
    case 0xc6: return 0xc4;
    case 0xc7: return 0xc5;
    case 0xc5: return 0xc7;
    case 0xe8: return 0xe9;
    case 0x9d: return 0xe8;
    case 0xea: return 0xeb;
    case 0xeb: return 0xea;
    default: return code;
  }
}

static bool mn10300_elf_relax_section(bfd *abfd,
                                     asection *sec,
                                     struct bfd_link_info *link_info,
                                     bool *again)
{
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Rela *internal_relocs = NULL;
  Elf_Internal_Rela *irel, *irelend;
  bfd_byte *contents = NULL;
  Elf_Internal_Sym *isymbuf = NULL;
  struct elf32_mn10300_link_hash_table *hash_table;
  asection *section = sec;
  bfd_vma align_gap_adjustment;
  
  if (bfd_link_relocatable(link_info))
    link_info->callbacks->fatal(_("%P: --relax and -r may not be used together\n"));
  
  *again = false;
  
  hash_table = elf32_mn10300_hash_table(link_info);
  if (hash_table == NULL)
    return false;
  
  if ((hash_table->flags & INIT_FLAG) == 0) {
    if (!initialize_hash_table_entries(abfd, link_info, hash_table))
      return false;
  }
  
  contents = NULL;
  internal_relocs = NULL;
  isymbuf = NULL;
  section = sec;
  
  if (bfd_link_relocatable(link_info) ||
      (sec->flags & SEC_RELOC) == 0 ||
      sec->reloc_count == 0 ||
      (sec->flags & SEC_CODE) == 0)
    return true;
  
  symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
  
  internal_relocs = _bfd_elf_link_read_relocs(abfd, sec, NULL, NULL,
                                             link_info->keep_memory);
  if (internal_relocs == NULL)
    goto error_return;
  
  irelend = internal_relocs + sec->reloc_count;
  align_gap_adjustment = 0;
  
  for (irel = internal_relocs; irel < irelend; irel++) {
    if (ELF32_R_TYPE(irel->r_info) == (int) R_MN10300_ALIGN) {
      bfd_vma adj = 1 << irel->r_addend;
      bfd_vma aend = irel->r_offset;
      
      aend = BFD_ALIGN(aend, 1 << irel->r_addend);
      adj = 2 * adj - adj - 1;
      
      if (align_gap_adjustment < adj &&
          aend < sec->output_section->vma + sec->output_offset + sec->size)
        align_gap_adjustment = adj;
    }
  }
  
  irelend = internal_relocs + sec->reloc_count;
  for (irel = internal_relocs; irel < irelend; irel++) {
    bfd_vma symval;
    bfd_signed_vma jump_offset;
    asection *sym_sec = NULL;
    struct elf32_mn10300_link_hash_entry *h = NULL;
    
    if (ELF32_R_TYPE(irel->r_info) == (int) R_MN10300_NONE ||
        ELF32_R_TYPE(irel->r_info) == (int) R_MN10300_8 ||
        ELF32_R_TYPE(irel->r_info) == (int) R_MN10300_MAX)
      continue;
    
    if (contents == NULL) {
      contents = load_section_contents(abfd, sec);
      if (contents == NULL)
        goto error_return;
    }
    
    if (isymbuf == NULL && symtab_hdr->sh_info != 0) {
      isymbuf = load_symbols(abfd, symtab_hdr);
      if (isymbuf == NULL)
        goto error_return;
    }
    
    if (ELF32_R_SYM(irel->r_info) < symtab_hdr->sh_info) {
      Elf_Internal_Sym *isym = isymbuf + ELF32_R_SYM(irel->r_info);
      sym_sec = get_symbol_section(abfd, isym);
      
      const char *sym_name = bfd_elf_string_from_elf_section(abfd,
                                                            symtab_hdr->sh_link,
                                                            isym->st_name);
      
      if ((sym_sec->flags & SEC_MERGE) &&
          sym_sec->sec_info_type == SEC_INFO_TYPE_MERGE) {
        symval = isym->st_value;
        
        if (ELF_ST_TYPE(isym->st_info) == STT_SECTION)
          symval += irel->r_addend;
        
        symval = _bfd_merged_section_offset(abfd, &sym_sec,
                                           elf_section_data(sym_sec)->sec_info,
                                           symval);
        
        if (ELF_ST_TYPE(isym->st_info) != STT_SECTION)
          symval += irel->r_addend;
        
        symval += sym_sec->output_section->vma + sym_sec->output_offset - irel->r_addend;
      } else {
        symval = isym->st_value + sym_sec->output_section->vma + sym_sec->output_offset;
      }
      
      char *new_name = create_unique_symbol_name(sym_name, sym_sec);
      if (new_name == NULL)
        goto error_return;
      
      h = (struct elf32_mn10300_link_hash_entry *)
          elf_link_hash_lookup(&hash_table->static_hash_table->root,
                              new_name, false, false, false);
      free(new_name);
    } else {
      unsigned long indx = ELF32_R_SYM(irel->r_info) - symtab_hdr->sh_info;
      h = (struct elf32_mn10300_link_hash_entry *)(elf_sym_hashes(abfd)[indx]);
      BFD_ASSERT(h != NULL);
      
      if (h->root.root.type != bfd_link_hash_defined &&
          h->root.root.type != bfd_link_hash_defweak)
        continue;
      
      if (h->root.root.u.def.section->output_section == NULL)
        continue;
      
      sym_sec = h->root.root.u.def.section->output_section;
      symval = h->root.root.u.def.value +
               h->root.root.u.def.section->output_section->vma +
               h->root.root.u.def.section->output_offset;
    }
  }
  
  cache_or_free_symbols(symtab_hdr, isymbuf, link_info);
  cache_or_free_contents(sec, contents, link_info);
  
  if (elf_section_data(sec)->relocs != internal_relocs)
    free(internal_relocs);
  
  return true;
  
error_return:
  if (symtab_hdr->contents != (unsigned char *) isymbuf)
    free(isymbuf);
  if (elf_section_data(section)->this_hdr.contents != contents)
    free(contents);
  if (elf_section_data(section)->relocs != internal_relocs)
    free(internal_relocs);
  
  return false;
}

/* This is a version of bfd_generic_get_relocated_section_contents
   which uses mn10300_elf_relocate_section.  */

static bool should_use_generic_handler(bool relocatable, asection *input_section)
{
  return relocatable || elf_section_data(input_section)->this_hdr.contents == NULL;
}

static bfd_byte *allocate_and_copy_data(asection *input_section, bfd_byte *data)
{
  if (data == NULL)
    {
      data = bfd_malloc(input_section->size);
      if (data == NULL)
        return NULL;
    }
  memcpy(data, elf_section_data(input_section)->this_hdr.contents,
         (size_t) input_section->size);
  return data;
}

static Elf_Internal_Sym *get_symbol_buffer(bfd *input_bfd, Elf_Internal_Shdr *symtab_hdr)
{
  if (symtab_hdr->sh_info == 0)
    return NULL;
    
  Elf_Internal_Sym *isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
  if (isymbuf == NULL)
    isymbuf = bfd_elf_get_elf_syms(input_bfd, symtab_hdr,
                                    symtab_hdr->sh_info, 0,
                                    NULL, NULL, NULL);
  return isymbuf;
}

static asection *get_section_from_symbol(bfd *input_bfd, Elf_Internal_Sym *isym)
{
  if (isym->st_shndx == SHN_UNDEF)
    return bfd_und_section_ptr;
  else if (isym->st_shndx == SHN_ABS)
    return bfd_abs_section_ptr;
  else if (isym->st_shndx == SHN_COMMON)
    return bfd_com_section_ptr;
  else
    return bfd_section_from_elf_index(input_bfd, isym->st_shndx);
}

static asection **build_section_map(bfd *input_bfd, Elf_Internal_Sym *isymbuf, 
                                    bfd_size_type count)
{
  bfd_size_type amt = count * sizeof(asection *);
  asection **sections = bfd_malloc(amt);
  if (sections == NULL && amt != 0)
    return NULL;
    
  Elf_Internal_Sym *isym;
  asection **secpp;
  Elf_Internal_Sym *isymend = isymbuf + count;
  
  for (isym = isymbuf, secpp = sections; isym < isymend; ++isym, ++secpp)
    *secpp = get_section_from_symbol(input_bfd, isym);
    
  return sections;
}

static void cleanup_resources(asection **sections, Elf_Internal_Sym *isymbuf,
                              Elf_Internal_Rela *internal_relocs,
                              Elf_Internal_Shdr *symtab_hdr,
                              asection *input_section,
                              bfd_byte *data, bfd_byte *orig_data)
{
  free(sections);
  if (symtab_hdr->contents != (unsigned char *) isymbuf)
    free(isymbuf);
  if (internal_relocs != elf_section_data(input_section)->relocs)
    free(internal_relocs);
  if (orig_data == NULL)
    free(data);
}

static bool has_relocations(asection *input_section)
{
  return (input_section->flags & SEC_RELOC) != 0 && input_section->reloc_count > 0;
}

static bfd_byte *
mn10300_elf_get_relocated_section_contents(bfd *output_bfd,
                                           struct bfd_link_info *link_info,
                                           struct bfd_link_order *link_order,
                                           bfd_byte *data,
                                           bool relocatable,
                                           asymbol **symbols)
{
  asection *input_section = link_order->u.indirect.section;
  bfd *input_bfd = input_section->owner;
  asection **sections = NULL;
  Elf_Internal_Rela *internal_relocs = NULL;
  Elf_Internal_Sym *isymbuf = NULL;
  
  if (should_use_generic_handler(relocatable, input_section))
    return bfd_generic_get_relocated_section_contents(output_bfd, link_info,
                                                      link_order, data,
                                                      relocatable, symbols);
  
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
  bfd_byte *orig_data = data;
  
  data = allocate_and_copy_data(input_section, data);
  if (data == NULL)
    return NULL;
  
  if (!has_relocations(input_section))
    return data;
  
  internal_relocs = _bfd_elf_link_read_relocs(input_bfd, input_section,
                                              NULL, NULL, false);
  if (internal_relocs == NULL)
    goto error_return;
  
  isymbuf = get_symbol_buffer(input_bfd, symtab_hdr);
  if (symtab_hdr->sh_info != 0 && isymbuf == NULL)
    goto error_return;
  
  sections = build_section_map(input_bfd, isymbuf, symtab_hdr->sh_info);
  if (sections == NULL && symtab_hdr->sh_info != 0)
    goto error_return;
  
  if (!mn10300_elf_relocate_section(output_bfd, link_info, input_bfd,
                                    input_section, data, internal_relocs,
                                    isymbuf, sections))
    goto error_return;
  
  cleanup_resources(sections, isymbuf, internal_relocs, symtab_hdr,
                   input_section, NULL, NULL);
  return data;
  
error_return:
  cleanup_resources(sections, isymbuf, internal_relocs, symtab_hdr,
                   input_section, data, orig_data);
  return NULL;
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
	     bfd_hash_allocate (table, sizeof (* ret));
      if (ret == NULL)
        return NULL;
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
  struct elf32_mn10300_link_hash_entry * edir;
  struct elf32_mn10300_link_hash_entry * eind;

  edir = elf_mn10300_hash_entry (dir);
  eind = elf_mn10300_hash_entry (ind);

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
  struct elf32_mn10300_link_hash_table *ret
    = (struct elf32_mn10300_link_hash_table *) obfd->link.hash;

  obfd->link.hash = &ret->static_hash_table->root.root;
  _bfd_elf_link_hash_table_free (obfd);
  obfd->is_linker_output = true;
  obfd->link.hash = &ret->root.root;
  _bfd_elf_link_hash_table_free (obfd);
}

/* Create an mn10300 ELF linker hash table.  */

static void cleanup_hash_table_on_failure(bfd *abfd, struct elf32_mn10300_link_hash_table *ret)
{
    abfd->is_linker_output = true;
    abfd->link.hash = &ret->static_hash_table->root.root;
    _bfd_elf_link_hash_table_free(abfd);
    free(ret);
}

static void cleanup_static_hash_table(struct elf32_mn10300_link_hash_table *ret)
{
    free(ret->static_hash_table);
    free(ret);
}

static void cleanup_main_table(struct elf32_mn10300_link_hash_table *ret)
{
    free(ret);
}

static struct elf32_mn10300_link_hash_table *allocate_main_table(void)
{
    size_t amt = sizeof(struct elf32_mn10300_link_hash_table);
    return bfd_zmalloc(amt);
}

static struct elf_link_hash_table *allocate_static_hash_table(void)
{
    size_t amt = sizeof(struct elf_link_hash_table);
    return bfd_zmalloc(amt);
}

static bool initialize_hash_table(struct elf_link_hash_table *table, bfd *abfd)
{
    return _bfd_elf_link_hash_table_init(&table->root, abfd,
                                        elf32_mn10300_link_hash_newfunc,
                                        sizeof(struct elf32_mn10300_link_hash_entry));
}

static void prepare_abfd_for_root_init(bfd *abfd)
{
    abfd->is_linker_output = false;
    abfd->link.hash = NULL;
}

static struct bfd_link_hash_table *
elf32_mn10300_link_hash_table_create(bfd *abfd)
{
    struct elf32_mn10300_link_hash_table *ret;

    ret = allocate_main_table();
    if (ret == NULL)
        return NULL;

    ret->static_hash_table = allocate_static_hash_table();
    if (ret->static_hash_table == NULL) {
        cleanup_main_table(ret);
        return NULL;
    }

    if (!initialize_hash_table(ret->static_hash_table, abfd)) {
        cleanup_static_hash_table(ret);
        return NULL;
    }

    prepare_abfd_for_root_init(abfd);
    
    if (!initialize_hash_table(&ret->root, abfd)) {
        cleanup_hash_table_on_failure(abfd, ret);
        return NULL;
    }

    ret->root.root.hash_table_free = elf32_mn10300_link_hash_table_free;
    ret->tls_ldm_got.offset = -1;

    return &ret->root.root;
}

static unsigned long
elf_mn10300_mach (flagword flags)
{
  flagword mach_type = flags & EF_MN10300_MACH;
  
  if (mach_type == E_MN10300_MACH_AM33)
    return bfd_mach_am33;
    
  if (mach_type == E_MN10300_MACH_AM33_2)
    return bfd_mach_am33_2;
    
  return bfd_mach_mn10300;
}

/* The final processing done just before writing out a MN10300 ELF object
   file.  This gets the MN10300 architecture right based on the machine
   number.  */

static unsigned long get_machine_flag(bfd *abfd)
{
    switch (bfd_get_mach(abfd))
    {
    case bfd_mach_am33:
        return E_MN10300_MACH_AM33;
    case bfd_mach_am33_2:
        return E_MN10300_MACH_AM33_2;
    default:
        return E_MN10300_MACH_MN10300;
    }
}

static void update_elf_flags(bfd *abfd, unsigned long val)
{
    elf_elfheader(abfd)->e_flags &= ~(EF_MN10300_MACH);
    elf_elfheader(abfd)->e_flags |= val;
}

static bool
_bfd_mn10300_elf_final_write_processing(bfd *abfd)
{
    unsigned long val = get_machine_flag(abfd);
    update_elf_flags(abfd, val);
    return _bfd_elf_final_write_processing(abfd);
}

static bool
_bfd_mn10300_elf_object_p (bfd *abfd)
{
  Elf_Internal_Ehdr *header = elf_elfheader (abfd);
  unsigned long mach = elf_mn10300_mach (header->e_flags);
  bfd_default_set_arch_mach (abfd, bfd_arch_mn10300, mach);
  return true;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bool is_elf_flavour(bfd *file)
{
    return bfd_get_flavour(file) == bfd_target_elf_flavour;
}

static bool should_update_arch_mach(bfd *obfd, bfd *ibfd)
{
    return bfd_get_arch(obfd) == bfd_get_arch(ibfd) &&
           bfd_get_mach(obfd) < bfd_get_mach(ibfd);
}

static bool update_arch_mach(bfd *obfd, bfd *ibfd)
{
    return bfd_set_arch_mach(obfd, bfd_get_arch(ibfd), bfd_get_mach(ibfd));
}

static bool
_bfd_mn10300_elf_merge_private_bfd_data(bfd *ibfd, struct bfd_link_info *info)
{
    bfd *obfd = info->output_bfd;

    if (!is_elf_flavour(ibfd) || !is_elf_flavour(obfd))
        return true;

    if (should_update_arch_mach(obfd, ibfd))
        return update_arch_mach(obfd, ibfd);

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

static int get_pointer_alignment(const struct elf_backend_data *bed)
{
  switch (bed->s->arch_size)
    {
    case 32:
      return 2;
    case 64:
      return 3;
    default:
      bfd_set_error (bfd_error_bad_value);
      return -1;
    }
}

static asection *create_reloc_section(bfd *abfd, const char *base_name, 
                                      bool use_rela, flagword flags, int ptralign)
{
  char section_name[16];
  asection *s;
  
  snprintf(section_name, sizeof(section_name), "%s%s", 
           use_rela ? ".rela" : ".rel", base_name);
  
  s = bfd_make_section_anyway_with_flags(abfd, section_name, flags | SEC_READONLY);
  
  if (s == NULL || !bfd_set_section_alignment(s, ptralign))
    return NULL;
    
  return s;
}

static bool create_dynbss_section(bfd *abfd)
{
  asection *s = bfd_make_section_anyway_with_flags(abfd, ".dynbss",
                                                   SEC_ALLOC | SEC_LINKER_CREATED);
  return s != NULL;
}

static bool create_copy_reloc_section(bfd *abfd, const struct elf_backend_data *bed,
                                      flagword flags, int ptralign)
{
  asection *s = create_reloc_section(abfd, ".bss", bed->default_use_rela_p, 
                                     flags, ptralign);
  return s != NULL;
}

static bool
_bfd_mn10300_elf_create_dynamic_sections (bfd *abfd, struct bfd_link_info *info)
{
  flagword flags;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table (info);
  int ptralign;

  ptralign = get_pointer_alignment(bed);
  if (ptralign < 0)
    return false;

  flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY
	   | SEC_LINKER_CREATED);

  htab->root.srelplt = create_reloc_section(abfd, ".plt", bed->default_use_rela_p,
                                            flags, ptralign);
  if (htab->root.srelplt == NULL)
    return false;

  if (!_bfd_mn10300_elf_create_got_section (abfd, info))
    return false;

  if (!bed->want_dynbss)
    return true;

  if (!create_dynbss_section(abfd))
    return false;

  if (!bfd_link_pic(info))
    {
      if (!create_copy_reloc_section(abfd, bed, flags, ptralign))
        return false;
    }

  return true;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bool
ensure_dynamic_symbol_output(struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
    if (h->dynindx == -1)
        return bfd_elf_link_record_dynamic_symbol(info, h);
    return true;
}

static void
allocate_plt_entry(struct bfd_link_info *info, struct elf_link_hash_entry *h, asection *splt)
{
    if (splt->size == 0)
        splt->size += elf_mn10300_sizeof_plt0(info);
    
    if (!bfd_link_pic(info) && !h->def_regular)
    {
        h->root.u.def.section = splt;
        h->root.u.def.value = splt->size;
    }
    
    h->plt.offset = splt->size;
    splt->size += elf_mn10300_sizeof_plt(info);
}

static void
allocate_got_and_rela_entries(struct elf32_mn10300_link_hash_table *htab)
{
    asection *sgotplt = htab->root.sgotplt;
    asection *srelplt = htab->root.srelplt;
    
    BFD_ASSERT(sgotplt != NULL);
    BFD_ASSERT(srelplt != NULL);
    
    sgotplt->size += 4;
    srelplt->size += sizeof(Elf32_External_Rela);
}

static bool
handle_function_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
    
    if (!bfd_link_pic(info) && !h->def_dynamic && !h->ref_dynamic)
    {
        BFD_ASSERT(h->needs_plt);
        return true;
    }
    
    if (!ensure_dynamic_symbol_output(info, h))
        return false;
    
    asection *splt = htab->root.splt;
    BFD_ASSERT(splt != NULL);
    
    allocate_plt_entry(info, h, splt);
    allocate_got_and_rela_entries(htab);
    
    return true;
}

static bool
handle_weak_alias(struct elf_link_hash_entry *h)
{
    struct elf_link_hash_entry *def = weakdef(h);
    BFD_ASSERT(def->root.type == bfd_link_hash_defined);
    h->root.u.def.section = def->root.u.def.section;
    h->root.u.def.value = def->root.u.def.value;
    return true;
}

static bool
handle_non_function_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *h, bfd *dynobj)
{
    if (bfd_link_pic(info) || !h->non_got_ref)
        return true;
    
    asection *s = bfd_get_linker_section(dynobj, ".dynbss");
    BFD_ASSERT(s != NULL);
    
    if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
        asection *srel = bfd_get_linker_section(dynobj, ".rela.bss");
        BFD_ASSERT(srel != NULL);
        srel->size += sizeof(Elf32_External_Rela);
        h->needs_copy = 1;
    }
    
    return _bfd_elf_adjust_dynamic_copy(info, h, s);
}

static bool
_bfd_mn10300_elf_adjust_dynamic_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
    bfd *dynobj = htab->root.dynobj;
    
    BFD_ASSERT(dynobj != NULL && 
               (h->needs_plt || h->is_weakalias || 
                (h->def_dynamic && h->ref_regular && !h->def_regular)));
    
    if (h->type == STT_FUNC || h->needs_plt)
        return handle_function_symbol(info, h);
    
    if (h->is_weakalias)
        return handle_weak_alias(h);
    
    return handle_non_function_symbol(info, h, dynobj);
}

/* Set the sizes of the dynamic sections.  */

static bool
set_interp_section(bfd *dynobj, struct bfd_link_info *info)
{
    if (!bfd_link_executable(info) || info->nointerp)
        return true;
    
    asection *s = bfd_get_linker_section(dynobj, ".interp");
    BFD_ASSERT(s != NULL);
    s->size = sizeof ELF_DYNAMIC_INTERPRETER;
    s->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
    s->alloced = 1;
    return true;
}

static void
reset_got_section(struct elf32_mn10300_link_hash_table *htab)
{
    asection *s = htab->root.sgot;
    if (s != NULL)
        s->size = 0;
}

static void
update_relgot_for_tls(struct elf32_mn10300_link_hash_table *htab)
{
    if (htab->tls_ldm_got.refcount <= 0)
        return;
    
    asection *s = htab->root.srelgot;
    BFD_ASSERT(s != NULL);
    s->size += sizeof(Elf32_External_Rela);
}

static bool
should_skip_section(asection *s)
{
    return (s->flags & SEC_LINKER_CREATED) == 0;
}

static bool
is_our_section(const char *name)
{
    return streq(name, ".plt") ||
           startswith(name, ".rela") ||
           startswith(name, ".got") ||
           streq(name, ".dynbss");
}

static void
handle_rela_section(asection *s, const char *name, bool *relocs)
{
    if (s->size == 0)
        return;
    
    if (!streq(name, ".rela.plt"))
        *relocs = true;
    
    s->reloc_count = 0;
}

static bool
allocate_section_contents(bfd *dynobj, asection *s)
{
    if ((s->flags & SEC_HAS_CONTENTS) == 0)
        return true;
    
    s->contents = bfd_zalloc(dynobj, s->size);
    if (s->contents == NULL)
        return false;
    
    s->alloced = 1;
    return true;
}

static bool
process_dynamic_section(bfd *dynobj, asection *s, bool *relocs)
{
    if (should_skip_section(s))
        return true;
    
    const char *name = bfd_section_name(s);
    
    if (!is_our_section(name))
        return true;
    
    if (startswith(name, ".rela"))
        handle_rela_section(s, name, relocs);
    
    if (s->size == 0) {
        s->flags |= SEC_EXCLUDE;
        return true;
    }
    
    return allocate_section_contents(dynobj, s);
}

static bool
_bfd_mn10300_elf_late_size_sections(bfd *output_bfd,
                                    struct bfd_link_info *info)
{
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
    bfd *dynobj = htab->root.dynobj;
    
    if (dynobj == NULL)
        return true;
    
    if (elf_hash_table(info)->dynamic_sections_created) {
        set_interp_section(dynobj, info);
    } else {
        reset_got_section(htab);
    }
    
    update_relgot_for_tls(htab);
    
    bool relocs = false;
    for (asection *s = dynobj->sections; s != NULL; s = s->next) {
        if (!process_dynamic_section(dynobj, s, &relocs))
            return false;
    }
    
    return _bfd_elf_add_dynamic_tags(output_bfd, info, relocs);
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

#define GOT_ENTRY_SIZE 4
#define RESERVED_GOT_ENTRIES 3

static void
fill_plt_entry_non_pic(bfd *output_bfd, asection *splt, asection *sgot,
                       bfd_vma plt_offset, bfd_vma got_offset,
                       struct bfd_link_info *info)
{
    memcpy(splt->contents + plt_offset, elf_mn10300_plt_entry,
           elf_mn10300_sizeof_plt(info));
    
    bfd_put_32(output_bfd,
               sgot->output_section->vma + sgot->output_offset + got_offset,
               splt->contents + plt_offset + elf_mn10300_plt_symbol_offset(info));
    
    bfd_put_32(output_bfd,
               1 - plt_offset - elf_mn10300_plt_plt0_offset(info),
               splt->contents + plt_offset + elf_mn10300_plt_plt0_offset(info));
}

static void
fill_plt_entry_pic(bfd *output_bfd, asection *splt, bfd_vma plt_offset,
                   bfd_vma got_offset, struct bfd_link_info *info)
{
    memcpy(splt->contents + plt_offset, elf_mn10300_pic_plt_entry,
           elf_mn10300_sizeof_plt(info));
    
    bfd_put_32(output_bfd, got_offset,
               splt->contents + plt_offset + elf_mn10300_plt_symbol_offset(info));
}

static void
fill_plt_relocation_offset(bfd *output_bfd, asection *splt,
                          bfd_vma plt_offset, bfd_vma plt_index,
                          struct bfd_link_info *info)
{
    bfd_put_32(output_bfd, plt_index * sizeof(Elf32_External_Rela),
               splt->contents + plt_offset + elf_mn10300_plt_reloc_offset(info));
}

static void
fill_got_plt_entry(bfd *output_bfd, asection *splt, asection *sgot,
                   bfd_vma plt_offset, bfd_vma got_offset,
                   struct bfd_link_info *info)
{
    bfd_put_32(output_bfd,
               splt->output_section->vma + splt->output_offset + plt_offset +
               elf_mn10300_plt_temp_offset(info),
               sgot->contents + got_offset);
}

static void
write_relocation(bfd *output_bfd, Elf_Internal_Rela *rel, asection *srel,
                bfd_vma index)
{
    bfd_elf32_swap_reloca_out(output_bfd, rel,
                              (bfd_byte *)((Elf32_External_Rela *)srel->contents + index));
}

static void
process_plt_entry(bfd *output_bfd, struct bfd_link_info *info,
                  struct elf_link_hash_entry *h, Elf_Internal_Sym *sym,
                  struct elf32_mn10300_link_hash_table *htab)
{
    asection *splt = htab->root.splt;
    asection *sgot = htab->root.sgotplt;
    asection *srel = htab->root.srelplt;
    Elf_Internal_Rela rel;
    
    BFD_ASSERT(h->dynindx != -1);
    BFD_ASSERT(splt != NULL && sgot != NULL && srel != NULL);
    
    bfd_vma plt_index = (h->plt.offset - elf_mn10300_sizeof_plt0(info)) /
                        elf_mn10300_sizeof_plt(info);
    bfd_vma got_offset = (plt_index + RESERVED_GOT_ENTRIES) * GOT_ENTRY_SIZE;
    
    if (!bfd_link_pic(info))
        fill_plt_entry_non_pic(output_bfd, splt, sgot, h->plt.offset, got_offset, info);
    else
        fill_plt_entry_pic(output_bfd, splt, h->plt.offset, got_offset, info);
    
    fill_plt_relocation_offset(output_bfd, splt, h->plt.offset, plt_index, info);
    fill_got_plt_entry(output_bfd, splt, sgot, h->plt.offset, got_offset, info);
    
    rel.r_offset = sgot->output_section->vma + sgot->output_offset + got_offset;
    rel.r_info = ELF32_R_INFO(h->dynindx, R_MN10300_JMP_SLOT);
    rel.r_addend = 0;
    write_relocation(output_bfd, &rel, srel, plt_index);
    
    if (!h->def_regular)
        sym->st_shndx = SHN_UNDEF;
}

static void
handle_tls_gd(bfd *output_bfd, asection *sgot, asection *srel,
              struct elf_link_hash_entry *h, Elf_Internal_Rela *rel)
{
    bfd_put_32(output_bfd, 0, sgot->contents + h->got.offset);
    bfd_put_32(output_bfd, 0, sgot->contents + h->got.offset + GOT_ENTRY_SIZE);
    
    rel->r_info = ELF32_R_INFO(h->dynindx, R_MN10300_TLS_DTPMOD);
    rel->r_addend = 0;
    write_relocation(output_bfd, rel, srel, srel->reloc_count);
    srel->reloc_count++;
    
    rel->r_info = ELF32_R_INFO(h->dynindx, R_MN10300_TLS_DTPOFF);
    rel->r_offset += GOT_ENTRY_SIZE;
    rel->r_addend = 0;
}

static void
handle_tls_ie(bfd *output_bfd, asection *sgot, struct elf_link_hash_entry *h,
              Elf_Internal_Rela *rel)
{
    rel->r_addend = bfd_get_32(output_bfd, sgot->contents + h->got.offset);
    bfd_put_32(output_bfd, 0, sgot->contents + h->got.offset);
    
    if (h->dynindx == -1)
        rel->r_info = ELF32_R_INFO(0, R_MN10300_TLS_TPOFF);
    else
        rel->r_info = ELF32_R_INFO(h->dynindx, R_MN10300_TLS_TPOFF);
}

static void
handle_default_got(bfd *output_bfd, asection *sgot, struct bfd_link_info *info,
                   struct elf_link_hash_entry *h, Elf_Internal_Rela *rel)
{
    if (bfd_link_pic(info) && (info->symbolic || h->dynindx == -1) && h->def_regular) {
        rel->r_info = ELF32_R_INFO(0, R_MN10300_RELATIVE);
        rel->r_addend = h->root.u.def.value +
                       h->root.u.def.section->output_section->vma +
                       h->root.u.def.section->output_offset;
    } else {
        bfd_put_32(output_bfd, 0, sgot->contents + h->got.offset);
        rel->r_info = ELF32_R_INFO(h->dynindx, R_MN10300_GLOB_DAT);
        rel->r_addend = 0;
    }
}

static void
process_got_entry(bfd *output_bfd, struct bfd_link_info *info,
                  struct elf_link_hash_entry *h,
                  struct elf32_mn10300_link_hash_table *htab)
{
    asection *sgot = htab->root.sgot;
    asection *srel = htab->root.srelgot;
    Elf_Internal_Rela rel;
    
    BFD_ASSERT(sgot != NULL && srel != NULL);
    
    rel.r_offset = sgot->output_section->vma + sgot->output_offset +
                   (h->got.offset & ~1);
    
    switch (elf_mn10300_hash_entry(h)->tls_type) {
    case GOT_TLS_GD:
        handle_tls_gd(output_bfd, sgot, srel, h, &rel);
        break;
    case GOT_TLS_IE:
        handle_tls_ie(output_bfd, sgot, h, &rel);
        break;
    default:
        handle_default_got(output_bfd, sgot, info, h, &rel);
        break;
    }
    
    if (ELF32_R_TYPE(rel.r_info) != R_MN10300_NONE) {
        write_relocation(output_bfd, &rel, srel, srel->reloc_count);
        srel->reloc_count++;
    }
}

static void
process_copy_reloc(bfd *output_bfd, struct elf_link_hash_entry *h, bfd *dynobj)
{
    asection *s;
    Elf_Internal_Rela rel;
    
    BFD_ASSERT(h->dynindx != -1 &&
               (h->root.type == bfd_link_hash_defined ||
                h->root.type == bfd_link_hash_defweak));
    
    s = bfd_get_linker_section(dynobj, ".rela.bss");
    BFD_ASSERT(s != NULL);
    
    rel.r_offset = h->root.u.def.value +
                   h->root.u.def.section->output_section->vma +
                   h->root.u.def.section->output_offset;
    rel.r_info = ELF32_R_INFO(h->dynindx, R_MN10300_COPY);
    rel.r_addend = 0;
    
    write_relocation(output_bfd, &rel, s, s->reloc_count);
    s->reloc_count++;
}

static bool
_bfd_mn10300_elf_finish_dynamic_symbol(bfd *output_bfd,
                                       struct bfd_link_info *info,
                                       struct elf_link_hash_entry *h,
                                       Elf_Internal_Sym *sym)
{
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
    bfd *dynobj = htab->root.dynobj;
    
    if (h->plt.offset != (bfd_vma)-1)
        process_plt_entry(output_bfd, info, h, sym, htab);
    
    if (h->got.offset != (bfd_vma)-1)
        process_got_entry(output_bfd, info, h, htab);
    
    if (h->needs_copy)
        process_copy_reloc(output_bfd, h, dynobj);
    
    if (h == elf_hash_table(info)->hdynamic || h == elf_hash_table(info)->hgot)
        sym->st_shndx = SHN_ABS;
    
    return true;
}

/* Finish up the dynamic sections.  */

static void
process_dynamic_entry(bfd *output_bfd, bfd *dynobj, Elf32_External_Dyn *dyncon,
                     struct elf32_mn10300_link_hash_table *htab)
{
    Elf_Internal_Dyn dyn;
    asection *s;
    
    bfd_elf32_swap_dyn_in(dynobj, dyncon, &dyn);
    
    switch (dyn.d_tag)
    {
    case DT_PLTGOT:
        s = htab->root.sgot;
        dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
        bfd_elf32_swap_dyn_out(output_bfd, &dyn, dyncon);
        break;
        
    case DT_JMPREL:
        s = htab->root.srelplt;
        dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
        bfd_elf32_swap_dyn_out(output_bfd, &dyn, dyncon);
        break;
        
    case DT_PLTRELSZ:
        s = htab->root.srelplt;
        dyn.d_un.d_val = s->size;
        bfd_elf32_swap_dyn_out(output_bfd, &dyn, dyncon);
        break;
        
    default:
        break;
    }
}

static void
process_dynamic_sections(bfd *output_bfd, bfd *dynobj, asection *sdyn,
                        struct elf32_mn10300_link_hash_table *htab)
{
    Elf32_External_Dyn *dyncon;
    Elf32_External_Dyn *dynconend;
    
    BFD_ASSERT(sdyn != NULL);
    
    dyncon = (Elf32_External_Dyn *) sdyn->contents;
    dynconend = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);
    
    for (; dyncon < dynconend; dyncon++)
    {
        process_dynamic_entry(output_bfd, dynobj, dyncon, htab);
    }
}

static void
fill_plt_entry_pic(asection *splt, struct bfd_link_info *info)
{
    memcpy(splt->contents, elf_mn10300_pic_plt_entry,
           elf_mn10300_sizeof_plt(info));
}

static void
fill_plt_entry_non_pic(bfd *output_bfd, asection *splt, asection *sgot,
                      struct bfd_link_info *info)
{
    memcpy(splt->contents, elf_mn10300_plt0_entry, PLT0_ENTRY_SIZE);
    bfd_put_32(output_bfd,
               sgot->output_section->vma + sgot->output_offset + 4,
               splt->contents + elf_mn10300_plt0_gotid_offset(info));
    bfd_put_32(output_bfd,
               sgot->output_section->vma + sgot->output_offset + 8,
               splt->contents + elf_mn10300_plt0_linker_offset(info));
}

static void
fill_plt_first_entry(bfd *output_bfd, asection *splt, asection *sgot,
                    struct bfd_link_info *info)
{
    if (splt && splt->size > 0)
    {
        if (bfd_link_pic(info))
        {
            fill_plt_entry_pic(splt, info);
        }
        else
        {
            fill_plt_entry_non_pic(output_bfd, splt, sgot, info);
        }
        
        elf_section_data(splt->output_section)->this_hdr.sh_entsize = 1;
    }
}

#define GOT_ENTRY_SIZE 4
#define GOT_OFFSET_ZERO 0
#define GOT_OFFSET_ONE 4
#define GOT_OFFSET_TWO 8

static void
fill_got_first_entries(bfd *output_bfd, asection *sgot, asection *sdyn)
{
    if (sgot->size > 0)
    {
        if (sdyn == NULL)
        {
            bfd_put_32(output_bfd, (bfd_vma) 0, sgot->contents);
        }
        else
        {
            bfd_put_32(output_bfd,
                      sdyn->output_section->vma + sdyn->output_offset,
                      sgot->contents);
        }
        bfd_put_32(output_bfd, (bfd_vma) 0, sgot->contents + GOT_OFFSET_ONE);
        bfd_put_32(output_bfd, (bfd_vma) 0, sgot->contents + GOT_OFFSET_TWO);
    }
    
    elf_section_data(sgot->output_section)->this_hdr.sh_entsize = GOT_ENTRY_SIZE;
}

static bool
_bfd_mn10300_elf_finish_dynamic_sections(bfd *output_bfd,
                                         struct bfd_link_info *info)
{
    bfd *dynobj;
    asection *sgot;
    asection *sdyn;
    struct elf32_mn10300_link_hash_table *htab = elf32_mn10300_hash_table(info);
    
    dynobj = htab->root.dynobj;
    sgot = htab->root.sgotplt;
    BFD_ASSERT(sgot != NULL);
    sdyn = bfd_get_linker_section(dynobj, ".dynamic");
    
    if (elf_hash_table(info)->dynamic_sections_created)
    {
        process_dynamic_sections(output_bfd, dynobj, sdyn, htab);
        fill_plt_first_entry(output_bfd, htab->root.splt, sgot, info);
    }
    
    fill_got_first_entries(output_bfd, sgot, sdyn);
    
    return true;
}

/* Classify relocation types, such that combreloc can sort them
   properly.  */

static enum elf_reloc_type_class
_bfd_mn10300_elf_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
				   const asection *rel_sec ATTRIBUTE_UNUSED,
				   const Elf_Internal_Rela *rela)
{
  switch ((int) ELF32_R_TYPE (rela->r_info))
    {
    case R_MN10300_RELATIVE:	return reloc_class_relative;
    case R_MN10300_JMP_SLOT:	return reloc_class_plt;
    case R_MN10300_COPY:	return reloc_class_copy;
    default:			return reloc_class_normal;
    }
}

/* Allocate space for an MN10300 extension to the bfd elf data structure.  */

static bool
mn10300_elf_mkobject (bfd *abfd)
{
  return bfd_elf_allocate_object (abfd, sizeof (struct elf_mn10300_obj_tdata));
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
