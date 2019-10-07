#include <assert.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct _FridaMachOParams FridaMachOParams;

struct _FridaMachOParams
{
  uintptr_t slide;
  const void * linkedit;
  const struct symtab_command * symtab;
  const struct dysymtab_command * dysymtab;
};

static void frida_append_string (char ** output, const char * val);
static void frida_append_char (char ** output, char val);
static void frida_append_uint64 (char ** output, uint64_t val);

static void frida_find_macho_params (const void * macho, FridaMachOParams * params);

static bool frida_str_equals (const char * str, const char * other);

size_t
frida_fetch_dyld_symbols (char * output_buffer, const struct dyld_all_image_infos * all_image_info)
{
  char * cursor;
  size_t size;
  FridaMachOParams dyld;
  const struct nlist_64 * symbols;
  const char * strings;
  uint32_t i;

  cursor = output_buffer;

  frida_find_macho_params (all_image_info->dyldImageLoadAddress, &dyld);

  symbols = dyld.linkedit + dyld.symtab->symoff;
  strings = dyld.linkedit + dyld.symtab->stroff;

  for (i = dyld.dysymtab->ilocalsym; i != dyld.dysymtab->nlocalsym; i++)
  {
    const struct nlist_64 * sym = &symbols[i];
    const char * name = strings + sym->n_un.n_strx;

#ifdef BUILDING_TEST_PROGRAM
    fprintf (stderr, "FOUND: '%s' VALUE: %p n_sect=%u\n", name, (void *) sym->n_value, sym->n_sect);
#endif

    frida_append_uint64 (&cursor, sym->n_value);
    frida_append_char (&cursor, '\t');
    frida_append_string (&cursor, name);
    frida_append_char (&cursor, '\n');
  }

  size = cursor - output_buffer;

  frida_append_char (&cursor, '\0');

  return size;
}

static void
frida_append_string (char ** output, const char * val)
{
  char * cursor = *output;
  char c;

  while ((c = *val++) != '\0')
    *cursor++ = c;

  *output = cursor;
}

static void
frida_append_char (char ** output, char val)
{
  char * cursor = *output;

  *cursor++ = val;

  *output = cursor;
}

static void
frida_append_uint64 (char ** output, uint64_t val)
{
  const char nibble_to_hex_char[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  };
  char * cursor = *output;
  char c;
  unsigned int offset;
  bool found_first_nonzero;

  found_first_nonzero = false;
  for (offset = 0; offset != 64; offset += 4)
  {
    uint8_t nibble = (val >> (64 - 4 - offset)) & 0xf;

    if (!found_first_nonzero && nibble != 0)
      found_first_nonzero = true;

    if (found_first_nonzero)
      *cursor++ = nibble_to_hex_char[nibble];
  }

  *output = cursor;
}

static void
frida_find_macho_params (const void * macho, FridaMachOParams * params)
{
  const struct mach_header_64 * header;
  const struct load_command * lc;
  uint32_t i;
  const void * preferred_base;
  const void * linkedit;

  header = macho;
  lc = (const struct load_command *) (header + 1);

  preferred_base = NULL;
  linkedit = NULL;

  for (i = 0; i != header->ncmds; i++)
  {
    switch (lc->cmd)
    {
      case LC_SEGMENT_64:
      {
        const struct segment_command_64 * sc = (const struct segment_command_64 *) lc;

        if (frida_str_equals (sc->segname, "__TEXT"))
          preferred_base = (const void *) sc->vmaddr;
        else if (frida_str_equals (sc->segname, "__LINKEDIT"))
          linkedit = (const void *) sc->vmaddr - sc->fileoff;

        break;
      }
      case LC_SYMTAB:
        params->symtab = (const struct symtab_command *) lc;
        break;
      case LC_DYSYMTAB:
        params->dysymtab = (const struct dysymtab_command *) lc;
        break;
      default:
        break;
    }

    lc = (const struct load_command *) ((uint8_t *) lc + lc->cmdsize);
  }

  params->slide = macho - preferred_base;
  params->linkedit = linkedit + params->slide;
}

static bool
frida_str_equals (const char * str, const char * other)
{
  char a, b;

  do
  {
    a = *str;
    b = *other;
    if (a != b)
      return false;
    str++;
    other++;
  }
  while (a != '\0');

  return true;
}

#ifdef BUILDING_TEST_PROGRAM

int
main (void)
{
  mach_port_t task;
  struct task_dyld_info info;
  mach_msg_type_number_t count;
  kern_return_t kr;
  const struct dyld_all_image_infos * dyld_info;
  char output_buffer[512 * 1024];
  size_t size;

  task = mach_task_self ();

  count = TASK_DYLD_INFO_COUNT;
  kr = task_info (task, TASK_DYLD_INFO, (task_info_t) &info, &count);
  assert (kr == KERN_SUCCESS);

  dyld_info = (const struct dyld_all_image_infos *) info.all_image_info_addr;

  size = frida_fetch_dyld_symbols (output_buffer, dyld_info);

  fprintf (stderr, "%s\n", output_buffer);
  fprintf (stderr, "size: %zu bytes\n", size);

  return 0;
}

#endif
